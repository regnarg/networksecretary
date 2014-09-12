import sys, os
import re
import asyncio
from asyncio.subprocess import PIPE, DEVNULL
import subprocess
from pathlib import Path
import weakref
from ipaddress import IPv4Address, IPv4Network
import json

from rulebook.abider import RuleAbider

from .util import *

import logging
logger = logging.getLogger(__name__)

class IpRoute2Table:
    CMD = ['ip']
    UNNAMED_COLS = {
        'link': ('idx', 'name', 'flags'),
        'addr': ('idx', 'name', 'flags'),
        'route': ('dest'),
    }
    def __init__(self, subcmd):
        self.subcmd = subcmd
        self.data = {}
        self.loop = asyncio.get_event_loop()

    def _parse_line(self, line):
        # Seems too hard to parse for now. The main problem is that some of the words
        # in the output are flags without an argument (e.g. `permanent` in `ip addr`)
        # while others are followed by an argument (e.g. `dev eth0`). This cannot  be
        # determined from the syntax, one would need at the very least a list of the
        # flag-only options (there aren't very many but they might change between versions).
        #
        # I'm rather tempted to parse the formal grammar from the help messages ;-)
        raise NotImplementedError("Generic `iproute2` parsing not implemented for now."
                                  " Please implement specific parsing in a subclass.")

    @asyncio.coroutine
    def _parse_output(self, stream):
        while True:
            line = yield from stream.readline()
            if not line: break
            self._parse_line(line.decode('utf-8').strip())

    @asyncio.coroutine
    def _load(self):
        logger.debug('Loading %s from iproute2', self.subcmd)
        #self.loop.subprocess_exec(IpRoute2Protocol, self.CMD, '-o', self.name, stderr=sys.stderr)
        cmd = self.CMD + ['-o', self.subcmd]
        proc = yield from asyncio.create_subprocess_exec(*cmd, stdin=DEVNULL, stdout=PIPE,
                start_new_session=True)

        yield from self._parse_output(proc.stdout)

    @asyncio.coroutine
    def _start_monitor(self):
        #self.loop.subprocess_exec(IpRoute2Protocol, self.CMD, '-o', self.name, stderr=sys.stderr)
        cmd = self.CMD + ['-o', 'monitor', self.subcmd]
        self.monitor_proc = yield from asyncio.create_subprocess_exec(*cmd, stdin=DEVNULL,
                stdout=PIPE, start_new_session=True)
        self.monitor_task = asyncio.Task(self._parse_output(self.monitor_proc.stdout))

    @asyncio.coroutine
    def start(self):
        yield from self._start_monitor()
        yield from self._load()

    def __del__(self):
        self.monitor_proc.terminate()



class PersistentStorage(RuleAbider):
    def __init__(self, key):
        super().__init__()
        self._key = key
        self._load()

    @property
    def _filename(self):
        return DATA_DIR / (self._key + '.json')

    def _save(self):
        data = { k: v for k, v in vars(self).items() if not k.startswith('_') }
        with open(str(self._filename) + '.tmp', 'w') as file:
            json.dump(data, file)
            file.write('\n') # everybody hates files without final newlines (especially cats ;-))
        os.rename(str(self._filename) + '.tmp', str(self._filename))

    def _load(self):
        if self._filename.exists():
            with self._filename.open('r') as file:
                data = json.load(file)
                for k,v in data.items(): setattr(self, k, v)

    def __setattr__(self, name, val):
        super().__setattr__(name, val)
        if not name.startswith('_'):
            self._save()

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return None

class Interface(RuleAbider):
    up = False
    carrier = False
    wireless = False
    netid = None
    netdata = None
    gateway = None
    addrs = ()
    preference = 0
    def __init__(self, index, name, mac):
        super().__init__()
        self.index = index
        self.name = name
        self.mac = mac

        self.addrs = []
        self.routes = []
        self.up = False

        self.dhcp_client_obj = DHCPClient(self)

    def set_netid(self, netid):
        if netid:
            self.netdata = PersistentStorage('net.' + netid)
        else:
            self.netdata = None
        self.netid = netid

    def _ip(self, *a):
        subprocess.check_call(('ip',)+a, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    def commit(self):
        logger.info('IFACE_IPD %s addrs=%r routes=%r', self.name, self.addrs, self.routes)
        if self.up:
            self._ip('link', 'set', self.name, 'up')
            # TODO On every update, we flush all addresses and re-add the current list.
            #      This is ugly. We need some kind of "synchronization": add new addresses,
            #      remove no-longer-wanted ones and leave the rest alone. This will require
            #      more sophisticated iproute2 parsing.
            self._ip('addr', 'flush', 'dev', self.name) # flushes routes too
            for addr in self.addrs:
                addr_flds = addr.strip().split()
                if 'brd' not in addr_flds:
                    # Auto-set broadcast address if not explicitly given
                    addr_flds += ['brd', '+']
                self._ip('addr', 'add', 'dev', self.name, *addr_flds)
            for route in self.routes:
                self._ip('route', 'add', 'dev', self.name, *route.strip().split())
        else:
            self._ip('link', 'set', self.name, 'down')
    _rbk_commit = commit


    def __repr__(self):
        return '<Interface %d:%s>'%(self.index, self.name)

class WiredInterface(Interface):
    pass

class Ess(RuleAbider):
    def __init__(self, essid):
        self.essid = essid

class WirelessInterface(Interface):
    wireless = True
    scan = False
    BSS_RE = re.compile(r'^BSS ([0-9a-f]{2}(?::[0-9a-f]{2}){5}).*', re.I)
    SSID_RE = re.compile(r'^\s*SSID:\s*(.*)$', re.I)
    @asyncio.coroutine
    def do_scan(self):
        # XXX The `iw` help explicitly asks us NOT to screen scrape its output.
        # Too bad there is no other simple way.
        proc = yield from asyncio.create_subprocess_exec('iw', 'dev', self.name, 'scan',
                stdin=DEVNULL, stdout=PIPE)
        out = (yield from proc.communicate())[0].decode('utf-8')
        if proc.returncode != 0:
            # XXX from time to time, the scan fails with
            #     command failed: Device or resource busy (-16)
            # Not sure why. We log it, ignore it and try again the next time.
            # TODO investigate this
            logger.error('Scan failed on %s.', self.name)
            return

    @asyncio.coroutine
    def scan_coro(self):
        while True:
            yield from self.do_scan()
            yield from asyncio.sleep(self.scan_interval)

    def set_scan(self, scan):
        if scan == self.scan: return
        if scan:
            import asyncio
            self._scan_task = run_task(self.scan_coro())
        else:
            self._scan_task.cancel()


class InterfaceMonitor(IpRoute2Table):
    IFACE_RE = re.compile(r'^(Deleted\s+)?(\d+):\s*(\S+):\s*\<([^>]+)\>(?:.*link/ether\s+(\S+))?.*')
    def __init__(self, lst):
        super().__init__('link')
        self._lst = lst

    def _parse_line(self, line):
        m = self.IFACE_RE.match(line)
        if not m:
            logger.warning("Invalid 'ip link' line: %s", line)
            return

        deleted = bool(m.group(1))
        index = int(m.group(2))
        name = m.group(3)
        flags = set(m.group(4).split(','))
        mac = m.group(5)

        if name == 'lo': return
        if not mac:
            # My wireless interface (at least) emits superfluous events in ``ip monitor link``
            # every few seconds. They can be distinguished by lacking a hardware address:
            # 4: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP>
            #     link/ether
            # 4: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP>
            #     link/ether
            # 4: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP>
            #     link/ether
            # ...
            # TODO: figure out why
            return

        if deleted:
            self._lst._delete(index)

        self._lst._update(index, name, flags, mac)


class InterfaceList(RuleAbider):
    def __init__(self):
        super().__init__()
        self._data = {}
        self._byname = {}
        self._bymac = {}

    def _reindex(self):
        self._byname = { iface.name: iface for iface in self._data.values() }
        self._bymac = { iface.mac: iface for iface in self._data.values() }

    def _delete(self, index):
        try: del self._data[index]
        except KeyError: pass
        else:
            self._reindex()
            self.changed(('iter', None))

    def _update(self, index, name, flags, mac):
        # The keys/attributes that changed contents (meaning they now refer to a different
        # object; changes _inside_ objects don't count). Used to report to Rulebook.
        changed = []

        logger.debug('IFACE_UPD %d:%s %r %s', index, name, flags, mac)

        # Attributes/items affected by the update. Used to notify Rulebook.
        carrier = 'UP' in flags and 'NO-CARRIER' not in flags
        logger.debug('.. carrier %d', carrier)
        if index in self._data:
            iface = self._data[index]
            if name != iface.name:
                changed.append(iface.name)
                changed.append(name)
                changed.append(('attr', name))
                changed.append(('attr', iface.name))
            if mac != iface.mac:
                changed.append(iface.mac)
                changed.append(mac)
            iface.name = name
            iface.mac = mac
            iface.carrier = carrier
        else:
            wireless = (Path('/sys/class/net') / name / 'wireless').exists()
            if wireless:
                iface = WirelessInterface(index, name, mac)
            else:
                iface = WiredInterface(index, name, mac)
            iface.carrier = carrier
            self._data[index] = iface
            self._reindex()
            changed = [('attr', name), name, mac, index, ('iter', None)]

        for key in changed:
            if isinstance(key, tuple):
                self._changed(key)
            else:
                self._changed(('item', key))

    def __iter__(self):
        return iter(self._data.values())

    def __getitem__(self, key):
        try: return self._byname[key]
        except KeyError: pass
        try: return self._bymac[key]
        except KeyError: pass
        try: return self._data[key]
        except KeyError: pass
        raise KeyError(key)

    def __getattr__(self, name):
        try: return self[name]
        except KeyError: raise AttributeError(name)



class NetworkState(RuleAbider):
    def __init__(self):
        super().__init__()
        self.ifaces = InterfaceList()
        self._ifmon = InterfaceMonitor(self.ifaces)

    @asyncio.coroutine
    def start(self):
        yield from self._ifmon.start()

class DHCPLease(RuleAbider):
    pass

class DHCPClient(RuleAbider):
    def __init__(self, iface):
        super().__init__()
        self.iface = weakref.ref(iface, self._iface_removed)
        self.active = False
        self.running = False
        self.client_id = None
        self.lease = None

    def _iface_removed(self):
        self.set_active(False)
        self.iface = None

    def _update_lease(self, lease, data):
        # Convert ip+netmask to the more convenient "1.2.3.4/24" format that can be
        # directly added to ``iface.addrs``.
        prefixlen = IPv4Network('0.0.0.0/%s'%(data['subnet'])).prefixlen
        data['addr'] = '%s/%d' % (data['ip'], prefixlen)
        for k, v in data.items():
            # XXX this shouldn't be necessary but currently is. In the future,
            # Rulebook will ignore assignments that don't change the value.
            # Currently it doesn't so we need this condition so as not to re-set
            # the interface addresses upon every renewal.
            if getattr(lease, k, None) != v:
                setattr(lease, k, v)

    def _process_event(self, data):
        logger.debug('DHCP_EV %r', data)
        event = data.pop('event')
        if event == 'deconfig':
            self.lease = None
        elif event == 'bound':
            lease = DHCPLease()
            self._update_lease(lease, data)
            self.lease = lease
        elif event == 'renew':
            self._update_lease(self.lease, data)

    @asyncio.coroutine
    def _output_processor(self):
        data = {}
        while True:
            line = yield from self.proc.stdout.readline()
            if not line: break
            line = line.decode('utf-8').strip()
            # Events are blocks of name=value variable assignments, followed by a blank line.
            # See `udhcpc-script.sh`.
            if '=' in line:
                name, val = line.split('=', 1)
                data[name] = val
            elif not line:
                self._process_event(data)
                data = {}
            else:
                logger.error('Unknown line from DHCP script ignored: %r', line)


    @asyncio.coroutine
    def start(self):
        if self.running: return
        self.running = True
        iface = self.iface()
        if iface is None: return
        cmd = [str(LIBDIR / 'udhcpc-wrapper.sh'), '-i', iface.name, '-f']
        if self.client_id:
            cmd += ['-c', self.client_id]
        if self.request_ip:
            cmd += ['-r', self.request_ip]
        self.proc = yield from asyncio.create_subprocess_exec(*cmd, stdout=PIPE)
        self.task = run_task(self._output_processor())

    @asyncio.coroutine
    def stop(self):
        if not self.running: return
        # Yes, kill. `udhcpc` should not have any persistent state and we don't want to
        # send DHCPRELEASE.
        if self.start_task: yield from self.start_task
        self.proc.kill()
        self.task.cancel()
        self.running = False

    def commit(self):
        if self.active: self.start_task = run_task(self.start())
        else: run_task(self.stop())
    _rbk_commit = commit

    def __del__(self):
        if self.active: self.proc.kill()


