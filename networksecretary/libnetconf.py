import sys, os
import re
import asyncio
from asyncio.subprocess import PIPE, DEVNULL
import subprocess
from rulebook.abider import RuleAbider
from pathlib import Path
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



class Interface(RuleAbider):
    up = False
    carrier = False
    wireless = False
    netid = None
    def __init__(self, index, name, mac):
        super().__init__()
        self.index = index
        self.name = name
        self.mac = mac

        self.addrs = []
        self.routes = []
        self.up = False


    def _ip(self, *a):
        subprocess.check_call(('ip',)+a, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    def _update(self):
        if self.up:
            self._ip('link', 'set', self.name, 'up')
            # TODO On every update, we flush all addresses and re-add the current list.
            #      This is ugly. We need some kind of "synchronization": add new addresses,
            #      remove no-longer-wanted ones and leave the rest alone. This will require
            #      more sophisticated iproute2 parsing.
            self._ip('addr', 'flush', 'dev', self.name) # flushes routes too
            for addr in self.addrs:
                self._ip('addr', 'add', 'dev', self.name, *addr.strip().split())
            for route in self.routes:
                self._ip('route', 'add', 'dev', self.name, *route.strip().split())
        else:
            self._ip('link', 'set', self.name, 'down')

    def set_addrs(self, addrs):
        self.addrs = addrs
        self._update()

    def set_routes(self, routes):
        self.routes = routes
        self._update()

    def set_up(self, up):
        self.up = up
        self._update()

    def set_mac(self, up):
        self.up = up
        self._update()

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
        def end_item():
            if bssid is None: return
        bssid = None
        for line in out.strip().split('\n'):
            m = BSS_RE.match(line)
            if m:
                bssid = m.group(1)
                end_item()
                continue
            m = SSID_RE.match(line)
            if m:
                ssid
            bssid = line
        end_item()

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

class DhcpClient(RuleAbider):
    def __init__(self, iface):
        self.iface = weakref.ref(iface, self._iface_removed)
        self.active = False

    def _iface_removed(self):
        self.set_active(False)
        self.iface = None

    def start(self):
        if self.active: return
        iface = self.iface()
        if iface is None: return
        cmd = ['udhcpc', '-i', iface.name, '-f']
        if self.client_id:
            cmd += ['-c', self.client_id]
        self.proc = asyncio.create_subprocess_exec(*cmd, stdout=PIPE)
        self.active = True

    def stop(self):
        if not self.active: return
        self.proc.kill()
        self.active = False

    def set_active(self, active):
        if active: self.stop()
        else: self.start()


