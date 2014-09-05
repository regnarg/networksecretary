import sys, os
import re
import asyncio
from asyncio.subprocess import PIPE, DEVNULL
from rulebook.abider import RuleAbider

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
    def __init__(self, index, name, mac):
        super().__init__()
        self.index = index
        self.name = name
        self.mac = mac

    def __repr__(self):
        return '<Interface %d:%s>'%(self.index, self.name)

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

        logger.debug('IFACE_UPD %d:%s <%s> %s', index, name, ','.join(flags), mac)

        # Attributes/items affected by the update. Used to notify Rulebook.
        carrier = 'NO-CARRIER' not in flags # I don't like double negatives.
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
            iface = Interface(index, name, mac)
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


