import sys, os
import asyncio
from asyncio.subprocess import PIPE, DEVNULL
from rulebook.abider import RuleAbide

# file:///usr/share/doc/python/html/library/itertools.html?highlight=itertools#itertools-recipes
def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

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
            self._parse_line(line.strip())

    @asyncio.coroutine
    def _load(self):
        #self.loop.subprocess_exec(IpRoute2Protocol, self.CMD, '-o', self.name, stderr=sys.stderr)
        cmd = self.cmd + ['-o', self.subcmd]
        proc = yield from asyncio.create_subprocess_exec(*cmd, stdin=DEVNULL, stdout=PIPE)

        yield from self._parse_output(proc.stdout)


    @asyncio.coroutine
    def start(self):
        self._start()
        self._load()



class Interface(RuleAbider):
    up = False
    carrier = False
    def __init__(self, name):
        self.name = name

class InterfaceMonitor(IpRoute2Table):
    IFACE_RE = r'^(Deleted\s+)?(\d+):\s*(\S+):\s*\<([^>])+\>.*link/ether\s+(\S+).*'
    def __init__(self, lst):
        super().__init__('link')
        self._lst = lst

    def _parse_line(self, line):
        m = IFACE_RE.match(line)
        if not m:
            print("Invalid 'ip link' line:", line, file=sys.stderr)

        deleted = bool(m.group(1))
        index = int(m.group(2))
        name = m.group(3)
        flags = set(m.group(4).split(','))
        mac = m.group(5)

        if deleted:
            self._lst._delete(index)

        self._lst._update(index, name, flags, mac)


class InterfaceList(RuleAbider):
    def __init__(self):
        self._data = {}
        self._byname = {}
        self._bymac = {}

    def _reindex(self):
        self._byname = { iface.name: iface for iface in self._data }
        self._bymac = { iface.mac: iface for iface in self._data }
        # Tell Rulebook that iteration contents have changed
        self._changed('__iter__')

    def _delete(self, index):
        try: del self._data[index]
        except KeyError: pass
        else:
            self._reindex()

    def _update(self, index, name, flags, mac):
        # Attributes/items affected by the update. Used to notify Rulebook.
        carrier = 'NO-CARRIER' not in flags # I don't like double negatives.
        if index in self._data:
            iface = self._data[index]
            if name != iface.name:
                changed.append(iface.name)
                changed.append(name)
            if mac != iface.mac:
                changed.append(iface.mac)
                changed.append(mac)
            iface.name = name
            iface.mac = mac
            iface.carrier = carrier
        else:
            iface = Interface(name, mac)
            iface.carrier = carrier
            self._data[index] = iface
            self._reindex()
            changed = ['name', 'mac', 'index']

        for key in changed:
            self._changed(('item', key))
            if isinstace(key, str):
                self._changed(('attr', key))



    def __getitem__(self, key):
        try: return self._byname[key]
        except KeyError: pass
        try: return self._bymac[key]
        except KeyError: pass
        try: return self._key[key]
        except KeyError: pass
        raise KeyError(key)

    def __getattr__(self, name):
        try: return self[name]
        except KeyError: return AttributeError(name)



class NetworkState(RuleAbider):
    def __init__(self):
        self.ifaces = InterfaceList()
        self._ifmon = InterfaceMonitor(self.ifaces)

    @asyncio.coroutine
    def start(self):
        pass
    def start(self


