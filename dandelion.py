import re

class InvalidOpcode(Exception):
    pass

class Chip8CPU(object):
    insns = [
        {'enc': '00E0', 's': 'clear'},
        {'enc': '00EE', 's': 'return', 'next': ()},
        {'enc': '1nnn', 's': 'jump $l', 'next': ('n'), 'label': 'n'},
        {'enc': '2nnn', 's': '$l', 'next': ('n', 2), 'label': 'n'},
        {'enc': '3xnn', 's': 'if v$x != $n:i then \\', 'next': (2, 4)},
        {'enc': '4xnn', 's': 'if v$x == $n:i then \\', 'next': (2, 4)},
        {'enc': '5xy0', 's': 'if v$x != v$y then \\', 'next': (2, 4)},
        {'enc': '6xnn', 's': 'v$x := $n:i'},
        {'enc': '7xnn', 's': 'v$x += $n:i'},
        {'enc': '8xy0', 's': 'v$x := v$y'},
        {'enc': '8xy1', 's': 'v$x |= v$y'},
        {'enc': '8xy2', 's': 'v$x &= v$y'},
        {'enc': '8xy3', 's': 'v$x ^= v$y'},
        {'enc': '8xy4', 's': 'v$x += v$y'},
        {'enc': '8xy5', 's': 'v$x -= v$y'},
        {'enc': '8xy6', 's': 'v$x >>= v$y'},
        {'enc': '8xy7', 's': 'v$x := v$y - v$y'},
        {'enc': '8xyE', 's': 'v$x <<= v$y'},
        {'enc': '9xy0', 's': 'if v$x == v$y then \\', 'next': (2, 4)},
        {'enc': 'Annn', 's': 'i := $l', 'label': 'n'},
        {'enc': 'Bnnn', 's': 'jump0 $n'},
        {'enc': 'Cxnn', 's': 'v$x := random $n:b'},
        {'enc': 'Dxyn', 's': 'sprite v$x v$y $n:i'},
        {'enc': 'Ex9E', 's': 'if v$x -key then \\', 'next': (2, 4)},
        {'enc': 'ExA1', 's': 'if v$x key then \\', 'next': (2, 4)},
        {'enc': 'Fx07', 's': 'v$x := delay'},
        {'enc': 'Fx0A', 's': 'v$x := key'},
        {'enc': 'Fx15', 's': 'delay := v$x'},
        {'enc': 'Fx18', 's': 'buzzer := v$x'},
        {'enc': 'Fx1E', 's': '#sound := v$x'},
        {'enc': 'Fx29', 's': 'i := hex v$x'},
        {'enc': 'Fx33', 's': 'bcd v$x'},
        {'enc': 'Fx55', 's': 'save v$x'},
        {'enc': 'Fx65', 's': 'load v$x'},
    ]

    def decode(self, addr, mem, engine):
        word = (mem.get(addr) << 8) | mem.get(addr + 1)
        word_hex = '{:04X}'.format(word)

        for insn in self.insns:
            m = self.match(insn['enc'], word_hex)
            if m is not None:
                for loc in insn.get('next', (2,)):
                    if isinstance(loc, int):
                        engine.add_transfer(addr, addr + loc)
                    else:
                        engine.add_transfer(addr, int(m[loc], 16))
                if 'label' in insn:
                    m['l'] = engine.get_label(int(m[insn['label']], 16))
                return self.substitute(m, insn['s'])
        raise InvalidOpcode(word_hex)

    def match(self, pat, word):
        def par_rep(m):
            return '(?P<' + m.group(1) + '>' + '.' * len(m.group(0)) + ')'

        pat_re = re.sub(r'([a-z])(\1*)', par_rep, pat)
        m = re.match(pat_re, word)
        if m:
            return m.groupdict()
        return None

    def substitute(self, groups, template):
        def val_rep(m):
            var = m.group(1)
            fmt = m.group(2)
            if var in groups:
                value = groups[var]
                if fmt:
                    if fmt == 'i':
                        value_i = int(value, 16)
                        if value_i > 0xE0:
                            return str(value_i - 0x100)
                        return str(value_i)
                    elif fmt == 'b':
                        value_i = int(value, 16)
                        if value_i == 1:
                            return str(value_i)
                        return bin(value_i)
                    return 'ERR %r %r' % (var, fmt)
                return value
            return 'ERR %r %r' % (var, fmt)
        return re.sub(r'\$(.)(?::(.))?', val_rep, template)



class MemoryMap(object):

    def __init__(self):
        self.segments = []

    def load_segment(self, offset, data):
        self.segments.append((offset, data))

    def get(self, addr):
        for offset, data in self.segments:
            if offset <= addr < offset + len(data):
                return data[addr - offset]
        return None

    def addrs(self):
        for offset, data in self.segments:
            for pos, value in enumerate(data):
                yield offset + pos, value


class Analyzer(object):

    def __init__(self, decoder, mem):
        self.code = {}
        self.worklist = []
        self.decoder = decoder
        self.mem = mem
        self.labels = {}
        self.label_n = 0

    def code_ref(self, addr):
        self.worklist.append(addr)

    def analyze(self):
        while self.worklist:
            addr = self.worklist.pop()
            if self.code.get(addr):
                continue
            asm = self.decoder.decode(addr, self.mem, self)
            self.code[addr] = asm

    def add_transfer(self, src, dst):
        self.code_ref(dst)

    def get_label(self, addr):
        if addr in self.labels:
            return self.labels[addr]
        ret = 'L%d' % self.label_n
        self.label_n += 1
        self.labels[addr] = ret
        return ret

    def dump(self):
        out = ''
        for pos, label in sorted(self.labels.iteritems()):
            out += ':proto %s # %X\n' % (label, pos)
        out += ': main\n'
        addr_iter = self.mem.addrs()
        for addr, val in addr_iter:
            if addr in self.labels:
                if not out.endswith('\n'):
                    out += '\n'
                out += ': %s ' % self.labels[addr]
            if addr in self.code:
                out += self.code[addr] + '\n'
                addr_iter.next()
            else:
                out += hex(val) + ' '
        for pos, label in sorted(self.labels.iteritems()):
            if pos < 0x200:
                continue
            if pos > addr:
                while pos > addr:
                    out += '0 '
                    addr += 1
                out += '\n: %s 0 ' % label

        return out.replace('\\\n', '')


def decompile_chip8(data):
    mem = MemoryMap()
    mem.load_segment(0x200, data)
    ana = Analyzer(Chip8CPU(), mem)
    ana.code_ref(0x200)
    ana.analyze()
    print ana.dump()

if __name__ == '__main__':
    import sys
    data = map(ord, open(sys.argv[1], 'rb').read())
    decompile_chip8(data)
