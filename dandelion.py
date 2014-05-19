#!/usr/bin/env python

import re
import string


class InvalidOpcode(Exception):
    pass


class Chip8CPU(object):
    insns = [
        {'enc': '00E0', 's': 'clear'},
        {'enc': '00EE', 's': 'return', 'next': ()},
        {'enc': '1nnn', 's': 'jump {n!l}', 'next': ('n')},
        {'enc': '2nnn', 's': '{n!l}', 'next': ('n', 2)},
        {'enc': '3xnn', 's': 'if v{x} != {n!i} then \\', 'next': (2, 4)},
        {'enc': '4xnn', 's': 'if v{x} == {n!i} then \\', 'next': (2, 4)},
        {'enc': '5xy0', 's': 'if v{x} != v{y} then \\', 'next': (2, 4)},
        {'enc': '6xnn', 's': 'v{x} := {n!i}'},
        {'enc': '7xnn', 's': 'v{x} += {n!i}'},
        {'enc': '8xy0', 's': 'v{x} := v{y}'},
        {'enc': '8xy1', 's': 'v{x} |= v{y}'},
        {'enc': '8xy2', 's': 'v{x} &= v{y}'},
        {'enc': '8xy3', 's': 'v{x} ^= v{y}'},
        {'enc': '8xy4', 's': 'v{x} += v{y}'},
        {'enc': '8xy5', 's': 'v{x} -= v{y}'},
        {'enc': '8xy6', 's': 'v{x} >>= v{y}'},
        {'enc': '8xy7', 's': 'v{x} =- v{y}'},
        {'enc': '8xyE', 's': 'v{x} <<= v{y}'},
        {'enc': '9xy0', 's': 'if v{x} == v{y} then \\', 'next': (2, 4)},
        {'enc': 'Annn', 's': 'i := {n!l}'},
        {'enc': 'Bnnn', 's': 'jump0 {n}'},
        {'enc': 'Cxnn', 's': 'v{x} := random {n!b}'},
        {'enc': 'Dxyn', 's': 'sprite v{x} v{y} {n!i}'},
        {'enc': 'Ex9E', 's': 'if v{x} -key then \\', 'next': (2, 4)},
        {'enc': 'ExA1', 's': 'if v{x} key then \\', 'next': (2, 4)},
        {'enc': 'Fx07', 's': 'v{x} := delay'},
        {'enc': 'Fx0A', 's': 'v{x} := key'},
        {'enc': 'Fx15', 's': 'delay := v{x}'},
        {'enc': 'Fx18', 's': 'buzzer := v{x}'},
        {'enc': 'Fx1E', 's': 'i += v{x}'},
        {'enc': 'Fx29', 's': 'i := hex v{x}'},
        {'enc': 'Fx33', 's': 'bcd v{x}'},
        {'enc': 'Fx55', 's': 'save v{x}'},
        {'enc': 'Fx65', 's': 'load v{x}'},
    ]

    def decode(self, addr, mem, engine):
        class InsnFormatter(string.Formatter):
            def convert_field(self, value, conversion):
                if conversion is None:
                    return value
                value_i = int(value, 16)
                if conversion == 'l':
                    return engine.get_label(value_i)
                elif conversion == 'i':
                    if value_i > 0xE0:
                        return value_i - 0x100
                    return value_i
                elif conversion == 'b':
                    if value_i <= 1:
                        return value_i
                    return bin(value_i)

        formatter = InsnFormatter()

        def par_rep(m):
            return '(?P<' + m.group(1) + '>' + '.' * len(m.group(0)) + ')'

        word = (mem.get(addr) << 8) | mem.get(addr + 1)
        word_hex = '{:04X}'.format(word)

        for insn in self.insns:
            pat_re = re.sub(r'([a-z])(\1*)', par_rep, insn['enc'])
            m = re.match(pat_re, word_hex)
            if m is not None:
                m = m.groupdict()
                for loc in insn.get('next', (2,)):
                    if isinstance(loc, int):
                        engine.add_transfer(addr, addr + loc)
                    else:
                        engine.add_transfer(addr, int(m[loc], 16))
                if 'label' in insn:
                    m['l'] = engine.get_label(int(m[insn['label']], 16))
                return formatter.format(insn['s'], **m)
        raise InvalidOpcode(word_hex)


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
        labels_emitted = set()
        for addr, val in addr_iter:
            if addr in self.labels:
                if not out.endswith('\n'):
                    out += '\n'
                out += ': %s ' % self.labels[addr]
                labels_emitted.add(addr)
            if addr in self.code and addr + 1 not in self.labels:
                # addr + 1 in self.labels indicates self-modifying code
                out += self.code[addr] + '\n'
                addr_iter.next()
            else:
                out += hex(val) + ' '
                if addr - 1 in self.code:
                    out += ' # SMC: %s\n' % self.code[addr - 1]
        for pos, label in sorted(self.labels.iteritems()):
            if pos < 0x200:
                continue
            if pos > addr:
                while pos > addr:
                    out += '0 '
                    addr += 1
                out += '\n: %s 0 ' % label
                labels_emitted.add(pos)
        labels_missed = set(self.labels) - labels_emitted
        if labels_missed:
            out += '# missed labels: %s' % ', '.join(self.labels[l] for l in sorted(labels_missed))

        return out.replace('\\\n', '')


def decompile_chip8(data):
    mem = MemoryMap()
    mem.load_segment(0x200, data)
    ana = Analyzer(Chip8CPU(), mem)
    ana.code_ref(0x200)
    ana.analyze()
    return ana.dump()

if __name__ == '__main__':
    import sys
    for fname in sys.argv[1:]:
        data = map(ord, open(fname, 'rb').read())
        print '#', fname
        print decompile_chip8(data)
