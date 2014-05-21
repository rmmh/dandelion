#!/usr/bin/env python

import re
import string


class InvalidOpcode(Exception):
    pass

class Label(object):
    def __init__(self, name, addr, uses):
        self.name = name
        self.addr = addr
        self.uses = uses

    def __str__(self):
        return self.name


class Instruction(object):
    def __init__(self, addr, fmt, data, engine):
        self.fmt = fmt
        self.data = data

        if '{n!l}' in self.fmt:
            self.label = engine.get_label(data['n'], addr)

    def __str__(self):
        class InsnFormatter(string.Formatter):
            def convert_field(inner, value, conversion):
                if conversion is None:
                    return value
                if conversion == 'l':
                    return self.label
                elif conversion == 'i':
                    if value > 0xE0:
                        return value - 0x100
                    return value
                elif conversion == 'b':
                    if value <= 1:
                        return value
                    return bin(value)
        return InsnFormatter().format(self.fmt, **self.data)


class Chip8CPU(object):
    insns = [
        {'enc': '00E0', 's': 'clear'},
        {'enc': '00EE', 's': 'return', 'next': ()},
        {'enc': '1nnn', 's': 'jump {n!l}', 'next': ('n')},
        {'enc': '2nnn', 's': '{n!l}', 'call': ('n')},
        {'enc': '3xnn', 's': 'if v{x:X} != {n!i} then \\', 'next': (2, 4)},
        {'enc': '4xnn', 's': 'if v{x:X} == {n!i} then \\', 'next': (2, 4)},
        {'enc': '5xy0', 's': 'if v{x:X} != v{y:X} then \\', 'next': (2, 4)},
        {'enc': '6xnn', 's': 'v{x:X} := {n!i}'},
        {'enc': '7xnn', 's': 'v{x:X} += {n!i}'},
        {'enc': '8xy0', 's': 'v{x:X} := v{y:X}'},
        {'enc': '8xy1', 's': 'v{x:X} |= v{y:X}'},
        {'enc': '8xy2', 's': 'v{x:X} &= v{y:X}'},
        {'enc': '8xy3', 's': 'v{x:X} ^= v{y:X}'},
        {'enc': '8xy4', 's': 'v{x:X} += v{y:X}'},
        {'enc': '8xy5', 's': 'v{x:X} -= v{y:X}'},
        {'enc': '8xy6', 's': 'v{x:X} >>= v{y:X}'},
        {'enc': '8xy7', 's': 'v{x:X} =- v{y:X}'},
        {'enc': '8xyE', 's': 'v{x:X} <<= v{y:X}'},
        {'enc': '9xy0', 's': 'if v{x:X} == v{y:X} then \\', 'next': (2, 4)},
        {'enc': 'Annn', 's': 'i := {n!l}'},
        {'enc': 'Bnnn', 's': 'jump0 {n!l}'},
        {'enc': 'Cxnn', 's': 'v{x:X} := random {n!b}'},
        {'enc': 'Dxyn', 's': 'sprite v{x:X} v{y:X} {n!i}'},
        {'enc': 'Ex9E', 's': 'if v{x:X} -key then \\', 'next': (2, 4)},
        {'enc': 'ExA1', 's': 'if v{x:X} key then \\', 'next': (2, 4)},
        {'enc': 'Fx07', 's': 'v{x:X} := delay'},
        {'enc': 'Fx0A', 's': 'v{x:X} := key'},
        {'enc': 'Fx15', 's': 'delay := v{x:X}'},
        {'enc': 'Fx18', 's': 'buzzer := v{x:X}'},
        {'enc': 'Fx1E', 's': 'i += v{x:X}'},
        {'enc': 'Fx29', 's': 'i := hex v{x:X}'},
        {'enc': 'Fx33', 's': 'bcd v{x:X}'},
        {'enc': 'Fx55', 's': 'save v{x:X}'},
        {'enc': 'Fx65', 's': 'load v{x:X}'},
    ]

    def decode(self, addr, mem, engine):
        def par_rep(m):
            return '(?P<' + m.group(1) + '>' + '.' * len(m.group(0)) + ')'

        word = (mem.get(addr) << 8) | mem.get(addr + 1)
        word_hex = '{:04X}'.format(word)

        for insn in self.insns:
            pat_re = re.sub(r'([a-z])(\1*)', par_rep, insn['enc'])
            m = re.match(pat_re, word_hex)
            if m is not None:
                m = {k : int(v,16) for k, v in m.groupdict().iteritems()}
                for loc in insn.get('next', (2,)):
                    if isinstance(loc, int):
                        engine.add_transfer(addr, addr + loc)
                    else:
                        engine.add_transfer(addr, m[loc])
                if 'call' in insn:
                    engine.add_call(addr, m[insn['call']])
                return Instruction(addr, insn['s'], m, engine)
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
        self.rename_labels()

    def add_transfer(self, src, dst):
        self.code_ref(dst)

    def add_call(self, src, target):
        self.code_ref(target)

    def get_label(self, addr, xref):
        if addr in self.labels:
            lab = self.labels[addr]
            lab.uses.append(xref)
            return lab
        ret = Label('L%d' % self.label_n, addr, [xref])
        self.label_n += 1
        self.labels[addr] = ret
        return ret

    def rename_labels(self):
        code_count = 1
        data_count = 1
        for pos, label in sorted(self.labels.iteritems()):
            if label.addr in self.code:
                label.name = 'L%d' % code_count
                code_count += 1
            else:
                label.name = 'D%d' % data_count
                data_count += 1

    def dump(self):
        out = ''
        for pos, label in sorted(self.labels.iteritems()):
            if any(label.addr > use for use in label.uses):
                out += ':proto %s # %X\n' % (label, pos)
        out += ': main\n'
        addr_iter = self.mem.addrs()
        labels_emitted = set()
        for addr, val in addr_iter:
            if addr in self.labels:
                if not out.endswith('\n'):
                    out += '\n'
                out += ': %s \n' % self.labels[addr]
                labels_emitted.add(addr)
            if addr in self.code and addr + 1 not in self.labels:
                # addr + 1 in self.labels indicates self-modifying code
                out += '%s\n' % self.code[addr]
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
