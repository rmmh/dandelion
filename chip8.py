import re


class InvalidOpcode(Exception):
    pass


class Chip8Instruction(object):

    def __init__(self, addr, args, engine):
        self.addr = addr
        self.args = args
        self.fmt_args = self.fmt_args(args, engine)
        if self.call_:
            engine.add_call(addr, args[self.call_])
        for offset in self.next_:
            if isinstance(offset, int):
                engine.add_transfer(addr, addr + offset)
            else:
                engine.add_transfer(addr, args[offset])

    def __str__(self):
        return self.fmt_.format(**self.fmt_args)

    def fmt_args(self, args, engine):
        ret = dict(args)
        for k, v in args.iteritems():
            if k == 'x' or k == 'y':
                ret[k] = 'v{:X}'.format(v)
            elif k == 'n':
                ret[k] = v - (0x100 if v > 0xE0 else 0)
            elif k == 'o':
                ret['l'] = engine.get_label(v, self.addr)
        return ret

    def __repr__(self):
        return str(self)


def InsnType(encoding, fmt, next=(2,), call=None):
    def par_rep(m):
        return '(?P<' + m.group(1) + '>' + '.' * len(m.group(0)) + ')'
    pat_re = re.sub(r'([a-z])(\1*)', par_rep, encoding)

    class Instruction(Chip8Instruction):
        match = re.compile(pat_re).match
        encoding_ = encoding
        call_ = call
        next_ = next
        fmt_ = fmt

    return Instruction

instructions = [
    InsnType('00E0', 'clear'),
    InsnType('00EE', 'return', next=()),
    InsnType('1ooo', 'jump {l}', next=('o')),
    InsnType('2ooo', '{l}', call=('o')),
    InsnType('3xnn', 'if {x} != {n} then \\', next=(2, 4)),
    InsnType('4xnn', 'if {x} == {n} then \\', next=(2, 4)),
    InsnType('5xy0', 'if {x} != {y} then \\', next=(2, 4)),
    InsnType('6xnn', '{x} := {n}'),
    InsnType('7xnn', '{x} += {n}'),
    InsnType('8xy0', '{x} := {y}'),
    InsnType('8xy1', '{x} |= {y}'),
    InsnType('8xy2', '{x} &= {y}'),
    InsnType('8xy3', '{x} ^= {y}'),
    InsnType('8xy4', '{x} += {y}'),
    InsnType('8xy5', '{x} -= {y}'),
    InsnType('8xy6', '{x} >>= {y}'),
    InsnType('8xy7', '{x} =- {y}'),
    InsnType('8xyE', '{x} <<= {y}'),
    InsnType('9xy0', 'if {x} == {y} then \\', next=(2, 4)),
    InsnType('Aooo', 'i := {l}'),
    InsnType('Booo', 'jump0 {l}'),
    InsnType('Cxvv', '{x} := random {v:b}'),
    InsnType('Dxyn', 'sprite {x} {y} {n}'),
    InsnType('Ex9E', 'if {x} -key then \\', next=(2, 4)),
    InsnType('ExA1', 'if {x} key then \\', next=(2, 4)),
    InsnType('Fx07', '{x} := delay'),
    InsnType('Fx0A', '{x} := key'),
    InsnType('Fx15', 'delay := {x}'),
    InsnType('Fx18', 'buzzer := {x}'),
    InsnType('Fx1E', 'i += {x}'),
    InsnType('Fx29', 'i := hex {x}'),
    InsnType('Fx33', 'bcd {x}'),
    InsnType('Fx55', 'save {x}'),
    InsnType('Fx65', 'load {x}'),
]


def decode(addr, mem, engine):
    word = (mem.get(addr) << 8) | mem.get(addr + 1)
    word_hex = '{:04X}'.format(word)

    for insn in instructions:
        m = insn.match(word_hex)
        if m is not None:
            m = {k: int(v, 16) for k, v
                 in m.groupdict().iteritems()}
            return insn(addr, m, engine)
    raise InvalidOpcode(word_hex)