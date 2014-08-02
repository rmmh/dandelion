import machine

class Chip8Instruction(machine.Instruction):
    length = 2

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

    def get_defuses(self):
        return [], []

def insn(encoding, fmt, branch=None, call=None):
    class Insn(Chip8Instruction):
        match = machine.build_matcher(encoding)
        encoding_ = encoding
        call_ = call
        branch_ = branch
        fmt_ = fmt

    return Insn

instructions = [
    insn('00E0', 'clear'),
    insn('00EE', 'return', branch=()),
    insn('1ooo', 'jump l', branch=('o')),
    insn('2ooo', 'l', call=('o')),
    insn('3xnn', 'if x != n then \\', branch=(2, 4)),
    insn('4xnn', 'if x == n then \\', branch=(2, 4)),
    insn('5xy0', 'if x != y then \\', branch=(2, 4)),
    insn('6xnn', 'x := n'),
    insn('7xnn', 'x += n'),
    insn('8xy0', 'x := y'),
    insn('8xy1', 'x |= y'),
    insn('8xy2', 'x &= y'),
    insn('8xy3', 'x ^= y'),
    insn('8xy4', 'x += y'),
    insn('8xy5', 'x -= y'),
    insn('8xy6', 'x >>= y'),
    insn('8xy7', 'x =- y'),
    insn('8xyE', 'x <<= y'),
    insn('9xy0', 'if x == y then \\', branch=(2, 4)),
    insn('Aooo', 'i := l'),
    insn('Booo', 'jump0 l'),
    insn('Cxvv', 'x := random v:b'),
    insn('Dxyn', 'sprite x y n'),
    insn('Ex9E', 'if x -key then \\', branch=(2, 4)),
    insn('ExA1', 'if x key then \\', branch=(2, 4)),
    insn('Fx07', 'x := delay'),
    insn('Fx0A', 'x := key'),
    insn('Fx15', 'delay := x'),
    insn('Fx18', 'buzzer := x'),
    insn('Fx1E', 'i += x'),
    insn('Fx29', 'i := hex x'),
    insn('Fx33', 'bcd x'),
    insn('Fx55', 'save x'),
    insn('Fx65', 'load x'),

    # SuperChip instructions
    insn('00Cv', 'scroll-down v'),
    insn('00FB', 'scroll-right'),
    insn('00FC', 'scroll-left'),
    insn('00FD', 'exit'),
    insn('00FE', 'lores'),
    insn('00FF', 'hires'),
    insn('Fx75', 'saveflags x'),
    insn('Fx85', 'loadflags x'),
    insn('Fx30', 'i := bighex x'),
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
    raise machine.InvalidOpcode(word_hex)
