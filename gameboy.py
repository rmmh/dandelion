import machine

reg_groups = {
    'x': ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A'],
    'z': ['BC', 'DE', 'HL', 'SP'],
    'w': ['BC', 'DE', 'HL+', 'HL-'],
    'f': ['NZ', 'Z', 'NC', 'C']
}
reg_groups['y'] = reg_groups['x']


class LR35902Instruction(machine.Instruction):

    def fmt_args(self, args, engine):
        ret = dict(args)
        for k, v in args.iteritems():
            if k in reg_groups:
                ret[k] = reg_groups[k][v]
            elif k == 'p':
                self.pick_fmt(v)
            elif k == 'simm8':
                if v > 0x80:
                    v -= 0x100
                ret[k] = v
            elif 'imm' in k:
                ret[k] = hex(v)
            elif k == 'h':
                ret[k] = '{:x}H'.format(v * 8)
        return ret

    def pick_fmt(self, num):
        opts, tail = (self.fmt_ + ' ').split(' ', 1)
        opt = opts.split('/')[num]
        self.fmt_ = opt + ' ' + tail


def insn(encoding, fmt, branch=None, call=None):
    class Insn(LR35902Instruction):
        length = 1 + ('imm' in encoding) + ('16' in encoding)
        match = machine.build_matcher(encoding)
        encoding_ = encoding
        call_ = call
        branch_ = branch
        fmt_ = fmt

    return Insn

instructions = [
    # based on http://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html

    # variables specify the precise instruction formatting
    # x/y/z/w/f are register selections (see reg_groups above)
    # p selects an operation (separated by slashes)
    # h is only used in RST, and is first multiplied by 8
    #     pattern    mnemonic
    insn('00000000', 'NOP'),
    insn('00010000', 'STOP'),
    insn('00zz0001 imm16', 'LD z,imm16'),
    insn('00ww0010', 'LD (w),A'),
    insn('00zzp011', 'INC/DEC z'),
    insn('00xxx10p', 'INC/DEC x'),
    insn('00xxx110 imm8', 'LD x,imm8'),
    insn('00ppp111', 'RLCA/RRCA/RLA/RRA/DAA/CPL/SCF/CCF'),
    insn('00001000 imm16', 'LD (imm16),SP'),
    insn('00zz1001', 'ADD HL,z'),
    insn('00ww1010', 'LD A,(w)'),
    insn('01110110', 'HALT'),  # would be LD (HL),(HL)
    insn('01xxxyyy', 'LD x,y'),
    insn('100ppxxx', 'ADD/ADC/SUB/SBC A,x'),
    insn('101ppxxx', 'AND/XOR/OR/CP x'),
    insn('110pp110 imm8', 'ADD/ADC/SUB/SBC A,imm8'),
    insn('111pp110 imm8', 'AND/XOR/OR/CP imm8'),
    insn('11hhh111', 'RST h'),  # RST 00h/RST 08h/.../RST 38h
    insn('11100000 imm8', 'LDH (imm8),A'),
    insn('11110000 imm8', 'LDH A,(imm8)'),
    insn('11100010', 'LD (C),A'),
    insn('11110011', 'LD A,(C)'),
    insn('11101010 imm16', 'LD (imm16),A'),
    insn('11111010 imm16', 'LD A,(imm16)'),
    insn('11111000 simm8', 'LD HL,SP+simm8'),
    insn('11111001', 'LD SP,HL'),
    insn('11101001 simm8', 'ADD SP,simm8'),
    insn('110ff100 imm16', 'CALL f,imm16'),
    insn('11001101 imm16', 'CALL imm16'),
    insn('110p1001', 'RET/RETI'),
    insn('11zz0p01', 'POP/PUSH z'),
    insn('00011000 simm8', 'JR simm8'),
    insn('001ff000 simm8', 'JR f,simm8'),
    insn('110ff000', 'RET f'),
    insn('110ff010 imm16', 'JP f,imm16', branch=('imm16',)),
    insn('11000011 imm16', 'JP imm16', branch=('imm16',)),
    insn('11100101', 'JP (HL)'),
    insn('1111p011', 'DI/EI'),

    # Prefix CB (two-byte opcodes)
    insn('11001011 00pppxxx', 'RLC/RRC/RL/RR/SLA/SRA/SWAP/SRL x'),
    insn('11001011 01bbbxxx', 'BIT b,x'),
    insn('11001011 10bbbxxx', 'RES b,x'),
    insn('11001011 11bbbxxx', 'SET b,x'),
]


def decode(addr, mem, engine):
    context = (mem.get(addr) << 16) | (mem.get(addr + 1) << 8) \
        | mem.get(addr + 2)
    context_bin = '{:024b}'.format(context)

    def swapb(k):
        if k in m:
            m[k] = (m[k] & 0xFF) << 8 | (m[k] >> 8)

    for insn in instructions:
        m = insn.match(context_bin)
        if m is not None:
            m = {k: int(v, 2) for k, v
                 in m.groupdict().iteritems()}
            swapb('imm16')
            swapb('simm16')
            return insn(addr, m, engine)
    raise machine.InvalidOpcode(addr, context_bin, '{:06X}'.format(context))
