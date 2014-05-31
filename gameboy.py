

reg_groups = {
    'x': ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A'],
    'z': ['BC', 'DE', 'HL', 'SP'],
    'w': ['BC', 'DE', 'HL+', 'HL-'],
    'f': ['NZ', 'Z', 'NC', 'C']
}
reg_groups['y'] = reg_groups['x']

def insn():
    pass

instructions = [
    # based on http://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html

    # variables specify the precise instruction formatting
    # x/y/z/w/f are register selections (see reg_groups above)
    # p selects an operation (separated by slashes)
    # h is only used in RST, and is first multiplied by 8
    #     pattern    mnemonic
    insn('00000000', 'NOP'),
    insn('00010000', 'STOP'),
    insn('00zz0001', 'LD z,d16'),
    insn('00ww0010', 'LD (w),A'),
    insn('00zzp011', 'INC/DEC z'),
    insn('00xxx10p', 'INC/DEC x'),
    insn('00xxx110', 'LD x,d8'),
    insn('00ppp111', 'RLCA/RRCA/RLA/RRA/DAA/CPL/SCF/CCF'),
    insn('00001000', 'LD (a16),SP'),
    insn('00zz1001', 'ADD HL,z'),
    insn('00ww1010', 'LD A,(w)'),
    insn('01110110', 'HALT'),  # would be LD (HL),(HL)
    insn('01xxxyyy', 'LD x,y'),
    insn('100ppxxx', 'ADD/ADC/SUB/SBC A,x'),
    insn('101ppxxx', 'AND/XOR/OR/CP x'),
    insn('110pp110', 'ADD/ADC/SUB/SBC A,d8'),
    insn('111pp110', 'AND/XOR/OR/CP d8'),
    insn('110hh111', 'RST h',  # RST 00h/RST 08h/.../RST 38h
    insn('11100000', 'LDH (a8),A'),
    insn('11110000', 'LDH A,(a8)'),
    insn('11100010', 'LD (C),A'),
    insn('11110011', 'LD A,(C)'),
    insn('11100110', 'LD (a16),A'),
    insn('11110110', 'LD A,(a16)'),
    insn('11111000', 'LD HL,SP+r8'),
    insn('11111001', 'LD SP,HL'),
    insn('11100100', 'ADD SP,r8'),
    insn('110ff100', 'CALL f,a16'),
    insn('11001111', 'CALL a16'),
    insn('110p1001', 'RET/RETI'),
    insn('11zz0p01', 'POP/PUSH z'),
    insn('00011000', 'JR r8'),
    insn('001ff000', 'JR f,r8'),
    insn('110ff000', 'RET f'),
    insn('110ff010', 'JP f,a16'),
    insn('11000111', 'JP a16'),
    insn('11100101', 'JP (HL)'),
    insn('1111p011', 'DI/EI'),

    # Prefix CB (two-byte opcodes)
    insn('11001011 00pppxxx', 'RLC/RRC/RL/RR/SLA/SRA/SWAP/SRL x'),
    insn('11001011 01bbbxxx', 'BIT b,x'),
    insn('11001011 10bbbxxx', 'RES b,x'),
    insn('11001011 11bbbxxx', 'SET b,x'),
]
