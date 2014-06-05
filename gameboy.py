import machine

reg_groups = {
    'x': ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A'],
    'z': ['BC', 'DE', 'HL', 'SP'],
    'w': ['BC', 'DE', 'HL+', 'HL-'],
    'f': ['NZ', 'Z', 'NC', 'C']
}
reg_groups['y'] = reg_groups['x']

io_ports = {
    # these names aren't the same as the official documentation,
    # but they're significantly more readable.
    0xFF00: 'JOYPAD',
    0xFF01: 'SERIAL_DATA',
    0xFF02: 'SERIAL_CTL',
    0xFF04: 'TIMER_DIVIDER',
    0xFF05: 'TIMER_COUNTER',
    0xFF06: 'TIMER_MODULO',
    0xFF07: 'TIMER_CTL',
    0xFF10: 'SND_CH1_SWEEP',
    0xFF11: 'SND_CH1_LENGTH',
    0xFF12: 'SND_CH1_VOLUME_ENVELOPE',
    0xFF13: 'SND_CH1_FREQ_LO',
    0xFF14: 'SND_CH1_FREQ_HI',
    0xFF16: 'SND_CH2_LENGTH',
    0xFF17: 'SND_CH2_VOLUME_ENVELOPE',
    0xFF18: 'SND_CH2_FREQ_LO',
    0xFF19: 'SND_CH2_FREQ_HI',
    0xFF1A: 'SND_CH3_ON',
    0xFF1B: 'SND_CH3_LENGTH',
    0xFF1C: 'SND_CH3_VOLUME',
    0xFF1D: 'SND_CH3_FREQ_LO',
    0xFF1E: 'SND_CH3_FREQ_HI',
    0xFF20: 'SND_CH4_LENGTH',
    0xFF21: 'SND_CH4_VOLUME_ENVELOPE',
    0xFF22: 'SND_CH4_SWITCH_FREQUENCY',
    0xFF23: 'SND_CH4_COUNTER',
    0xFF24: 'SND_OUTPUT_VOLUME',
    0xFF25: 'SND_OUTPUT_MIX',
    0xFF26: 'SND_ON',
    0xFF40: 'LCD_CTL',
    0xFF41: 'LCD_STAT',
    0xFF42: 'LCD_BG_SCROLLY',
    0xFF43: 'LCD_BG_SCROLLX',
    0xFF44: 'LCD_LINE',
    0xFF45: 'LCD_LINE_COMPARE',
    0xFF46: 'LCD_OAM_DMA_BEGIN',
    0xFF47: 'LCD_BG_PALETTE',
    0xFF48: 'LCD_OBJ_PALETTE0',
    0xFF49: 'LCD_OBJ_PALETTE1',
    0xFF4A: 'LCD_WINDOW_Y',
    0xFF4B: 'LCD_WINDOW_XMINUS7',
    0xFF4D: 'CGB_SPEED_PREP',
    0xFF4F: 'LCD_VRAM_BANK',
    0xFF51: 'LCD_VRAM_DMA_SRC_HI',
    0xFF52: 'LCD_VRAM_DMA_SRC_LO',
    0xFF53: 'LCD_VRAM_DMA_DST_HI',
    0xFF54: 'LCD_VRAM_DMA_DST_LO',
    0xFF55: 'LCD_VRAM_DMA_START',
    0xFF56: 'CGB_INFRARED',
    0xFF68: 'LCD_BG_PALETTE_IDX',
    0xFF69: 'LCD_BG_PALETTE_DATA',
    0xFF6A: 'LCD_OBJ_PALETTE_IDX',
    0xFF6B: 'LCD_OBJ_PALETTE_DATA',
    0xFF70: 'CGB_WRAM_BANK',
    0xFF0F: 'INTERRUPT_FLAG',
    0xFFFF: 'INTERRUPT_ENABLE'
}


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
                args[k] = v
                ret[k] = v
            elif k == 'addr16':
                ret[k] = engine.get_label(v, self.addr)
            elif 'imm' in k:
                if self.fmt_.startswith('LDH'):
                    ret[k] = io_ports.get(0xFF00 + v, hex(v))
                else:
                    ret[k] = hex(v)
            elif k == 'h':
                ret[k] = '{:x}H'.format(v * 8)
        if self.branch_ and 'rel8' in self.branch_:
            args['rel8'] = self.addr + self.length + args['simm8']
            ret['rel8'] = engine.get_label(args['rel8'], self.addr)
        return ret

    def pick_fmt(self, num):
        opts, tail = (self.fmt_ + ' ').split(' ', 1)
        opt = opts.split('/')[num]
        self.fmt_ = opt + ' ' + tail.strip()


def insn(encoding, fmt, branch=None, call=None):
    length_ = 1
    if '8' in encoding:
        length_ = 2
    elif '16' in encoding:
        length_ = 3

    class Insn(LR35902Instruction):
        length = length_
        match = machine.build_matcher(encoding)
        encoding_ = encoding
        call_ = call
        branch_ = branch
        fmt_ = fmt

        def get_predicate(self):
            return self.args_formatted.get('f')

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
    insn('00001000 addr16', 'LD (addr16),SP'),
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
    insn('11101010 addr16', 'LD (addr16),A'),
    insn('11111010 addr16', 'LD A,(addr16)'),
    insn('11111000 simm8', 'LD HL,SP+simm8'),
    insn('11111001', 'LD SP,HL'),
    insn('11101001 simm8', 'ADD SP,simm8'),
    insn('110ff100 addr16', 'CALL f,addr16', call='addr16'),
    insn('11001101 addr16', 'CALL addr16', call='addr16'),
    insn('110p1001', 'RET/RETI', branch=('return',)),
    insn('11zz0p01', 'POP/PUSH z'),
    insn('00011000 simm8', 'JR rel8', branch=('rel8',)),
    insn('001ff000 simm8', 'JR f,rel8', branch=(2, 'rel8')),
    insn('110ff000', 'RET f', branch=(1, 'return')),
    insn('110ff010 addr16', 'JP f,addr16', branch=(3, 'addr16')),
    insn('11000011 addr16', 'JP addr16', branch=('addr16',)),
    insn('11100101', 'JP (HL)', branch=()),
    insn('1111p011', 'DI/EI'),

    # Prefix CB (two-byte opcodes)
    insn('11001011 00pppxxx', 'RLC/RRC/RL/RR/SLA/SRA/SWAP/SRL x'),
    insn('11001011 01bbbxxx', 'BIT b,x'),
    insn('11001011 10bbbxxx', 'RES b,x'),
    insn('11001011 11bbbxxx', 'SET b,x'),
]


def decode(addr, mem, engine):
    context = 0
    for x in xrange(3):
        context = (context << 8) | (mem.get(addr + x) or 0)
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
            swapb('addr16')
            return insn(addr, m, engine)
    raise machine.InvalidOpcode(addr, context_bin, '{:06X}'.format(context))


def decompile(ana, data):
    ana.mem.load_segment(0x0, data)
    for addr, label in ((0x40, '_int_vblank'),
                        (0x48, '_int_lcdstat'),
                        (0x50, '_int_timer'),
                        (0x58, '_int_serial'),
                        (0x60, '_int_joypad'),
                        (0x100, '_init')):
        ana.define_subroutine(addr, label)
    ana.analyze()
    return ana.dump()

    addr = 0
    for op in range(256):
        mem.segments[0][1][:3] = [op, 0x34, 0x12]
        # print '{:02X}'.format(op),
        try:
            print gameboy.decode(0, mem, ana)
        except Exception, e:
            print
    while addr < len(data):
        try:
            insn = gameboy.decode(addr, mem, ana)
            opcodes = ''.join('{:02X}'.format(mem.get(addr + x))
                              for x in xrange(insn.length))
            print opcodes.ljust(6), insn
            addr += insn.length
        except Exception, e:
            print e
            addr += 1
