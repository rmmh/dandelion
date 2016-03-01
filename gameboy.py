import machine

import re

reg_groups = {
    'x': ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A'],
    'z': ['BC', 'DE', 'HL', 'SP'],
    's': ['BC', 'DE', 'HL', 'AF'],
    'w': ['BC', 'DE', 'HL+', 'HL-'],
    'f': ['NZ', 'Z', 'NC', 'C']
}
reg_groups['y'] = reg_groups['x']

# octo syntax version
reg_groups['f'] = ['!zero', 'zero', '!carry', 'carry']
reg_groups['x'][reg_groups['x'].index('(HL)')] = '*HL'
reg_groups['w'] = ['BC', 'DE', 'HL++', 'HL--']

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

cartridge_types = {
    0x00: 'ROM ONLY',
    0x01: 'MBC1',
    0x02: 'MBC1+RAM',
    0x03: 'MBC1+RAM+BATTERY',
    0x05: 'MBC2',
    0x06: 'MBC2+BATTERY',
    0x08: 'ROM+RAM',
    0x09: 'ROM+RAM+BATTERY',
    0x0B: 'MMM01',
    0x0C: 'MMM01+RAM',
    0x0D: 'MMM01+RAM+BATTERY',
    0x0F: 'MBC3+TIMER+BATTERY',
    0x10: 'MBC3+TIMER+RAM+BATTERY',
    0x11: 'MBC3',
    0x12: 'MBC3+RAM',
    0x13: 'MBC3+RAM+BATTERY',
    0x15: 'MBC4',
    0x16: 'MBC4+RAM',
    0x17: 'MBC4+RAM+BATTERY',
    0x19: 'MBC5',
    0x1A: 'MBC5+RAM',
    0x1B: 'MBC5+RAM+BATTERY',
    0x1C: 'MBC5+RUMBLE',
    0x1D: 'MBC5+RUMBLE+RAM',
    0x1E: 'MBC5+RUMBLE+RAM+BATTERY',
    0xFC: 'POCKET CAMERA',
    0xFD: 'BANDAI TAMA5',
    0xFE: 'HuC3',
    0xFF: 'HuC1+RAM+BATTERY',
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
                ret['himm8'] = io_ports.get(0xFF00 + v, '0xFF00 + %x' % v)
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
        def sub(m):
            return m.group(0).split('/')[num]
        self.fmt_ = re.sub(r'\S+/\S+', sub, self.fmt_)

    def _convert_ud(self, args):
        ret = []
        for var in args:
            var = self.args_formatted.get(var, var)
            if 'HL' in var:
                ret.extend('HL')
            elif var in reg_groups:
                ret.extend(reg_groups[var])
            else:
                ret.append(var)
        return ret

    def get_uses(self):
        return self._convert_ud(self.uses_)

    def get_defs(self):
        return self._convert_ud(self.defs_)

    def get_defuses(self):
        return self._convert_ud(self.defs_), self._convert_ud(self.uses_)


def insn(encoding, fmt, fmt_octo, defuse='/', branch=None, call=None):
    length_ = 1
    if '8' in encoding:
        length_ = 2
    elif '16' in encoding:
        length_ = 3

    reg_tok = re.compile(r'SP|PC|.')
    defs, uses = map(reg_tok.findall, defuse.split('/'))

    class Insn(LR35902Instruction):
        length = length_
        match = machine.build_matcher(encoding)
        encoding_ = encoding
        call_ = call
        branch_ = branch
        fmt_ = fmt_octo
        uses_ = uses
        defs_ = defs

        def get_predicate(self):
            return self.args_formatted.get('f')

    return Insn

instructions = [
    # based on http://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html

    # variables specify the precise instruction formatting
    # x/y/z/w/f are register selections (see reg_groups above)
    # p selects an operation (separated by slashes)
    # h is only used in RST, and is first multiplied by 8
    #     pattern    mnemonic def/use

    # XXX def/use patterns are imprecise
    insn('00000000', 'NOP', 'nop'),
    insn('00010000', 'STOP', 'stop'),
    insn('00zz0001 imm16', 'LD z,imm16', 'z := imm16', 'z/'),
    insn('00ww0010', 'LD (w),A', '*w := A', '/Aw'),
    insn('00zzp011', 'INC/DEC z', 'z++/z--', 'zF/z'),
    insn('00xxx10p', 'INC/DEC x', 'x++/x--', 'xF/x'),
    insn('00xxx110 imm8', 'LD x,imm8', 'x := imm8', 'x/'),
    insn('00110111', 'SCF', 'carry := 1', 'F/'),
    insn('00111111', 'CCF', 'carry := !carry', 'F/F'),
    insn('0000p111', 'RLCA/RRCA', 'rlca/rrca' 'AF/A'),
    insn('0001p111', 'RLA/RRA', 'rla/rra', 'AF/AF'),
    insn('00100111', 'DAA', 'daa', 'AF/AF'),
    insn('00101111', 'CPL', 'A := ~A', 'AF/A'),
    insn('00001000 addr16', 'LD (addr16),SP', '*addr16 := SP', '/SP'),
    insn('00zz1001', 'ADD HL,z', 'HL += z', 'HLF/z'),
    insn('00ww1010', 'LD A,(w)', 'A := *w', 'A/w'),
    insn('01110110', 'HALT', 'halt'),  # would be LD (HL),(HL)
    insn('01xxxyyy', 'LD x,y', 'x := y', 'x/y'),
    insn('100p0xxx', 'ADD/SUB A,x', 'A +=/-= x', 'AF/Ax'),
    insn('100p1xxx', 'ADC/SBC A,x', 'A +c=/-c= x', 'AF/xF'),
    insn('10111xxx', 'CP x', 'compare x', 'F/x'),
    insn('101ppxxx', 'AND/XOR/OR/?? x', 'A &=/^=/|=/?? x', 'AF/Ax'),
    insn('110p0110 imm8', 'ADD/SUB A,imm8', 'A +=/-= imm8', 'AF/A'),
    insn('110p1110 imm8', 'ADC/SBC A,imm8', 'A +c=/-c= imm8', 'AF/AF'),
    insn('11111110 imm8', 'CP imm8', 'compare imm8', 'F/A'),
    insn('111pp110 imm8', 'AND/XOR/OR/?? imm8', 'A &=/^=/|=/?? imm8', 'AF/A'),
    insn('11hhh111', 'RST h', 'reset h', 'PCSP/PCSP'),  # RST 00h/RST 08h/.../RST 38h
    insn('11100000 imm8', 'LDH (imm8),A', '*(himm8) := A', '/A'),
    insn('11110000 imm8', 'LDH A,(imm8)', 'A := *(himm8)', 'A/'),
    insn('11100010', 'LD (C),A', '*(0xFF00 + C) := A', '/CA'),
    insn('11110010', 'LD A,(C)', 'A := *(0xFF00 + C)', 'A/C'),
    insn('11101010 addr16', 'LD (addr16),A', '*addr16 := A', '/A'),
    insn('11111010 addr16', 'LD A,(addr16)', 'A := *addr16', 'A/'),
    insn('11111000 simm8', 'LD HL,SP+simm8', 'HL := SP + simm8', 'HLF/SP'),
    insn('11111001', 'LD SP,HL', 'SP := HL', 'SP/HL'),
    insn('11101000 simm8', 'ADD SP,simm8', 'SP += simm8', 'SPF/'),
    insn('110ff100 addr16', 'CALL f,addr16', 'if f addr16', 'PCSP/FPCSP', call='addr16'),
    insn('11001101 addr16', 'CALL addr16', 'addr16', 'PCSP/PCSP', call='addr16'),
    insn('110p1001', 'RET/RETI', 'return/returni', 'PCSP/SP', branch=('return',)),
    insn('11ss0001', 'POP s', 'pop s', 'sSP/SP'),
    insn('11ss0101', 'PUSH s', 'push s', 'SP/SPs'),
    insn('00011000 simm8', 'JR rel8', 'jumpr rel8', 'PC/PC', branch=('rel8',)),
    insn('001ff000 simm8', 'JR f,rel8', 'if f jumpr rel8', 'PC/FPC', branch=(2, 'rel8')),
    insn('110ff000', 'RET f', 'if f return', 'PCSP/FSP', branch=(1, 'return')),
    insn('110ff010 addr16', 'JP f,addr16', 'if f jump addr16', 'PC/F', branch=(3, 'addr16')),
    insn('11000011 addr16', 'JP addr16', 'jump addr16', 'PC/', branch=('addr16',)),
    insn('11101001', 'JP (HL)', 'jump *HL', 'PC/HL', branch=()),
    insn('1111p011', 'DI/EI', 'interrupts-disable/interrupts-enable'),

    # Prefix CB (two-byte opcodes)
    insn('11001011 00pppxxx', 'RLC/RRC/RL/RR/SLA/SRA/SWAP/SRL x', 'rlc/rrc/rl/rr/sla/sra/swap/srl x', 'Fx/x'),
    insn('11001011 01bbbxxx', 'BIT b,x', 'x & bit b', 'Fx/x'),
    insn('11001011 10bbbxxx', 'RES b,x', 'x &~= bit b', 'x/x'),
    insn('11001011 11bbbxxx', 'SET b,x', 'x |= bit b', 'x/x'),
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
    ana.add_metadata('cart: ' + cartridge_types[data[0x147]])
    rom_size = data[0x148]
    if 0 <= rom_size <= 7:
        ana.add_metadata('rom: %dKB' % (32 << rom_size))
    ram_size = data[0x149]
    if ram_size:
        ana.add_metadata('ram: %dKB' % [0, 2, 8, 32][ram_size])

    ana.mem.load_segment(0x0, data)
    for addr, label in ((0x40, '_int_vblank'),
                        (0x48, '_int_lcdstat'),
                        (0x50, '_int_timer'),
                        (0x58, '_int_serial'),
                        (0x60, '_int_joypad'),
                        (0x100, '_init')):
        ana.define_subroutine(addr, label)
    ana.analyze()

    for pos, label in ana.labels.iteritems():
        if label.name.startswith('_i'):
            branch = ana.get_ref(pos, 'branch')
            if branch in ana.labels:
                ana.set_label_name(branch, label.name[1:])

def test_invalid():
    class Engine(object):
        def get_label(self, v, addr):
            return 'L1'

        def add_branch(self, *args):
            pass

        add_call = add_branch

    invalid = set()
    for opcode in range(256):
        if not opcode & 0xF:
            print
        mem = {0: opcode, 1: 0x12, 2: 0x34}
        try:
            insn = decode(0, mem, Engine())
        except machine.InvalidOpcode:
            invalid.add(opcode)

    expected_invalid = {0xd3,       0xdb,       0xdd,
                        0xe3, 0xe4, 0xeb, 0xec, 0xed,
                              0xf4,       0xfc, 0xfd}
    assert invalid == expected_invalid

if __name__ == '__main__':
    test_chart()
