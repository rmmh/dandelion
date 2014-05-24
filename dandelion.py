#!/usr/bin/env python

import collections


class Label(object):
    def __init__(self, name, addr, uses):
        self.name = name
        self.addr = addr
        self.uses = uses

    def __str__(self):
        return self.name


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

class BasicBlock(object):
    def __init__(self, addr, label):
        self.addr = addr
        self.label = label
        self.code = []
        self.pred = []
        self.succ = []

    def __repr__(self):
        def labels(l):
            return ','.join(str(x.label) for x in l)
        return '(BB %s P:%s S:%s #%r)' % (self.label, labels(self.pred), labels(self.succ), self.code)

class Analyzer(object):

    def __init__(self, decoder, mem):
        self.code = {}
        self.worklist = []
        self.decoder = decoder
        self.mem = mem
        self.labels = {}
        self.label_n = 0
        self.transfers = collections.defaultdict(list)

    def code_ref(self, addr):
        self.worklist.append(addr)

    def analyze(self):
        while self.worklist:
            addr = self.worklist.pop()
            if self.code.get(addr):
                continue
            asm = self.decoder(addr, self.mem, self)
            self.code[addr] = asm
        self.rename_labels()

    def add_transfer(self, src, dst):
        self.transfers[src].append(dst)
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

    def extract_cfg(self):
        bbs = {}
        for pos, label in sorted(self.labels.iteritems()):
            if pos not in self.code:
                continue
            bbs[pos] = BasicBlock(pos, label)
        for pos, bb in bbs.iteritems():
            while True:
                line = self.code[pos]
                bb.code.append(line)
                if pos in self.transfers and self.transfers[pos] not in (
                    [pos + 2], [pos + 2, pos + 4]):
                    for succ_pos in self.transfers[pos]:
                        succ = bbs[succ_pos]
                        bb.succ.append(succ)
                        succ.pred.append(bb)
                    break
                pos += 2
                if pos not in self.code or pos in self.labels:
                    break
        print '#', sorted(bbs.iteritems())

    def dump(self):
        self.extract_cfg()
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
    import chip8
    mem = MemoryMap()
    mem.load_segment(0x200, data)
    ana = Analyzer(chip8.decode, mem)
    ana.code_ref(0x200)
    ana.analyze()
    return ana.dump()

if __name__ == '__main__':
    import sys
    for fname in sys.argv[1:]:
        data = map(ord, open(fname, 'rb').read())
        print '#', fname
        print decompile_chip8(data)
