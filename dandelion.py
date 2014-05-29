#!/usr/bin/env python

import collections
import re


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
        return '(BB %s P:%s S:%s #%r)' % (self.label, labels(self.pred),
                                          labels(self.succ), self.code)


def find_dominators(bbs):
    bb_doms = {bb: set(bbs) for bb in bbs}

    changed = True
    while changed:
        # TODO: traverse cfg in post-order for efficiency
        changed = False
        for bb in bbs:
            if bb.pred:
                dom = set.intersection(*[bb_doms[pred] for pred in bb.pred])
            else:
                dom = set()
            dom.add(bb)
            if dom != bb_doms[bb]:
                changed = True
                bb_doms[bb] = dom
    return bb_doms

NaturalLoop = collections.namedtuple('NaturalLoop',
                                     'head body back back_nested')


def extract_natural_loops(bbs, doms):
    natural_loops = {}

    def extract_loop(head, back):
        loop = natural_loops.setdefault(
            head, NaturalLoop(head, {head}, set(), set()))
        loop.back.add(back)
        stack = [back]
        while stack:
            bb = stack.pop()
            if bb not in loop.body:
                loop.body.add(bb)
                for pred in bb.pred:
                    stack.append(pred)

    for bb in bbs.itervalues():
        for succ in bb.succ:
            if succ in doms[bb]:
                extract_loop(succ, bb)

    # TODO: proper interval/structural analysis

    # loops should nest properly
    for head1, loop1 in natural_loops.iteritems():
        for head2, loop2 in natural_loops.iteritems():
            if head1 is head2:
                continue
            if head2 in loop1.body:
                assert loop2.body.issubset(loop1.body)
                loop1.back_nested.update(loop2.body & loop1.back)

    return natural_loops


class Analyzer(object):

    def __init__(self, decoder, mem):
        self.code = {}
        self.worklist = []
        self.decoder = decoder
        self.mem = mem
        self.labels = {}
        self.label_n = 0
        self.transfers = collections.defaultdict(list)
        self.xrefs = collections.defaultdict(list)

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

    def add_transfer(self, src, dst, next=False):
        self.transfers[src].append(dst)
        self.code_ref(dst)

    def add_xref(self, src, dst, ty):
        self.xrefs[dst].append((src, ty))

    def has_xref(self, addr, ty):
        for source, xref_ty in self.xrefs.get(addr, []):
            if xref_ty == ty:
                return True
        return False

    def add_call(self, src, target):
        self.add_xref(src, target, 'call')
        self.code_ref(target)

    def get_label(self, addr, xref, name=None):
        if addr in self.labels:
            lab = self.labels[addr]
            lab.uses.append(xref)
            return lab
        if name is None:
            name = 'L%d' % self.label_n
            self.label_n += 1
        ret = Label(name, addr, [xref])
        self.labels[addr] = ret
        return ret

    def rename_labels(self):
        code_count = 1
        data_count = 1
        pred_count = 1
        for pos, label in sorted(self.labels.iteritems()):
            if not label.name.startswith('L'):
                continue
            if label.addr in self.code:
                if self.has_xref(label.addr, 'call'):
                    label.name = 'Sub%d' % pred_count
                    pred_count += 1
                else:
                    label.name = 'L%d' % code_count
                    code_count += 1
            else:
                label.name = 'D%d' % data_count
                data_count += 1

    def extract_cfg(self):
        bbs = {}
        worklist = []

        def get_bb(pos, label=None):
            if pos not in bbs:
                if label is None:
                    label = 'C%d' % pos
                bb = BasicBlock(pos, label)
                worklist.append(bb)
                bbs[pos] = bb
            return bbs[pos]

        for pos, label in sorted(self.labels.iteritems()):
            if pos not in self.code:
                continue
            get_bb(pos, label)

        def linkto(a, b):
            a.succ.append(b)
            b.pred.append(a)

        while worklist:
            bb = worklist.pop()
            pos = bb.addr
            if self.has_xref(pos, 'call'):
                bb_entry = BasicBlock(None, '%s_ENTRY' % bb.label)
                linkto(bb_entry, bb)
                bbs[-pos] = bb_entry
            while True:
                line = self.code[pos]
                bb.code.append(line)
                following = self.transfers.get(pos)
                if following is None:
                    break
                if following != [pos + 2]:
                    for succ_pos in following:
                        linkto(bb, get_bb(succ_pos))
                    break
                assert len(following) <= 1
                if not following:
                    break
                pos = following[0]
                if pos not in self.code:
                    break
                if pos in self.labels or self.has_xref(pos, 'branch'):
                    linkto(bb, get_bb(pos))
                    break
        return bbs

    def dump(self):
        bbs = self.extract_cfg()
        doms = find_dominators(bbs.values())
        natural_loops = extract_natural_loops(bbs, doms)

        def labels(bbs, truncate=False):
            bbs = sorted(bbs, key=lambda x: x.addr)
            if truncate and len(bbs) > 1:
                return '%s..%s' % (bbs[0].label, bbs[-1].label)
            return '/'.join(str(bb.label) for bb in bbs)

        for pos, bb in sorted(bbs.iteritems()):
            print '#', bb, labels(doms[bb])

        loop_points = set()
        again_points = set()

        print '# loops:'
        for head, loop in natural_loops.iteritems():
            print '# HEAD:', str(head.label), labels(loop.body, True), labels(loop.back_nested),
            if loop.back - loop.back_nested:
                loop_point = loop.head
                again_point = max(loop.back - loop.back_nested, key=lambda x: x.addr)
                loop_points.add(loop_point.addr)
                again_points.add(again_point.addr)
                print loop_point.label, '...', again_point.label,
            print


        out = ''
        for pos, label in sorted(self.labels.iteritems()):
            if any(label.addr > use for use in label.uses):
                out += ':proto %s # %X\n' % (label, pos)

        addr_iter = self.mem.addrs()
        labels_emitted = set()
        indent_count = 0
        indent = ''
        for addr, val in addr_iter:
            if addr in self.labels:
                label = self.labels[addr]
                is_loop = addr in loop_points
                if len(label.uses) - is_loop:
                    if not out.endswith('\n'):
                        out += '\n'
                    if label.name.startswith('Sub'):
                        out += '\n'
                    out += ': %s \n' % label
                    labels_emitted.add(addr)
                if is_loop:
                    out += indent + 'loop\n'
                    indent_count += 2
                    indent = ' ' * indent_count
            if addr in self.code and addr + 1 not in self.labels:
                # addr + 1 in self.labels indicates self-modifying code
                if addr in again_points:
                    if out.endswith('\\\n'):
                        out = out[:-2] + '\n'
                    indent_count -= 2
                    indent = ' ' * indent_count
                    out += indent + 'again\n'
                else:
                    out += indent + '%s\n' % self.code[addr]
                addr_iter.next()
            else:
                out += hex(val) + ' '
                if addr - 1 in self.code:
                    out += ' # SMC: %s\n' % self.code[addr - 1]
            # out += '# %x\n' % addr
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
            out += '# missed labels: %s' % ', '.join(
                str(self.labels[l]) for l in sorted(labels_missed))

        return re.sub(r'(\w) +(\w)', r'\1 \2', out.replace('\\\n', ''))


def decompile_chip8(data):
    import chip8
    mem = MemoryMap()
    mem.load_segment(0x200, data)
    ana = Analyzer(chip8.decode, mem)
    ana.get_label(0x200, 0x200, 'main')
    ana.add_call(0x200, 0x200)
    ana.analyze()
    return ana.dump()

if __name__ == '__main__':
    import sys
    for fname in sys.argv[1:]:
        data = map(ord, open(fname, 'rb').read())
        print '# INPUT:', fname
        print decompile_chip8(data)
