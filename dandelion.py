#!/usr/bin/env python

import collections
import itertools
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


class NaturalLoop(object):

    def __init__(self, head, body):
        self.head = head
        self.body = body
        self.back = set()
        self.back_nested = set()

    def get_head_addr(self):
        return self.head.addr

    def get_again_insn(self):
        if self.back - self.back_nested:
            again_point = max(self.back - self.back_nested,
                              key=lambda x: x.addr)
            return again_point.code[-1]
        return None


def extract_natural_loops(bbs, doms):
    natural_loops = {}

    def extract_loop(head, back):
        loop = natural_loops.setdefault(
            head, NaturalLoop(head, {head}))
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
        self.label_generator = ('L%d' % n for n in itertools.count())
        self.refs = collections.defaultdict(list)
        self.xrefs = collections.defaultdict(list)
        self.use_proto = False

        self.bbs = {}

    def code_ref(self, addr):
        self.worklist.append(addr)

    def analyze(self):
        while self.worklist:
            addr = self.worklist.pop()
            if addr == 'return':
                continue
            while True:
                if self.code.get(addr):
                    break
                if self.mem.get(addr) is None:
                    print '# executing code at unknown memory loc 0x%x' % addr
                    break
                insn = self.decoder(addr, self.mem, self)
                # print addr, insn, insn.next, insn.args
                self.code[addr] = insn
                if insn.does_control_flow():
                    break
                addr += len(insn)

        self.rename_labels()

    def add_branch(self, src, dst, next=False):
        self.add_ref(src, dst, 'branch')
        self.code_ref(dst)

    def add_ref(self, src, dst, ty):
        self.refs[src].append((dst, ty))
        self.xrefs[dst].append((src, ty))

    def get_xref(self, addr, ty):
        for source, xref_ty in self.xrefs.get(addr, []):
            if xref_ty == ty:
                return True
        return False

    def add_call(self, src, target):
        self.add_ref(src, target, 'call')
        self.code_ref(target)

    def define_subroutine(self, addr, name):
        self.get_label(addr, None, name)
        self.add_call(None, addr)

    def get_label(self, addr, xref, name=None):
        if addr in self.labels:
            lab = self.labels[addr]
            lab.uses.append(xref)
            return lab
        if name is None:
            name = next(self.label_generator)
        ret = Label(name, addr, [xref])
        self.labels[addr] = ret
        return ret

    def rename_labels(self):
        code_count = itertools.count(1)
        data_count = itertools.count(1)
        pred_count = itertools.count(1)
        for pos, label in sorted(self.labels.iteritems()):
            if not label.name.startswith('L'):
                continue
            if self.get_xref(label.addr, 'call'):
                label.name = 'Sub%d' % next(pred_count)
            elif label.addr in self.code:
                label.name = 'L%d' % next(code_count)
            else:
                label.name = 'D%d' % next(data_count)

    def build_cfg(self, force=False):
        if self.bbs and not force:
            # don't rebuild
            return

        bbs = {}
        worklist = []

        def get_bb(pos, label=None):
            if pos not in bbs:
                if label is None:
                    label = 'C%s' % pos
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
            if pos == 'return':
                continue
            if self.get_xref(pos, 'call'):
                bb_entry = BasicBlock(None, '%s_ENTRY' % bb.label)
                bb_exit = BasicBlock(None, '%s_EXIT' % bb.label)
                bbs['return'] = bb_exit
                linkto(bb_entry, bb)
                bbs[-pos] = bb_entry
            while True:
                insn = self.code[pos]
                bb.code.append(insn)
                if insn.does_control_flow():
                    for succ_pos in insn.next:
                        linkto(bb, get_bb(succ_pos))
                    break
                pos += len(insn)
                if pos not in self.code:
                    break
                if pos in self.labels or self.get_xref(pos, 'branch'):
                    linkto(bb, get_bb(pos))
                    break

        self.bbs = bbs

    def find_common_sequences(self):
        self.build_cfg()

        pair_counts = collections.Counter((a.fmt_, b.fmt_)
                                          for addr, bb in self.bbs.iteritems()
                                          for a, b in zip(bb.code, bb.code[1:]))

        triple_counts = collections.Counter((a.fmt_, b.fmt_, c.fmt_)
                                            for addr, bb in self.bbs.iteritems()
                                            for a, b, c in zip(bb.code, bb.code[1:], bb.code[2:]))

        for pair, count in pair_counts.most_common(30):
            print count, '\t'.join(pair)

        print 'triples:'
        for triple, count in triple_counts.most_common(30):
            print count, '\t'.join(triple)

    def dump(self):
        self.build_cfg()
        bbs = self.bbs
        doms = find_dominators(bbs.values())
        natural_loops = extract_natural_loops(bbs, doms)

        def labels(bbs, truncate=False):
            bbs = sorted(bbs, key=lambda x: x.addr)
            if truncate and len(bbs) > 1:
                return '%s..%s' % (bbs[0].label, bbs[-1].label)
            return '/'.join(str(bb.label) for bb in bbs)

        # for pos, bb in sorted(bbs.iteritems()): print '#', bb,
        # labels(doms[bb])

        loop_points = set()
        again_points = set()
        break_points = set()

        # print '# loops:'
        for head, loop in sorted(natural_loops.iteritems(),
                                 key=lambda (k, v): k.addr):
            again_point = loop.get_again_insn()
            if again_point:
                loop_points.add(loop.get_head_addr())
                again_points.add(again_point)

        out = ''
        if self.use_proto:
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
            # TODO: fix SMC for chip8
            if addr in self.code:  # and addr + 1 not in self.labels:
                # addr + 1 in self.labels indicates self-modifying code
                insn = self.code[addr]
                if insn in again_points:
                    if out.endswith('\\\n'):
                        out = out[:-2] + '\n'
                    indent_count -= 2
                    indent = ' ' * indent_count
                    pred = insn.get_predicate() or ''
                    if pred:
                        pred = ' if %s' % pred
                    out += indent + 'again%s # %s\n' % (pred, insn)
                else:
                    out += indent + '%s\n' % insn
                for _ in xrange(1, insn.length):
                    addr_iter.next()
            else:
                # don't output long runs of zeros
                zero_addr = addr
                while self.mem.get(zero_addr) == 0 and zero_addr not in self.labels:
                    zero_addr += 1
                zero_count = zero_addr - addr
                if zero_count > 10:
                    for _ in xrange(zero_count - 1):
                        addr, val = addr_iter.next()
                    out += '\n:org 0x%x\n' % (addr + 1)
                else:
                    out += hex(val) + ' '
                # if addr - 1 in self.code:
                # out += ' # SMC: %s\n' % self.code[addr - 1]
            # out += '# %x\n' % addr
        for pos, label in sorted(self.labels.iteritems()):
            if pos > addr:
                if pos > addr + 10:
                    out += '\n\n:org 0x%x\n' % pos
                else:
                    while pos > addr:
                        addr += 1
                        out += '0 '
                addr = pos
                out += '\n: %s 0 ' % label
                labels_emitted.add(pos)
        labels_missed = set(self.labels) - labels_emitted
        if labels_missed:
            out += '\n# missed labels: %s' % ', '.join(
                '{0} {0.addr:X}'.format(self.labels[l]) for l in sorted(labels_missed))

        return re.sub(r'(\w) +(\w)', r'\1 \2', out.replace('\\\n', ''))


def decompile_chip8(data):
    import chip8
    mem = MemoryMap()
    mem.load_segment(0x200, data)
    ana = Analyzer(chip8.decode, mem)
    ana.define_subroutine(0x200, 'main')
    ana.analyze()
    ana.use_proto = True
    return ana.dump()


def decompile_gameboy(data):
    import gameboy
    global ana
    ana = Analyzer(gameboy.decode, MemoryMap())
    gameboy.decompile(ana, data)
    # print ana.find_common_sequences()
    return ana.dump()

if __name__ == '__main__':
    import sys
    for fname in sys.argv[1:]:
        data = map(ord, open(fname, 'rb').read())
        print '# INPUT:', fname
        if fname.endswith('.ch8'):
            print decompile_chip8(data)
        elif fname.endswith('.gb'):
            print decompile_gameboy(data)
        else:
            print "# No handlers for file", fname
