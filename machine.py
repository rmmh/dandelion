import re

class Instruction(object):

    def __init__(self, addr, args, engine):
        self.addr = addr
        self.args = args
        self.fmt_args = self.fmt_args(args, engine)
        self.next = []
        if self.call_:
            engine.add_call(addr, args[self.call_])
        if self.branch_ is not None:
            for offset in self.branch_:
                if isinstance(offset, int):
                    target = addr + offset
                else:
                    target = args[offset]
                self.next.append(target)
                engine.add_branch(self.addr, target)

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

    def __len__(self):
        return self.length

    def does_control_flow(self):
        return self.branch_ is not None


class InvalidOpcode(Exception):
    pass

def build_matcher(pat):
    def par_rep(m):
        return '(?P<' + m.group(1) + '>' + '.' * len(m.group(0)) + ')'
    return re.compile(re.sub(r'([a-z])(\1*)', par_rep, pat)).match
