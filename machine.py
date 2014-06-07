import re

class Instruction(object):

    def __init__(self, addr, args, engine):
        self.addr = addr
        self.args = args
        self.args_formatted = self.fmt_args(args, engine)
        self.next = []
        if self.call_:
            engine.add_call(addr, args[self.call_])
        if self.branch_ is not None:
            for offset in self.branch_:
                if isinstance(offset, int):
                    target = addr + offset
                elif offset == 'return':
                    target = offset
                else:
                    target = args[offset]
                self.next.append(target)
                engine.add_branch(self.addr, target)

        self.defs, self.uses = self.get_defuses()

    def __str__(self):
        def rep(m):
            val = self.args_formatted.get(m.group(1), m.group(1))
            fmt = m.group(2)
            if fmt:
                if fmt == 'b':
                    return bin(val)
                raise ValueError(fmt)
            return str(val)
        return re.sub(r'(\w+)(?::(\w+))?', rep, self.fmt_) + ' # ' + self.ud_str()

    def fmt_args(self, args, engine):
        return dict(args)

    def __repr__(self):
        return str(self)

    def __len__(self):
        return self.length

    def does_control_flow(self):
        return self.branch_ is not None

    def get_predicate(self):
        return None

    def get_uses(self):
        return []

    def get_defs(self):
        return []

    def ud_str(self):
        return ' '.join(self.defs) + '/' + ' '.join(self.uses)


class InvalidOpcode(Exception):
    pass

def build_matcher(pat):
    def par_rep(m):
        if m.group(1) is not None:
            return '(?P<%s>%s)' % (m.group(1), '.' * int(m.group(2)))
        return '(?P<' + m.group(3) + '>' + '.' * len(m.group(0)) + ')'
    pat_re = re.sub(r'((?:s?imm|addr)(\d+))|([a-z])(\3*)', par_rep, pat.replace(' ',''))
    #print 'build_matcher', pat, '->', pat_re
    return re.compile(pat_re).match
