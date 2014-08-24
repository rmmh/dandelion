#!/usr/bin/env python

import pipes
import subprocess
import sys

FORMAT='"%04.4_ax  " 16/1 "%02x " "\n"'

def check_roundtrip(fname):
    cmdline = './dandelion.py %s | ../Octo/octo /dev/stdin' % pipes.quote(fname)
    proc = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    #if err:
    #    print err
    if proc.returncode:
        print 'ERROR', fname, out, err
        return False
    #print repr(out)
    expected = open(fname).read()
    #print repr(expected)
    if out.rstrip('\x00') != expected.rstrip('\x00'):
        diffs = []
        for n, (a, b) in enumerate(zip(out, expected)):
            if a != b:
                diffs.append((n, ord(a), ord(b)))
        print 'BAD ', fname
        for d in diffs:
            print '%04x  %02x->%02x' % d
        return False
    else:
        print 'GOOD', fname
        return True

if __name__ == '__main__':
    total = 0
    good = 0
    for fname in sys.argv[1:]:
        good += check_roundtrip(fname)
        total += 1
    print '%s/%s' % (good, total)
