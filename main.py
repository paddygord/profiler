#!/usr/bin/env python

import sys
import dwarf
import probe
from time import sleep

if len(sys.argv) < 4:
    print("usage:", sys.argv[0], "binary filename line_number")
    sys.exit(1)
binary = sys.argv[1]
filename = sys.argv[2].encode()
line = int(sys.argv[3])

print('reading dwarf')
_, address = dwarf.location_to_abs_address(dwarf.load_dwarf(binary), filename, line)
print('compiling bpf')
b = probe.compile()
print('attaching probes')
probe.attach(b, binary, address)
print('running')
while True:
    probe.report(b)
    sleep(1)
