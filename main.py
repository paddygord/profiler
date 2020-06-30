#!/usr/bin/env python

import sys
import dwarf
import test_probe

if len(sys.argv) < 4:
    print("usage:", sys.argv[0], "binary filename line_number")
    sys.exit(1)
binary = sys.argv[1]
filename = sys.argv[2].encode()
line = int(sys.argv[3])

print('getting address from line number')
_, address = dwarf.location_to_abs_address(dwarf.load_dwarf(binary), filename, line)
print('address', hex(address))
print('attaching probe')
test_probe.run(binary, address)
