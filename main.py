#!/usr/bin/env python

import sys
import profile
import funcslower
import dwarf
import test_probe

if len(sys.argv) < 4:
    print("usage:", sys.argv[0], "binary filename line_number")
    sys.exit(1)
binary = sys.argv[1]
filename = sys.argv[2].encode()
line = int(sys.argv[3])

_, address = dwarf.location_to_abs_address(dwarf.load_dwarf(binary), filename, line)
print('address', hex(address))
test_probe.run(binary, address)

exit(0)

profile.user_stacks_only = False
profile.kernel_stacks_only = False
bpf_text = profile.preprocess()
funcslower.get_user_stack = True
funcslower.get_kernel_stack = True
bpf_text += '\n' + funcslower.preprocess(["c:open"], 3, None)
b = profile.compile(bpf_text)
profile.attach(b)
profile.wait()
profile.report(b)
