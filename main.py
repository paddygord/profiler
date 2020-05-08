#!/usr/bin/env python

import profile
import funcslower

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
