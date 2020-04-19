#!/usr/bin/env python
import profile

profile.user_stacks_only = False
profile.kernel_stacks_only = False
bpf_text = profile.preprocess()
b = profile.compile(bpf_text)
profile.attach(b)
profile.wait()
profile.report(b)
