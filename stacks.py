#!/usr/bin/python
from sys import stderr
import errno

def stack_id_err(stack_id):
    return stack_id < 0 and stack_id != -errno.EFAULT

def print_stack(b, k, v, stack_traces, need_delimiter = False, annotations = False):
    user_stacks = True
    kernel_stacks = False

    if kernel_stacks and stack_id_err(k.kernel_stack_id):
        print("WARNING: stack trace could not be displayed.", file=stderr)
        if k.kernel_stack_id == -errno.ENOMEM:
            print("Consider increasing stack storage size.", file=stderr)
        return
    if user_stacks and stack_id_err(k.user_stack_id):
        print("WARNING: stack trace could not be displayed.", file=stderr)
        if k.user_stack_id == -errno.ENOMEM:
            print("Consider increasing stack storage size.", file=stderr)
        return

    user_stack = \
        list(stack_traces.walk(k.user_stack_id)) if user_stacks else [] 
    kernel_stack = \
        [k.kernel_ip] if kernel_stacks and k.kernel_ip else [] + \
        list(stack_traces.walk(k.kernel_stack_id)) if kernel_stacks and k.kernel_stack_id >= 0 else []

    line = [k.command]
    if user_stacks:
        line += [b.sym(addr, k.tid) for addr in reversed(user_stack)]
    if kernel_stacks:
        annotation = "_[k]".encode() if annotations else ""
        line += [b"-"] if need_delimiter else []
        line += [b.ksym(addr) + annotation for addr in reversed(kernel_stack)]
    print("{} {}".format(b";".join(line).decode('utf-8', 'replace'), v.value))
