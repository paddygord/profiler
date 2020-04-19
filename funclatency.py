#!/usr/bin/python
from bcc import BPF
from time import sleep, strftime
import signal

pid = 0
interval = 0
duration = 0
timestamp = True
microseconds = True
milliseconds = False
function = True
regexp = False
pattern = "*printf"

if duration and not interval:
    interval = duration
if not interval:
    interval = 99999999

if True:
    library = None
    pattern = pattern
else:
    library = BPF.find_library(lib) or BPF.find_exe(lib)
    if not library:
        print("error: can't resolve library %s" % lib)
        exit(1)
    pattern = pattern

if not regexp:
    pattern = pattern.replace('*', '.*')
    pattern = '^' + pattern + '$'

bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct ip_pid {
    u64 ip;
    u64 pid;
} ip_pid_t;

typedef struct hist_key {
    ip_pid_t key;
    u64 slot;
} hist_key_t;

BPF_HASH(start, u32);
STORAGE

int trace_func_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    u64 ts = bpf_ktime_get_ns();

    FILTER
    ENTRYSTORE
    start.update(&pid, &ts);

    return 0;
}

int trace_func_return(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // calculate delta time
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    FACTOR

    // store as histogram
    STORE

    return 0;
}
"""

# do we need to store the IP and pid for each invocation?
need_key = function or (library and not pid)

# code substitutions
if pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (tgid != %d) { return 0; }' % pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"
if need_key:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HASH(ipaddr, u32);\n' +
        'BPF_HISTOGRAM(dist, hist_key_t);')
    # stash the IP on entry, as on return it's kretprobe_trampoline:
    bpf_text = bpf_text.replace('ENTRYSTORE',
        'u64 ip = PT_REGS_IP(ctx); ipaddr.update(&pid, &ip);')
    pid = '-1' if not library else 'tgid'
    bpf_text = bpf_text.replace('STORE',
        """
    u64 ip, *ipp = ipaddr.lookup(&pid);
    if (ipp) {
        ip = *ipp;
        hist_key_t key;
        key.key.ip = ip;
        key.key.pid = %s;
        key.slot = bpf_log2l(delta);
        dist.increment(key);
        ipaddr.delete(&pid);
    }
        """ % pid)
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('ENTRYSTORE', '')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
b = BPF(text=bpf_text)

# attach probes
if not library:
    b.attach_kprobe(event_re=pattern, fn_name="trace_func_entry")
    b.attach_kretprobe(event_re=pattern, fn_name="trace_func_return")
    matched = b.num_open_kprobes()
else:
    b.attach_uprobe(name=library, sym_re=pattern, fn_name="trace_func_entry",
                    pid=pid or -1)
    b.attach_uretprobe(name=library, sym_re=pattern,
                       fn_name="trace_func_return", pid=pid or -1)
    matched = b.num_open_uprobes()

if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % pattern)
    exit()

# header
print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
    (matched / 2, pattern))

# output
def print_section(key):
    if not library:
        return BPF.sym(key[0], -1)
    else:
        return "%s [%d]" % (BPF.sym(key[0], key[1]), key[1])

exiting = not interval
seconds = 0
dist = b.get_table("dist")
while (1):
    try:
        sleep(interval)
        seconds += interval
    except KeyboardInterrupt:
        exiting = True
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
    if duration and seconds >= duration:
        exiting = True

    print()
    if timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if need_key:
        dist.print_log2_hist(label, "Function", section_print_fn=print_section,
            bucket_fn=lambda k: (k.ip, k.pid))
    else:
        dist.print_log2_hist(label)
    dist.clear()

    if exiting:
        print("Detaching...")
        exit()
