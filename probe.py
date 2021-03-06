#!/usr/bin/env python
import bcc
from stacks import print_stack

def compile():
    bpf_text = """
    #include <uapi/linux/bpf_perf_event.h>
    #include <linux/sched.h> //TASK_COMM_LEN

    typedef u32 tid_t;
    typedef u64 tick_t;
    typedef u64 time_t;

    struct trace {
        tick_t tick;
        time_t time;
    };
    BPF_HASH(current_traces, tid_t, struct trace);

    struct output_trace {
        tick_t tick;
        tid_t tid;
    };
    BPF_HASH(output_traces, struct output_trace, time_t);

    struct sample {
        tick_t tick;
        tid_t tid;
        int user_stack_id;
        char command[TASK_COMM_LEN];
    };
    BPF_HASH(samples, struct sample, u32);

    BPF_STACK_TRACE(stack_traces, 4096);

    int on_trace(struct pt_regs *ctx) {
        tid_t tid = bpf_get_current_pid_tgid();

        struct trace* t = current_traces.lookup(&tid);
        time_t current_time = bpf_ktime_get_ns();
        if (t) {
            time_t dt = current_time - t->time;

            struct output_trace output = {};
            output.tick = t->tick;
            output.tid = tid;
            output_traces.insert(&output, &dt);

            t->time = current_time;
            t->tick += 1;
            //TODO is it safe to use this pointer?
            //won't there be concurrent inserts to the map
            //that will invalidate the pointer
        } else {
            struct trace t;
            t.tick = 0;
            t.time = current_time;
            current_traces.insert(&tid, &t);
        }

        return 0;
    }

    int on_sample(struct bpf_perf_event_data *ctx) {
        tid_t tid = bpf_get_current_pid_tgid();
        struct trace* t = current_traces.lookup(&tid);
        if (!t) {
            //ignore sample, not from a tid with a previous trace
            return 0;
        }
        struct sample s = {};
        s.tick = t->tick;
        s.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
        s.tid = tid;
        bpf_get_current_comm(&s.command, sizeof(s.command));
        samples.increment(s);
        return 0;
    }
    """

    b = bcc.BPF(text=bpf_text)
    return b

def attach(b, binary, offset):
    b.attach_uprobe(
        name=binary,
        addr=offset,
        fn_name="on_trace"
    )

    b.attach_perf_event(
        ev_type=bcc.PerfType.SOFTWARE,
        ev_config=bcc.PerfSWConfig.CPU_CLOCK,
        fn_name="on_sample",
        sample_period=0,
        sample_freq=4096,
        cpu=-1
    )

def report(b):
    samples = b["samples"]
    traces = b["output_traces"]
    stack_traces = b["stack_traces"]
    for k, v in samples.items():
        print("tick {} tid {}".format(k.tick, k.tid))
        try:
            print_stack(b, k, v, stack_traces)
        except KeyError:
            pass
    for k, v in sorted(traces.items(), key=lambda kv: kv[0].tick):
        #print("tick {} tid {} time {}".format(k.tick, k.tid, v.value))
        pass
    samples.clear()
    traces.clear()
