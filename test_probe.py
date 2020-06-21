#!/usr/bin/env python
import bcc

def run(binary, offset):
    bpf_text = """
    #include <uapi/linux/bpf_perf_event.h>
    #include <linux/sched.h> //TASK_COMM_LEN

    struct trace {
        u64 tick;
        u64 time;
    };
    BPF_HASH(traces, u32, struct trace);

    struct sample {
        u32 tid;
        int user_stack_id;
        char command[TASK_COMM_LEN];
    };

    BPF_HASH(samples_uncategorised, struct sample, u32);

    BPF_STACK_TRACE(stack_traces, 4096);

    int on_trace(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();

        struct trace* e = traces.lookup(&tid);
        u64 current_time = bpf_ktime_get_ns();
        if (e) {
            u64 dt = current_time - e->time;
            bpf_trace_printk("thread %lu tick %llu time %lluns\\n", tid, e->tick, dt);
            e->time = current_time;
            e->tick += 1;
            //TODO is it safe to use this pointer?
            //won't there be concurrent inserts to the map
            //that will invalidate the pointer
        } else {
            struct trace e;
            e.tick = 0;
            e.time = current_time;
            traces.insert(&tid, &e);
        }

        return 0;
    }

    int on_sample(struct bpf_perf_event_data *ctx) {
        struct sample s;
        s.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
        s.tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&s.command, sizeof(s.command));
        samples_uncategorised.increment(s);
        bpf_trace_printk("blep\\n");
        return 0;
    }
    """

    b = bcc.BPF(text=bpf_text)
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
        sample_freq=1,
        cpu=-1
    )

    print('good')
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            print(msg.decode())
        except ValueError:
            pass
