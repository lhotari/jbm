#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    bindings::{BPF_F_USER_STACK, BPF_NOEXIST},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_send_signal_thread,
    },
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray, StackTrace},
    programs::{ProbeContext, TracePointContext},
};
use jbm_common::{
    BlockEvent, CollectionStats, Config, STACK_STORAGE_SIZE, TASK_COMM_LEN,
};

#[map(name = "START_TIMES")]
static mut START_TIMES: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(10240, 0);

#[map(name = "RATE_LIMIT_LOCK")]
static mut RATE_LIMIT_LOCK: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1, 0);

#[map(name = "LAST_SAMPLE_TIME")]
static mut LAST_SAMPLE_TIME: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1, 0);

#[map(name = "STACK_TRACES")]
static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_STORAGE_SIZE as u32, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);

#[map(name = "STATS")]
static mut STATS: PerCpuArray<CollectionStats> = PerCpuArray::with_max_entries(1, 0);

// The actual value is set at initialization phase by the control application
#[no_mangle]
static CONFIG: Config = Config {
    target_tgid: 0,
    min_block_us: 0,
    max_block_us: 0,
    sample_interval_ns: 0,
    stack_storage_size: 0,
};

#[kprobe(name = "jbm")]
pub fn jbm(ctx: ProbeContext) -> u32 {
    match unsafe { try_jbm(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint(name = "record_switch_out")]
pub fn record_switch_out(ctx: TracePointContext) -> u32 {
    match unsafe { try_record_switch_out(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_record_switch_out(_ctx: TracePointContext) -> Result<u32, i64> {
    // sched_switch runs in the outgoing task's context, so helpers provide the
    // outgoing PID/TGID without reading version-dependent task_struct fields.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let config = core::ptr::read_volatile(&CONFIG);
    if tgid == config.target_tgid {
        START_TIMES.insert(&pid, &bpf_ktime_get_ns(), 0)?;
    }
    Ok(0)
}

unsafe fn try_jbm(ctx: ProbeContext) -> Result<u32, i64> {
    let config = core::ptr::read_volatile(&CONFIG);

    // finish_task_switch runs in the incoming task's context.
    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let t_start = if let Some(tsp) = START_TIMES.get(&pid) {
        *tsp
    } else {
        return Ok(0);
    };

    // calculate current thread's delta time
    let t_end = bpf_ktime_get_ns();
    START_TIMES.remove(&pid)?;
    if tgid != config.target_tgid {
        // There's a possibility such a task id that previously belonged to tgid = 1234
        // is now re-used and is a task id of a different process.
        return Ok(0);
    }
    if t_start > t_end {
        return Ok(0);
    }
    let offtime = (t_end - t_start) / 1000;

    if offtime < config.min_block_us || offtime > config.max_block_us {
        return Ok(0);
    }
    if let Some(stats) = STATS.get_ptr_mut(0) {
        (*stats).eligible_intervals += 1;
        (*stats).eligible_duration_us += offtime;
    }

    // Rate limit before stack collection, perf-buffer output, and signal
    // delivery. This is the authoritative limiter: rejecting the matching
    // signal later would leave an emitted BPF event without its JVM stack.
    // A BPF_NOEXIST insertion is an atomic, non-spinning try-lock across
    // CPUs. Hold it only while checking and updating the global timestamp;
    // expensive stack collection and signal delivery happen after release.
    // A contended attempt is conservatively skipped and counted separately.
    let sample_key: u32 = 0;
    if RATE_LIMIT_LOCK
        .insert(&sample_key, &1, BPF_NOEXIST as u64)
        .is_err()
    {
        if let Some(stats) = STATS.get_ptr_mut(0) {
            (*stats).limiter_contention += 1;
        }
        return Ok(0);
    }
    let too_soon = LAST_SAMPLE_TIME.get(&sample_key).is_some_and(|last_sample_time| {
        t_end <= *last_sample_time || t_end - *last_sample_time < config.sample_interval_ns
    });
    if too_soon {
        let _ = RATE_LIMIT_LOCK.remove(&sample_key);
        if let Some(stats) = STATS.get_ptr_mut(0) {
            (*stats).interval_rejections += 1;
        }
        return Ok(0);
    }
    let update_result = LAST_SAMPLE_TIME.insert(&sample_key, &t_end, 0);
    let unlock_result = RATE_LIMIT_LOCK.remove(&sample_key);
    update_result?;
    unlock_result?;
    if let Some(stats) = STATS.get_ptr_mut(0) {
        (*stats).selected_intervals += 1;
    }

    // create and submit an event
    // A stack-map failure must not suppress the interval or its JVM sample.
    // Preserve the negative BPF error in the event so user space can account
    // for the missing native stack independently.
    let kernel_stack_id = match STACK_TRACES.get_stackid(&ctx, 0) {
        Ok(stack_id) => stack_id,
        Err(error) => error,
    };
    let user_stack_id = match STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK as u64) {
        Ok(stack_id) => stack_id,
        Err(error) => error,
    };
    if let Some(stats) = STATS.get_ptr_mut(0) {
        if kernel_stack_id < 0 {
            (*stats).kernel_stack_failures += 1;
        }
        if user_stack_id < 0 {
            (*stats).user_stack_failures += 1;
        }
    }

    let name = match bpf_get_current_comm() {
        Ok(name) => name,
        Err(_) => [0; TASK_COMM_LEN],
    };
    let signal_result = bpf_send_signal_thread(27);
    if signal_result != 0 {
        if let Some(stats) = STATS.get_ptr_mut(0) {
            (*stats).signal_failures += 1;
        }
    }
    let event = BlockEvent {
        pid,
        tgid,
        user_stack_id,
        kernel_stack_id,
        name,
        offtime,
        t_start,
        t_end,
        signal_result,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
