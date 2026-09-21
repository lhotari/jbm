# JBM

> JBM = Java Blocking Monitor

JBM is an agent that monitors JVM processes from the kernel using eBPF. It detects when an application thread is blocking for an extended period of time and generates a backtrace from the kernel to userspace. It then reports this information, providing valuable insights into blocking issues within your JVM applications.


# Building

1. Install rustup: https://rustup.rs/
2. Install Rust and bpf-linker
```sh
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```
3. Build JBM
```sh
git clone https://github.com/kawamuray/jbm.git
cd jbm

# Build async-profiler
git submodule update --init
cd async-profiler
git submodule update --init
make -j8

cd ..

# Build JBM
cargo xtask build-ebpf --release
cargo build --release
# Now binrary is ready at:
./target/release/jbm
```

# Usage

```sh
# Example usage for detecting "block" behavior defined as a thread stopped over a second but less than a minute
jbm -p TARGET_JVM_PID \
  --min-block-time 1000000 \
  --max-block-time 60000000 \
  --sample-probability 0.001 \
  --output offcpu.jsonl \
  --collapsed-output offcpu.collapsed \
  --quiet \
  --async-profiler-lib /path/visible/in/target/libasyncProfiler.so \
  --async-profiler-stream-dir /path/shared/by/collector/and/target
```

`--min-block-time` and `--max-block-time` select completed off-CPU intervals by
their duration in microseconds. `--sample-probability` independently selects each
qualifying interval with a probability between 0 and 1 (default 0.001, or 0.1%).
Zero captures none; one captures all qualifying intervals. The kernel performs
selection before stack collection, event output, and signaling the JVM. No global
rate-limiter lock is used. Capture volume grows with workload, so a probability is
not a maximum samples-per-second limit. Async-profiler accepts every signal;
selection happens only in JBM so a second filter cannot discard matching stacks.

`--collapsed-output` writes correlated JVM stacks in the standard collapsed
format. Each line is weighted by the event's off-CPU duration in microseconds,
so it can be rendered with FlameGraph tools. Events without a matching JVM
sample are retained under a `[no JVM stack]` frame, preserving their duration
in the profile total.

The bundled async-profiler converter renders the collapsed output as an
interactive off-CPU Flame Graph. Label the duration counter explicitly because
collapsed files do not carry unit metadata:

```sh
async-profiler/build/bin/jfrconv \
  --units us \
  --title "JVM off-CPU duration" \
  offcpu.collapsed offcpu.html
```

The graph represents the duration of the intervals selected by JBM's event-probability
sampling policy. Raw weights are not extrapolated. Dividing by the effective
probability estimates duration for qualifying completed intervals only, assuming
no capture loss; it does not include waits excluded by the duration filters or
waits that have not completed. The threshold is quantized to 1 / 2^32.

`--output` preserves each selected interval as JSONL, including its host and
JVM-visible thread identifiers, monotonic start and end timestamps, duration,
native stack, and optional correlated JVM stack. Keep this raw output alongside
the collapsed file so correlation and measurement-window policies remain
auditable.

Use `--quiet` for performance runs to avoid formatting and writing a verbose
human-readable copy of every event to stdout. Raw and collapsed files are still
written.

Set `RUST_LOG=info` to retain the final coverage summary. It reports eligible,
probability-rejected, selected, received, matched and unmatched interval counts, plus
stack, signal and perf-ring failures. Treat a capture with unexplained
selected/received differences or any transport loss as incomplete.

Use `--async-profiler-lib` when the collector launcher and target JVM need
different native builds, such as a glibc collector profiling a musl-based
Pulsar container. The path must be absolute and visible at the same location in
the target process mount namespace.

For a target in another mount namespace, `--async-profiler-stream-dir` must
name a writable directory mounted at the same absolute path in the collector
and target. JBM tails the live JSONL stream from this directory.

# How it works

![How it works](how-it-works.png)

After startup JBM attaches to the `sched_switch` tracepoint and adds a kprobe for
`finish_task_switch`. The tracepoint records when a target thread leaves a CPU
using stable PID/TGID helpers, while the kprobe detects when that thread resumes.
This avoids depending on kernel-version-specific `task_struct` field offsets.
The difference between those timestamps is the thread's off-CPU interval.
The target JVM gets the custom [async-profiler](https://github.com/async-profiler/async-profiler) attached.
The eBPF program then sends an event when it detects long blocking, and user space control program zips the kernel space backtrace obtained by an event from eBPF with the event generated by the custom async-profiler running on the target JVM, which generates an event in response to receiving singnal from the eBPF program.

## License

JBM is licensed under the [MIT License](https://opensource.org/licenses/MIT). You are free to use, modify, and distribute this software. See the `LICENSE` file for more information.
