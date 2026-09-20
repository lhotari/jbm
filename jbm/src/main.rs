use clap::Parser;
use jbm::async_profiler::AsyncProfilerStackTraceProvider;
use jbm::{format_time, pid_alive, BpfEvent, Jbm, JvmEvent};
use jbm_common::Config;
use log::info;
use serde::Serialize;
use std::fs::File;
use std::future::Future;
use std::io::{BufWriter, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::signal;

const DEFAULT_ASYNC_PROFILER_BIN: &str = "./async-profiler/build/bin/asprof";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "PID")]
    pid: u32,
    #[arg(long, default_value_t = 1000)]
    min_block_time: u64,
    #[arg(long, default_value_t = 18446744073709551615)]
    max_block_time: u64,
    #[arg(long, default_value_t = 10240)]
    stack_storage_size: u32,
    #[arg(long)]
    output: Option<String>,
    #[arg(long)]
    discarded_events_output: Option<String>,
    /// Write JVM off-CPU stacks in collapsed format, weighted in microseconds.
    #[arg(long)]
    collapsed_output: Option<String>,
    /// Suppress human-readable event output on stdout.
    #[arg(long, default_value_t = false)]
    quiet: bool,
    #[arg(long, default_value_t = false)]
    skip_jvm_stack: bool,
    #[arg(long)]
    async_profiler_bin: Option<String>,
    /// async-profiler library path visible in the target process mount namespace.
    #[arg(long)]
    async_profiler_lib: Option<String>,
    /// Directory visible at the same path in the collector and target namespaces.
    #[arg(long)]
    async_profiler_stream_dir: Option<String>,
    /// Minimum interval between samples accepted from blocking events.
    ///
    /// This rate limits stack collection, event output, and JVM stack walking
    /// independently of min-block-time, which selects qualifying events.
    #[arg(long, default_value = "10ms", value_parser = parse_duration)]
    sample_interval: Duration,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let cli = Cli::parse();

    let config = Config {
        target_tgid: cli.pid,
        min_block_us: cli.min_block_time,
        max_block_us: cli.max_block_time,
        sample_interval_ns: cli
            .sample_interval
            .as_nanos()
            .try_into()
            .map_err(|_| anyhow::anyhow!("sample interval is too large"))?,
        stack_storage_size: cli.stack_storage_size,
    };

    let async_profiler = AsyncProfilerStackTraceProvider::start(
        config.target_tgid,
        cli.async_profiler_bin
            .unwrap_or_else(|| DEFAULT_ASYNC_PROFILER_BIN.to_string()),
        cli.async_profiler_lib,
        cli.async_profiler_stream_dir,
    )
    .await?;
    let mut jbm = Jbm::new(config, async_profiler)?;
    let mut collapsed_output = cli
        .collapsed_output
        .as_deref()
        .map(File::create)
        .transpose()?
        .map(BufWriter::new);
    let mut raw_output = cli
        .output
        .as_deref()
        .map(File::create)
        .transpose()?
        .map(BufWriter::new);

    let mut signal = Box::pin(signal::ctrl_c());
    while !has_done(signal.as_mut()) {
        if !pid_alive(cli.pid) {
            info!("Quitting as the target pid {} no longer alive", cli.pid);
            break;
        }
        write_events(
            jbm.process().await?,
            &mut raw_output,
            &mut collapsed_output,
            !cli.quiet,
        )?;
    }

    info!("Exiting...");
    write_events(
        jbm.shutdown().await?,
        &mut raw_output,
        &mut collapsed_output,
        !cli.quiet,
    )?;

    if let Some(output) = raw_output.as_mut() {
        output.flush()?;
    }
    if let Some(output) = collapsed_output.as_mut() {
        output.flush()?;
    }

    Ok(())
}

fn write_events(
    events: Vec<(BpfEvent, Option<JvmEvent>)>,
    raw_output: &mut Option<BufWriter<File>>,
    collapsed_output: &mut Option<BufWriter<File>>,
    print_events: bool,
) -> std::io::Result<()> {
    for (bpf_event, jvm_event) in events {
        if let Some(output) = raw_output.as_mut() {
            serde_json::to_writer(
                &mut *output,
                &CorrelatedEvent {
                    interval: &bpf_event,
                    jvm_stack: jvm_event.as_ref(),
                },
            )?;
            output.write_all(b"\n")?;
        }
        if let Some(output) = collapsed_output.as_mut() {
            writeln!(
                output,
                "{}",
                collapsed_sample(&bpf_event, jvm_event.as_ref())
            )?;
        }
        if !print_events {
            continue;
        }
        let mut out = format!(
            "=== {} {} PID: {}, TID: {} ({}), DURATION: {} us\n",
            format_time(bpf_event.timestamp),
            bpf_event.timestamp,
            bpf_event.pid,
            bpf_event
                .tid
                .map(|tid| tid.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            bpf_event.comm,
            bpf_event.duration.as_micros(),
        );
        out.push_str("Native Stack:\n");
        for (i, (address, symbol)) in bpf_event.stacktrace.into_iter().enumerate() {
            out.push_str(&format!("  {}: [0x{:x}] {}\n", i, address, symbol));
        }
        if let Some(jvm_event) = jvm_event {
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "JVM Stack (took: {}):\n",
                format_time(jvm_event.timestamp)
            ));
            for (i, frame) in jvm_event.frames.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(&format!(
                    "  {}: [0x{:x}] {}",
                    i, frame.method_id, frame.symbol
                ));
            }
        }

        println!("{}", out);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorrelatedEvent<'a> {
    interval: &'a BpfEvent,
    jvm_stack: Option<&'a JvmEvent>,
}

fn collapsed_sample(bpf_event: &BpfEvent, jvm_event: Option<&JvmEvent>) -> String {
    let mut frames = Vec::new();
    frames.push(collapsed_frame(&format!("[thread: {}]", bpf_event.comm)));
    if let Some(jvm_event) = jvm_event {
        if jvm_event.frames.is_empty() {
            frames.push("[empty JVM stack]".to_string());
        } else {
            frames.extend(
                jvm_event
                    .frames
                    .iter()
                    .rev()
                    .map(|frame| collapsed_frame(&frame.symbol)),
            );
        }
    } else {
        frames.push("[no JVM stack]".to_string());
    }
    format!("{} {}", frames.join(";"), bpf_event.duration.as_micros())
}

fn collapsed_frame(frame: &str) -> String {
    frame
        .chars()
        .map(|character| match character {
            ';' => ':',
            '\n' | '\r' => ' ',
            _ => character,
        })
        .collect()
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value).map_err(|error| error.to_string())?;
    if duration.is_zero() {
        return Err("duration must be positive".to_string());
    }
    Ok(duration)
}

fn has_done<F: Future<Output = std::io::Result<()>>>(f: Pin<&mut F>) -> bool {
    let mut ctx = Context::from_waker(futures::task::noop_waker_ref());
    match f.poll(&mut ctx) {
        Poll::Ready(_) => true,
        Poll::Pending => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_duration_weighted_collapsed_stack() {
        let bpf_event = BpfEvent {
            timestamp: 0,
            pid: 1,
            host_tid: 2,
            tid: Some(2),
            comm: "worker".to_string(),
            duration: Duration::from_micros(123),
            start_monotonic_ns: 0,
            end_monotonic_ns: 123_000,
            signal_result: 0,
            stacktrace: Vec::new(),
        };
        let jvm_event = JvmEvent {
            timestamp: 0,
            monotonic_timestamp_ns: 0,
            tid: 2,
            thread_name: "worker".to_string(),
            frames: vec![
                jbm::JvmFrame {
                    bci: 0,
                    method_id: 1,
                    symbol: "leaf;method".to_string(),
                },
                jbm::JvmFrame {
                    bci: 0,
                    method_id: 2,
                    symbol: "root.method".to_string(),
                },
            ],
        };

        assert_eq!(
            collapsed_sample(&bpf_event, Some(&jvm_event)),
            "[thread: worker];root.method;leaf:method 123"
        );
    }
}
