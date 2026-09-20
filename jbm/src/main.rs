use clap::Parser;
use jbm::async_profiler::AsyncProfilerStackTraceProvider;
use jbm::{format_time, pid_alive, Jbm};
use jbm_common::Config;
use log::info;
use std::future::Future;
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
    #[arg(long, default_value_t = false)]
    skip_jvm_stack: bool,
    #[arg(long)]
    async_profiler_bin: Option<String>,
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
        humantime::format_duration(cli.sample_interval).to_string(),
    )
    .await?;
    let mut jbm = Jbm::new(config, async_profiler)?;

    let mut signal = Box::pin(signal::ctrl_c());
    while !has_done(signal.as_mut()) {
        if !pid_alive(cli.pid) {
            info!("Quitting as the target pid {} no longer alive", cli.pid);
            break;
        }
        for (bpf_event, jvm_event) in jbm.process().await? {
            let mut out = format!(
                "=== {} {} PID: {}, TID: {} ({}), DURATION: {} us\n",
                format_time(bpf_event.timestamp),
                bpf_event.timestamp,
                bpf_event.pid,
                bpf_event.tid,
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
    }

    info!("Exiting...");

    Ok(())
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
