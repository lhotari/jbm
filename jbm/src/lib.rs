pub mod async_profiler;
mod symbol;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use aya::{
    include_bytes_aligned,
    maps::{
        perf::{PerfEventArray, PerfEventArrayBuffer},
        MapData, PerCpuArray, StackTraceMap,
    },
    programs::{kprobe::KProbeLinkId, trace_point::TracePointLinkId, KProbe, TracePoint},
    util::{kernel_symbols, online_cpus},
    Bpf, BpfError, BpfLoader, Btf,
};
use bytes::BytesMut;
use chrono::{Local, TimeZone};
use jbm_common::{BlockEvent, CollectionStats, Config, STACK_STORAGE_SIZE};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    ffi::CStr,
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use symbol::Resolver;
use tokio::{sync::mpsc, task::JoinHandle};

const EVENT_MATCH_TIME_THRESHOLD: Duration = Duration::from_secs(1);
const EVENT_MATCH_GIVEUP_TIME: Duration = Duration::from_secs(30);
const STACK_STORAGE_SIZE_CHECK_COUNT: usize = 100;
const PERF_EVENTS_PER_READ: usize = 64;
const PERF_EVENT_CHANNEL_CAPACITY: usize = 256;
const PERF_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const PERF_READER_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(50);
const PERF_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

enum PerfReaderMessage {
    Progress {
        cpu: u32,
        observed_through_ns: u64,
        events: Vec<BlockEvent>,
        lost: u64,
    },
    Failed {
        cpu: u32,
        error: String,
    },
}

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Jbm<JvmStackP: JvmStackTraceProvider> {
    bpf: Bpf,
    perf_event_receiver: mpsc::Receiver<PerfReaderMessage>,
    perf_readers: Vec<JoinHandle<()>>,
    perf_watermarks: HashMap<u32, u64>,
    perf_reader_failure: Option<String>,
    lost_perf_events: u64,
    emitted_intervals: u64,
    matched_intervals: u64,
    stream: EventStream,
    jvm_stack_provider: JvmStackP,
    resume_link: Option<KProbeLinkId>,
    switch_out_link: Option<TracePointLinkId>,
}

impl<JvmStackP: JvmStackTraceProvider + Send> Jbm<JvmStackP> {
    pub fn new(config: Config, jvm_stack_provider: JvmStackP) -> Result<Self> {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
        let bpf_binary = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/jbm");
        #[cfg(not(debug_assertions))]
        let bpf_binary = include_bytes_aligned!("../../target/bpfel-unknown-none/release/jbm");

        let mut bpf = match Self::load_bpf(&bpf_binary, &config) {
            Ok(bpf) => bpf,
            Err(e) => {
                if let BpfError::MapError(_) = e {
                    // On some platform BPF map creation can fail with EPERM by lack of
                    // MEMLOCK resource limit. bcc work-around by increasing resource limit
                    // when map creation fails with EPERM.
                    if let Ok(_) = nix::sys::resource::setrlimit(
                        nix::sys::resource::Resource::RLIMIT_MEMLOCK,
                        nix::sys::resource::RLIM_INFINITY,
                        nix::sys::resource::RLIM_INFINITY,
                    ) {
                        Self::load_bpf(&bpf_binary, &config)
                            .context("load BPF program after raising memlock limit")?
                    } else {
                        return Err(e).context("load BPF program and raise memlock limit");
                    }
                } else {
                    return Err(e).context("load BPF program");
                }
            }
        };

        let symbols = kernel_symbols().context("read kernel symbols")?;
        let finish_task_switch = find_finish_task_switch(&symbols)
            .ok_or_else(|| anyhow!("cannot find finish_task_switch kernel symbol"))?;
        let program: &mut KProbe = bpf
            .program_mut("jbm")
            .expect("program 'jbm'")
            .try_into()
            .context("get jbm kprobe program")?;
        program.load().context("load finish_task_switch kprobe")?;
        let switch_out: &mut TracePoint = bpf
            .program_mut("record_switch_out")
            .expect("program 'record_switch_out'")
            .try_into()
            .context("get sched_switch tracepoint program")?;
        switch_out
            .load()
            .context("load sched_switch tracepoint program")?;
        let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").expect("EVENTS map"))
            .context("open BPF EVENTS map")?;

        let (perf_event_sender, perf_event_receiver) = mpsc::channel(PERF_EVENT_CHANNEL_CAPACITY);
        let cpus = online_cpus().context("read online CPU list")?;
        let mut perf_readers = Vec::new();
        let mut perf_watermarks = HashMap::with_capacity(cpus.len());
        for cpu in cpus {
            let perf_buf = perf_array
                .open(cpu, None)
                .with_context(|| format!("open BPF perf event buffer for CPU {cpu}"))?;
            perf_readers.push(spawn_perf_reader(cpu, perf_buf, perf_event_sender.clone()));
            perf_watermarks.insert(cpu, 0);
        }
        drop(perf_event_sender);

        // Enable producers only after every per-CPU perf ring has a reader.
        // This keeps startup records from being selected by BPF before user
        // space has somewhere to receive them.
        let program: &mut KProbe = bpf.program_mut("jbm").expect("program 'jbm'").try_into()?;
        let resume_link = program
            .attach(finish_task_switch, 0)
            .with_context(|| format!("attach kprobe to {finish_task_switch}"))?;
        let switch_out: &mut TracePoint = bpf
            .program_mut("record_switch_out")
            .expect("program 'record_switch_out'")
            .try_into()?;
        let switch_out_link = switch_out
            .attach("sched", "sched_switch")
            .context("attach sched_switch tracepoint program")?;

        Ok(Self {
            bpf,
            perf_event_receiver,
            perf_readers,
            perf_watermarks,
            perf_reader_failure: None,
            lost_perf_events: 0,
            emitted_intervals: 0,
            matched_intervals: 0,
            stream: EventStream::new(),
            jvm_stack_provider,
            resume_link: Some(resume_link),
            switch_out_link: Some(switch_out_link),
        })
    }

    fn load_bpf(bpf_binary: &[u8], config: &Config) -> std::result::Result<Bpf, BpfError> {
        BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .set_max_entries("STACK_TRACES", config.stack_storage_size)
            .set_global("CONFIG", config)
            .load(bpf_binary)
    }

    pub async fn process(&mut self) -> Result<Vec<(BpfEvent, Option<JvmEvent>)>> {
        let bpf_events = self.receive_perf_events(PERF_EVENT_POLL_INTERVAL).await?;
        self.add_bpf_events(bpf_events)?;

        self.jvm_stack_provider
            .fill_queue(&mut self.stream.jvm_events)
            .await?;
        let results = self.stream.sweep(self.correlation_watermark_ns());
        self.account_results(&results);
        Ok(results)
    }

    pub async fn shutdown(&mut self) -> Result<Vec<(BpfEvent, Option<JvmEvent>)>> {
        if let Some(link) = self.switch_out_link.take() {
            let program: &mut TracePoint = self
                .bpf
                .program_mut("record_switch_out")
                .expect("program 'record_switch_out'")
                .try_into()?;
            program.detach(link)?;
        }
        if let Some(link) = self.resume_link.take() {
            let program: &mut KProbe = self
                .bpf
                .program_mut("jbm")
                .expect("program 'jbm'")
                .try_into()?;
            program.detach(link)?;
        }
        let detached_at_ns = monotonic_time_ns();
        let drain_deadline = tokio::time::Instant::now() + PERF_SHUTDOWN_DRAIN_TIMEOUT;
        while self.correlation_watermark_ns() < detached_at_ns {
            if tokio::time::Instant::now() >= drain_deadline {
                return Err(anyhow!(
                    "timed out draining per-CPU perf readers after BPF detach"
                ));
            }
            let bpf_events = self
                .receive_perf_events(PERF_READER_HEARTBEAT_INTERVAL)
                .await?;
            self.add_bpf_events(bpf_events)?;
        }
        for reader in self.perf_readers.drain(..) {
            reader.abort();
        }
        let bpf_events = self.receive_perf_events(Duration::ZERO).await?;
        self.add_bpf_events(bpf_events)?;
        self.jvm_stack_provider.stop().await?;
        self.jvm_stack_provider
            .fill_queue(&mut self.stream.jvm_events)
            .await?;
        if self.lost_perf_events != 0 {
            warn!(
                "{} events from eBPF were lost due to slow consumption",
                self.lost_perf_events
            );
        }
        let results = self.stream.sweep_remaining();
        self.account_results(&results);
        let stats = self.collection_stats()?;
        info!(
            "BPF coverage: eligible_intervals={}, eligible_duration_us={}, limiter_contention={}, interval_rejections={}, selected_intervals={}, received_intervals={}, matched_intervals={}, unmatched_intervals={}, kernel_stack_failures={}, user_stack_failures={}, signal_failures={}, perf_lost={}",
            stats.eligible_intervals,
            stats.eligible_duration_us,
            stats.limiter_contention,
            stats.interval_rejections,
            stats.selected_intervals,
            self.emitted_intervals,
            self.matched_intervals,
            self.emitted_intervals - self.matched_intervals,
            stats.kernel_stack_failures,
            stats.user_stack_failures,
            stats.signal_failures,
            self.lost_perf_events,
        );
        Ok(results)
    }

    fn account_results(&mut self, results: &[(BpfEvent, Option<JvmEvent>)]) {
        self.emitted_intervals += results.len() as u64;
        self.matched_intervals += results
            .iter()
            .filter(|(_, jvm_event)| jvm_event.is_some())
            .count() as u64;
    }

    pub fn collection_stats(&self) -> Result<CollectionStats> {
        let stats: PerCpuArray<&MapData, CollectionStats> =
            PerCpuArray::try_from(self.bpf.map("STATS").expect("STATS map"))?;
        let mut total = CollectionStats::default();
        for value in stats.get(&0, 0)?.iter() {
            total.eligible_intervals += value.eligible_intervals;
            total.eligible_duration_us += value.eligible_duration_us;
            total.limiter_contention += value.limiter_contention;
            total.interval_rejections += value.interval_rejections;
            total.selected_intervals += value.selected_intervals;
            total.kernel_stack_failures += value.kernel_stack_failures;
            total.user_stack_failures += value.user_stack_failures;
            total.signal_failures += value.signal_failures;
        }
        Ok(total)
    }

    async fn receive_perf_events(&mut self, wait: Duration) -> Result<Vec<BlockEvent>> {
        let mut events = Vec::new();
        if !wait.is_zero() {
            if let Ok(Some(batch)) =
                tokio::time::timeout(wait, self.perf_event_receiver.recv()).await
            {
                self.append_perf_message(batch, &mut events);
            }
        }
        while let Ok(message) = self.perf_event_receiver.try_recv() {
            self.append_perf_message(message, &mut events);
        }
        if let Some(error) = self.perf_reader_failure.take() {
            return Err(anyhow!(error));
        }
        events.sort_unstable_by_key(|event| event.t_end);
        Ok(events)
    }

    fn append_perf_message(&mut self, message: PerfReaderMessage, events: &mut Vec<BlockEvent>) {
        match message {
            PerfReaderMessage::Progress {
                cpu,
                observed_through_ns,
                events: batch_events,
                lost,
            } => {
                self.lost_perf_events += lost;
                if observed_through_ns != 0 {
                    self.perf_watermarks
                        .entry(cpu)
                        .and_modify(|watermark| *watermark = (*watermark).max(observed_through_ns))
                        .or_insert(observed_through_ns);
                }
                events.extend(batch_events);
            }
            PerfReaderMessage::Failed { cpu, error } => {
                self.perf_reader_failure =
                    Some(format!("perf reader for CPU {cpu} failed: {error}"));
            }
        }
    }

    fn correlation_watermark_ns(&self) -> u64 {
        self.perf_watermarks.values().copied().min().unwrap_or(0)
    }

    fn add_bpf_events(&mut self, events: Vec<BlockEvent>) -> Result<()> {
        for bpf_event in events {
            #[cfg(kernel3x)]
            let pid = bpf_event.pid as i32;
            self.stream.add_bpf_event(&self.bpf, bpf_event)?;
            #[cfg(kernel3x)]
            Self::send_signal(pid);
        }
        Ok(())
    }

    #[cfg(kernel3x)]
    fn send_signal(pid: i32) {
        debug!("Signaling {}", pid);
        let error = unsafe { libc::kill(pid, libc::SIGPROF) };
        if error != 0 {
            eprintln!("Failed to signal TID {}: error = {}", pid, error);
        }
    }
}

fn spawn_perf_reader(
    cpu: u32,
    mut perf_buf: PerfEventArrayBuffer<MapData>,
    sender: mpsc::Sender<PerfReaderMessage>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut read_bufs =
            vec![BytesMut::with_capacity(std::mem::size_of::<BlockEvent>()); PERF_EVENTS_PER_READ];
        loop {
            // A progress timestamp is taken before reading. Once the direct
            // ring read returns fewer than the buffer capacity, all
            // records whose end precedes this timestamp have been drained
            // from this CPU's ring and were sent before the watermark.
            let observed_through_ns = monotonic_time_ns();
            let info = match perf_buf.read_events(&mut read_bufs) {
                Ok(info) => info,
                Err(error) => {
                    let error = format!("{error:?}");
                    error!("Failed to poll eBPF buffer for CPU {}: {}", cpu, error);
                    let _ = sender.send(PerfReaderMessage::Failed { cpu, error }).await;
                    break;
                }
            };
            let read = info.read;
            let events = read_bufs[..read]
                .iter()
                .map(|buf| {
                    let mut event: BlockEvent = unsafe { std::mem::zeroed() };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            buf.as_ptr(),
                            &mut event as *mut BlockEvent as *mut u8,
                            std::mem::size_of::<BlockEvent>(),
                        );
                    }
                    event
                })
                .collect();
            let lost = info.lost as u64;
            let ring_was_drained = read < PERF_EVENTS_PER_READ;
            if sender
                .send(PerfReaderMessage::Progress {
                    cpu,
                    observed_through_ns: if ring_was_drained {
                        observed_through_ns
                    } else {
                        0
                    },
                    events,
                    lost,
                })
                .await
                .is_err()
            {
                break;
            }
            if read == 0 {
                tokio::time::sleep(PERF_READER_HEARTBEAT_INTERVAL).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
    })
}

fn find_finish_task_switch(symbols: &BTreeMap<u64, String>) -> Option<&str> {
    symbols
        .values()
        .find(|symbol| symbol.as_str() == "finish_task_switch")
        .or_else(|| {
            symbols.values().find(|symbol| {
                symbol.starts_with("finish_task_switch.") && !symbol.ends_with(".cold")
            })
        })
        .map(String::as_str)
}

#[cfg(test)]
mod kernel_symbol_tests {
    use super::*;

    #[test]
    fn prefers_exact_finish_task_switch_symbol() {
        let symbols = BTreeMap::from([
            (1, "finish_task_switch.isra.0".to_string()),
            (2, "finish_task_switch".to_string()),
        ]);
        assert_eq!(
            find_finish_task_switch(&symbols),
            Some("finish_task_switch")
        );
    }

    #[test]
    fn accepts_non_cold_compiler_suffix() {
        let symbols = BTreeMap::from([
            (1, "finish_task_switch.isra.0.cold".to_string()),
            (2, "finish_task_switch.isra.0".to_string()),
        ]);
        assert_eq!(
            find_finish_task_switch(&symbols),
            Some("finish_task_switch.isra.0")
        );
    }
}

#[async_trait]
pub trait JvmStackTraceProvider {
    async fn fill_queue(&mut self, queues: &mut HashMap<u32, VecDeque<JvmEvent>>) -> Result<()>;

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmEvent {
    pub timestamp: u64,
    pub monotonic_timestamp_ns: u64,
    pub tid: u32,
    #[serde(default)]
    pub thread_name: String,
    pub frames: Vec<JvmFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmFrame {
    pub bci: i64,
    pub method_id: u64,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BpfEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub host_tid: u32,
    /// Thread ID as seen by the target JVM, or `None` if the host-to-target
    /// PID namespace translation could not be completed.
    pub tid: Option<u32>,
    pub comm: String,
    pub duration: Duration,
    pub start_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
    pub signal_result: i64,
    pub stacktrace: Vec<(u64, String)>,
}

pub struct EventStream {
    bpf_events: HashMap<u32, VecDeque<BpfEvent>>,
    unmatched_bpf_events: VecDeque<BpfEvent>,
    event_count: usize,
    jvm_events: HashMap<u32, VecDeque<JvmEvent>>,
    ksyms: BTreeMap<u64, String>,
    symbol_resolver: Resolver,
    native_symbolization_unavailable: HashSet<u32>,
}

impl EventStream {
    pub fn new() -> Self {
        Self {
            bpf_events: HashMap::new(),
            unmatched_bpf_events: VecDeque::new(),
            jvm_events: HashMap::new(),
            ksyms: kernel_symbols().expect("kernel symbols"),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
            event_count: 0,
        }
    }

    pub fn add_bpf_event(&mut self, bpf: &Bpf, event: BlockEvent) -> Result<()> {
        let stack_traces =
            StackTraceMap::try_from(bpf.map("STACK_TRACES").expect("STACK_TRACES map"))?;
        let mut frames = Vec::new();

        if event.kernel_stack_id >= 0 {
            match stack_traces.get(&(event.kernel_stack_id as u32), 0) {
                Ok(mut kernel_stack) => {
                    for frame in kernel_stack.resolve(&self.ksyms).frames() {
                        frames.push((
                            frame.ip,
                            frame
                                .symbol_name
                                .clone()
                                .unwrap_or("[unknown symbol name]".to_string()),
                        ));
                    }
                }
                Err(error) => frames.push((0, format!("[kernel stack unavailable: {error}]"))),
            }
        } else {
            frames.push((
                0,
                format!("[kernel stack capture failed: {}]", event.kernel_stack_id),
            ));
        }

        if event.user_stack_id >= 0 {
            match stack_traces.get(&(event.user_stack_id as u32), 0) {
                Ok(user_stack) => {
                    let user_addresses = user_stack
                        .frames()
                        .iter()
                        .map(|f| f.ip as usize)
                        .collect::<Vec<_>>();
                    let unresolved_frames = || {
                        user_addresses
                            .iter()
                            .map(|address| (*address as u64, None))
                            .collect::<Vec<_>>()
                    };
                    let user_frames = if self.native_symbolization_unavailable.contains(&event.tgid)
                    {
                        unresolved_frames()
                    } else {
                        self.symbol_resolver
                            .resolve(event.tgid, &user_addresses)
                            .unwrap_or_else(|error| {
                                self.native_symbolization_unavailable.insert(event.tgid);
                                warn!(
                                    "Unable to symbolize native user stacks for process {}: {}",
                                    event.tgid, error
                                );
                                unresolved_frames()
                            })
                    };
                    for (addr, symbol) in user_frames {
                        frames.push((addr, symbol.unwrap_or("[unknown symbol name]".to_string())));
                    }
                }
                Err(error) => frames.push((0, format!("[user stack unavailable: {error}]"))),
            }
        } else {
            frames.push((
                0,
                format!("[user stack capture failed: {}]", event.user_stack_id),
            ));
        }

        let comm = CStr::from_bytes_until_nul(&event.name)?
            .to_string_lossy()
            .to_string();

        let timestamp = Self::compute_timestamp(event.t_end);
        let tid = namespace_tid(event.tgid, event.pid)
            .map(Some)
            .unwrap_or_else(|error| {
                warn!(
                    "Unable to translate host TID {} for process {}: {}",
                    event.pid, event.tgid, error
                );
                None
            });
        let bpf_event = BpfEvent {
            timestamp,
            pid: event.tgid,
            host_tid: event.pid,
            tid,
            comm,
            duration: Duration::from_micros(event.offtime),
            start_monotonic_ns: event.t_start,
            end_monotonic_ns: event.t_end,
            signal_result: event.signal_result,
            stacktrace: frames,
        };
        if let Some(tid) = tid {
            self.enqueue_bpf_event(tid, bpf_event);
        } else {
            self.unmatched_bpf_events.push_back(bpf_event);
        }

        self.event_count += 1;
        if self.event_count % STACK_STORAGE_SIZE_CHECK_COUNT == 0 {
            let cur_size = stack_traces.iter().count();
            if cur_size >= STACK_STORAGE_SIZE {
                warn!(
                    "Stacktraces storage is full, some stacks may be missing in output: {}/{}",
                    cur_size, STACK_STORAGE_SIZE
                );
            }
        }

        Ok(())
    }

    fn enqueue_bpf_event(&mut self, tid: u32, event: BpfEvent) {
        let queue = self.bpf_events.entry(tid).or_default();
        if queue
            .back()
            .map_or(true, |last| last.end_monotonic_ns <= event.end_monotonic_ns)
        {
            queue.push_back(event);
            return;
        }
        let position = queue
            .iter()
            .position(|queued| queued.end_monotonic_ns > event.end_monotonic_ns)
            .unwrap_or(queue.len());
        queue.insert(position, event);
    }

    fn compute_timestamp(bpf_ktime: u64) -> u64 {
        let now_ktime = Duration::from(
            nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
                .expect("clock_gettime(MONOTONIC)"),
        )
        .as_nanos() as u64;
        let offset = now_ktime - bpf_ktime;
        let now = time_now();
        let timestamp =
            (Duration::from_millis(now) - Duration::from_nanos(offset)).as_millis() as u64;
        debug!(
            "Event time compute, offset={}, now={}, timestamp={}",
            offset, now, timestamp
        );
        timestamp
    }

    pub fn sweep(&mut self, correlation_watermark_ns: u64) -> Vec<(BpfEvent, Option<JvmEvent>)> {
        let now_monotonic_ns = monotonic_time_ns();

        let mut empty = VecDeque::with_capacity(0);
        let mut ret: Vec<(BpfEvent, Option<JvmEvent>)> = self
            .unmatched_bpf_events
            .drain(..)
            .map(|event| (event, None))
            .collect();
        let mut tids = self.bpf_events.keys().copied().collect::<Vec<_>>();
        tids.sort_unstable();
        for tid in tids {
            let bpf_queue = self.bpf_events.get_mut(&tid).expect("bpf queue present");
            let jvm_queue = self.jvm_events.get_mut(&tid).unwrap_or(&mut empty);
            while let Some(bpf_event) = bpf_queue.front() {
                debug!(
                    "Finding match from {} JVM events for tid {}",
                    jvm_queue.len(),
                    tid
                );
                // Do not consume or discard a JVM sample until every CPU has
                // drained BPF records through its timestamp. An older interval
                // from this thread may still arrive from another CPU after a
                // migration; enqueue_bpf_event will place it chronologically.
                let mut waiting_for_watermark = false;
                loop {
                    match jvm_queue.front() {
                        Some(event) if event.monotonic_timestamp_ns > correlation_watermark_ns => {
                            waiting_for_watermark = true;
                            break;
                        }
                        Some(event)
                            if event.monotonic_timestamp_ns < bpf_event.end_monotonic_ns =>
                        {
                            Self::trash_jvm_event(&jvm_queue.pop_front().unwrap());
                        }
                        _ => break,
                    }
                }
                if waiting_for_watermark {
                    break;
                }

                let has_newer_candidate = bpf_queue.get(1).is_some_and(|next| {
                    jvm_queue.front().is_some_and(|jvm_event| {
                        next.end_monotonic_ns <= jvm_event.monotonic_timestamp_ns
                    })
                });
                if bpf_event.signal_result != 0 || has_newer_candidate {
                    ret.push((bpf_queue.pop_front().unwrap(), None));
                } else if let Some(jvm_event) =
                    Self::find_matching_jvm_event(bpf_event.end_monotonic_ns, jvm_queue)
                {
                    ret.push((bpf_queue.pop_front().unwrap(), Some(jvm_event)));
                } else if !jvm_queue.is_empty()
                    || now_monotonic_ns.saturating_sub(bpf_event.end_monotonic_ns)
                        >= EVENT_MATCH_GIVEUP_TIME.as_nanos() as u64
                {
                    ret.push((bpf_queue.pop_front().unwrap(), None));
                } else {
                    break;
                }
            }
            if jvm_queue.is_empty() {
                self.jvm_events.remove(&tid);
            }
            if bpf_queue.is_empty() {
                self.bpf_events.remove(&tid);
            }
        }
        debug!(
            "Swept {} events at monotonic time {}",
            ret.len(),
            now_monotonic_ns
        );
        ret
    }

    fn sweep_remaining(&mut self) -> Vec<(BpfEvent, Option<JvmEvent>)> {
        let mut result = self.sweep(u64::MAX);
        let mut tids = self.bpf_events.keys().copied().collect::<Vec<_>>();
        tids.sort_unstable();
        for tid in tids {
            let bpf_queue = self.bpf_events.get_mut(&tid).expect("bpf queue present");
            let jvm_queue = self.jvm_events.entry(tid).or_default();
            while let Some(bpf_event) = bpf_queue.pop_front() {
                while jvm_queue
                    .front()
                    .is_some_and(|event| event.monotonic_timestamp_ns < bpf_event.end_monotonic_ns)
                {
                    Self::trash_jvm_event(&jvm_queue.pop_front().unwrap());
                }
                let jvm_event =
                    Self::find_matching_jvm_event(bpf_event.end_monotonic_ns, jvm_queue);
                result.push((bpf_event, jvm_event));
            }
        }
        self.bpf_events.clear();
        self.jvm_events.clear();
        result
    }

    fn find_matching_jvm_event(
        monotonic_timestamp_ns: u64,
        jvm_queue: &mut VecDeque<JvmEvent>,
    ) -> Option<JvmEvent> {
        if let Some(jvm_event) = jvm_queue.front() {
            debug!(
                "Finding match, ebpf={}, jvm={}",
                monotonic_timestamp_ns, jvm_event.monotonic_timestamp_ns
            );
            let delay = jvm_event
                .monotonic_timestamp_ns
                .saturating_sub(monotonic_timestamp_ns);
            if jvm_event.monotonic_timestamp_ns >= monotonic_timestamp_ns
                && delay < EVENT_MATCH_TIME_THRESHOLD.as_nanos() as u64
            {
                return Some(jvm_queue.pop_front().unwrap());
            }
        }
        None
    }

    fn trash_jvm_event(event: &JvmEvent) {
        let mut out = format!(
            "DISCARDED AP EVENT tid={}, timestamp={}\n",
            event.tid, event.timestamp
        );
        for (i, frame) in event.frames.iter().enumerate() {
            out.push_str(&format!(
                "{}: [0x{:x}] {}",
                i, frame.method_id, frame.symbol
            ));
            if i > 0 {
                out.push('\n');
            }
        }
        info!("{}", out);
    }
}

fn monotonic_time_ns() -> u64 {
    Duration::from(
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
            .expect("clock_gettime(MONOTONIC)"),
    )
    .as_nanos() as u64
}

fn namespace_tid(host_tgid: u32, host_tid: u32) -> Result<u32> {
    let status = fs::read_to_string(format!("/proc/{host_tgid}/task/{host_tid}/status"))?;
    parse_innermost_namespace_pid(&status)
        .ok_or_else(|| anyhow!("NSpid is missing from task status"))
}

fn parse_innermost_namespace_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

#[cfg(test)]
mod event_stream_tests {
    use super::*;

    fn bpf_event(tid: u32, timestamp: u64) -> BpfEvent {
        BpfEvent {
            timestamp,
            pid: 1,
            host_tid: tid,
            tid: Some(tid),
            comm: format!("thread-{tid}"),
            duration: Duration::from_millis(1),
            start_monotonic_ns: 0,
            end_monotonic_ns: 1_000_000,
            signal_result: 0,
            stacktrace: Vec::new(),
        }
    }

    #[test]
    fn never_reassigns_a_jvm_event_to_another_thread() {
        let old_timestamp = time_now() - EVENT_MATCH_GIVEUP_TIME.as_millis() as u64 - 1_000;
        let mut stream = EventStream {
            bpf_events: HashMap::from([
                (1, VecDeque::from([bpf_event(1, old_timestamp)])),
                (2, VecDeque::from([bpf_event(2, old_timestamp + 80)])),
            ]),
            unmatched_bpf_events: VecDeque::new(),
            event_count: 0,
            jvm_events: HashMap::from([(
                1,
                VecDeque::from([JvmEvent {
                    timestamp: old_timestamp + 90,
                    monotonic_timestamp_ns: 1_000_100,
                    tid: 1,
                    thread_name: "thread-1".to_string(),
                    frames: Vec::new(),
                }]),
            )]),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        let result = stream.sweep(u64::MAX);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0.tid, Some(1));
        assert_eq!(result[0].1.as_ref().map(|event| event.tid), Some(1));
        assert_eq!(result[1].0.tid, Some(2));
        assert!(result[1].1.is_none());
    }

    #[test]
    fn parses_the_innermost_pid_namespace_identifier() {
        assert_eq!(
            parse_innermost_namespace_pid("Name:\tjava\nNSpid:\t81234\t27\t3\n"),
            Some(3)
        );
    }

    #[test]
    fn matches_using_monotonic_time_even_when_wall_timestamps_differ() {
        let mut bpf = bpf_event(1, 10_000);
        bpf.end_monotonic_ns = 5_000_000;
        let mut queue = VecDeque::from([JvmEvent {
            timestamp: 1,
            monotonic_timestamp_ns: 5_000_100,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        }]);

        let matched = EventStream::find_matching_jvm_event(bpf.end_monotonic_ns, &mut queue);
        assert!(matched.is_some());
        assert!(queue.is_empty());
    }

    #[test]
    fn assigns_a_coalesced_sample_to_the_latest_preceding_interval() {
        let now = monotonic_time_ns();
        let mut first = bpf_event(1, 1);
        first.end_monotonic_ns = now - 2_000;
        let mut second = bpf_event(1, 2);
        second.end_monotonic_ns = now - 1_000;
        let sample = JvmEvent {
            timestamp: 3,
            monotonic_timestamp_ns: now,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let mut stream = EventStream {
            bpf_events: HashMap::from([(1, VecDeque::from([first, second]))]),
            unmatched_bpf_events: VecDeque::new(),
            event_count: 0,
            jvm_events: HashMap::from([(1, VecDeque::from([sample]))]),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        let result = stream.sweep(u64::MAX);
        assert_eq!(result.len(), 2);
        assert!(result[0].1.is_none());
        assert!(result[1].1.is_some());
    }

    #[test]
    fn waits_for_perf_watermark_before_correlating_a_sample() {
        let sample_time = monotonic_time_ns();
        let mut first = bpf_event(1, 1);
        first.end_monotonic_ns = sample_time - 2_000;
        let sample = JvmEvent {
            timestamp: 3,
            monotonic_timestamp_ns: sample_time,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let mut stream = EventStream {
            bpf_events: HashMap::from([(1, VecDeque::from([first]))]),
            unmatched_bpf_events: VecDeque::new(),
            event_count: 0,
            jvm_events: HashMap::from([(1, VecDeque::from([sample]))]),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        assert!(stream.sweep(sample_time - 1).is_empty());

        let mut second = bpf_event(1, 2);
        second.end_monotonic_ns = sample_time - 1_000;
        stream.bpf_events.get_mut(&1).unwrap().push_back(second);
        let result = stream.sweep(sample_time);
        assert_eq!(result.len(), 2);
        assert!(result[0].1.is_none());
        assert!(result[1].1.is_some());
    }

    #[test]
    fn orders_migrated_thread_events_arriving_from_different_cpu_readers() {
        let mut later = bpf_event(1, 2);
        later.end_monotonic_ns = 1_050;
        let mut earlier = bpf_event(1, 1);
        earlier.end_monotonic_ns = 1_000;
        let first_sample = JvmEvent {
            timestamp: 1,
            monotonic_timestamp_ns: 1_010,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let second_sample = JvmEvent {
            timestamp: 2,
            monotonic_timestamp_ns: 1_060,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let mut stream = EventStream {
            bpf_events: HashMap::from([(1, VecDeque::from([later]))]),
            unmatched_bpf_events: VecDeque::new(),
            event_count: 0,
            jvm_events: HashMap::from([(1, VecDeque::from([first_sample, second_sample]))]),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        assert!(stream.sweep(900).is_empty());
        assert_eq!(stream.jvm_events.get(&1).unwrap().len(), 2);
        stream.enqueue_bpf_event(1, earlier);

        let result = stream.sweep(1_060);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0.end_monotonic_ns, 1_000);
        assert_eq!(result[0].1.as_ref().unwrap().monotonic_timestamp_ns, 1_010);
        assert_eq!(result[1].0.end_monotonic_ns, 1_050);
        assert_eq!(result[1].1.as_ref().unwrap().monotonic_timestamp_ns, 1_060);
    }

    #[test]
    fn rechecks_watermark_after_discarding_a_stale_jvm_sample() {
        let base = monotonic_time_ns();
        let mut first = bpf_event(1, 1);
        first.end_monotonic_ns = base + 1_000;
        let stale_sample = JvmEvent {
            timestamp: 1,
            monotonic_timestamp_ns: base + 900,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let second_sample = JvmEvent {
            timestamp: 2,
            monotonic_timestamp_ns: base + 1_100,
            tid: 1,
            thread_name: "thread-1".to_string(),
            frames: Vec::new(),
        };
        let mut stream = EventStream {
            bpf_events: HashMap::from([(1, VecDeque::from([first]))]),
            unmatched_bpf_events: VecDeque::new(),
            event_count: 0,
            jvm_events: HashMap::from([(1, VecDeque::from([stale_sample, second_sample]))]),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        // The stale sample may be discarded, but the next sample is beyond
        // the proven perf progress and must remain unconsumed.
        assert!(stream.sweep(base + 950).is_empty());
        assert_eq!(stream.jvm_events.get(&1).unwrap().len(), 1);
        assert_eq!(stream.bpf_events.get(&1).unwrap().len(), 1);

        let mut second = bpf_event(1, 2);
        second.end_monotonic_ns = base + 1_050;
        stream.enqueue_bpf_event(1, second);

        let result = stream.sweep(base + 1_100);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0.end_monotonic_ns, base + 1_000);
        assert!(result[0].1.is_none());
        assert_eq!(result[1].0.end_monotonic_ns, base + 1_050);
        assert_eq!(
            result[1].1.as_ref().unwrap().monotonic_timestamp_ns,
            base + 1_100
        );
    }

    #[test]
    fn emits_an_untranslated_thread_without_attempting_a_match() {
        let mut event = bpf_event(7, 1);
        event.tid = None;
        let mut stream = EventStream {
            bpf_events: HashMap::new(),
            unmatched_bpf_events: VecDeque::from([event]),
            event_count: 0,
            jvm_events: HashMap::new(),
            ksyms: BTreeMap::new(),
            symbol_resolver: Resolver::new(),
            native_symbolization_unavailable: HashSet::new(),
        };

        let result = stream.sweep(u64::MAX);
        assert_eq!(result.len(), 1);
        assert!(result[0].0.tid.is_none());
        assert!(result[0].1.is_none());
    }
}

pub fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

pub fn time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix epoch")
        .as_millis() as u64
}

pub fn format_time(timestamp: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp as i64)
        .single()
        .expect("local time")
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[cfg(test)]
mod integration_tests {
    use std::{
        process::{Child, Command},
        time::Duration,
    };

    use jbm_common::Config;

    use crate::{async_profiler::AsyncProfilerStackTraceProvider, BpfEvent, Jbm, JvmEvent};

    #[tokio::test]
    async fn test_detect_blocking() -> Result<(), anyhow::Error> {
        let java_proc = start_test_java();
        std::thread::sleep(Duration::from_secs(1));

        let config = Config {
            target_tgid: java_proc.id(),
            min_block_us: Duration::from_secs(1).as_micros() as u64,
            max_block_us: Duration::from_secs(10).as_micros() as u64,
            sample_interval_ns: Duration::from_millis(10).as_nanos() as u64,
            stack_storage_size: 10240,
        };

        let async_profiler = AsyncProfilerStackTraceProvider::start(
            config.target_tgid,
            "../async-profiler/build/bin/asprof".to_string(),
            None,
            None,
        )
        .await?;

        let mut jbm = Jbm::new(config, async_profiler)?;
        std::thread::sleep(Duration::from_secs(20));

        let events = jbm.process().await?;

        let (bpf_event, jvm_event) = find_event(&events, "LOCKER").unwrap();

        assert_ne!(Some(java_proc.id()), bpf_event.tid);
        assert_eq!(java_proc.id(), bpf_event.pid);
        assert_eq!("LOCKER", bpf_event.comm);
        assert!(
            bpf_event.duration.as_micros() as u64 >= config.min_block_us
                && bpf_event.duration.as_micros() as u64 <= config.max_block_us
        );
        assert!(bpf_event
            .stacktrace
            .iter()
            .find(|(_, sym)| sym.contains("pthread_cond_wait"))
            .is_some());

        let jvm_event = jvm_event.unwrap();
        assert_eq!(bpf_event.tid, Some(jvm_event.tid));
        assert!(jvm_event
            .frames
            .iter()
            .find(|f| f.symbol.contains("TestJavaApp.locker"))
            .is_some());

        Ok(())
    }

    fn start_test_java() -> Child {
        Command::new("java")
            .args(&["-cp", "./test", "TestJavaApp"])
            .spawn()
            .expect("failed to execute java")
    }

    fn find_event<'a>(
        events: &'a [(BpfEvent, Option<JvmEvent>)],
        comm: &str,
    ) -> Option<(&'a BpfEvent, Option<&'a JvmEvent>)> {
        for (bpf_event, jvm_event) in events {
            if bpf_event.comm == comm {
                return Some((bpf_event, jvm_event.as_ref()));
            }
        }
        None
    }
}
