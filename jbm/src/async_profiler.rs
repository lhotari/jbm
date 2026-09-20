use crate::{pid_alive, JvmEvent, JvmStackTraceProvider};
use anyhow::anyhow;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::process::Command;
use tempfile::{Builder, NamedTempFile};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

const MINIMUM_SIGNAL_INTERVAL: &str = "1ns";

pub struct AsyncProfilerStackTraceProvider {
    pid: u32,
    profiler_cmd_path: String,
    profiler_library_path: Option<String>,
    output_file: NamedTempFile,
    output: File,
    pending: Vec<u8>,
    active: bool,
}

impl AsyncProfilerStackTraceProvider {
    pub async fn start(
        pid: u32,
        profiler_cmd_path: String,
        profiler_library_path: Option<String>,
        stream_directory: Option<String>,
    ) -> Result<Self, anyhow::Error> {
        let mut builder = Builder::new();
        builder.prefix("jbm-ap-");
        let tmpfile = if let Some(directory) = stream_directory {
            builder.tempfile_in(directory)?
        } else {
            builder.tempfile()?
        };
        let file = File::open(tmpfile.path()).await?;
        unsafe {
            let path =
                CString::new(tmpfile.path().to_string_lossy().to_string()).expect("valid C-string");
            libc::chmod(
                path.as_ptr(),
                libc::S_IRUSR
                    | libc::S_IWUSR
                    | libc::S_IRGRP
                    | libc::S_IWGRP
                    | libc::S_IROTH
                    | libc::S_IWOTH,
            )
        };
        let this = Self {
            pid,
            profiler_cmd_path,
            profiler_library_path,
            output_file: tmpfile,
            output: file,
            pending: Vec::new(),
            active: true,
        };

        this.exec_profiler_cmd("start")?;
        Ok(this)
    }

    fn exec_profiler_cmd(&self, subcommand: &str) -> Result<(), anyhow::Error> {
        let mut args = vec![
            "-e".to_string(),
            "signal".to_string(),
            "-o".to_string(),
            "jsonl".to_string(),
            "-f".to_string(),
            self.output_file.path().to_string_lossy().to_string(),
            "-i".to_string(),
            MINIMUM_SIGNAL_INTERVAL.to_string(),
        ];
        if let Some(library_path) = &self.profiler_library_path {
            args.push("--libpath".to_string());
            args.push(library_path.clone());
        }
        args.push(subcommand.to_string());
        args.push(self.pid.to_string());
        info!("Executing async-profiler: {:?}", args);
        let status = Command::new(&self.profiler_cmd_path)
            .args(args)
            .spawn()?
            .wait()?;
        let code = status.code().unwrap_or(-1);
        if code != 0 {
            return Err(anyhow!("async-profiler command exit with error: {}", code));
        }
        Ok(())
    }
}

#[async_trait]
impl JvmStackTraceProvider for AsyncProfilerStackTraceProvider {
    async fn fill_queue(
        &mut self,
        queues: &mut HashMap<u32, VecDeque<JvmEvent>>,
    ) -> Result<(), anyhow::Error> {
        self.output.read_to_end(&mut self.pending).await?;
        let mut count = 0;
        for line in drain_complete_lines(&mut self.pending) {
            debug!(
                "Read line from AsyncProfiler stream: {}",
                String::from_utf8_lossy(&line)
            );
            match serde_json::from_slice::<JvmEvent>(&line) {
                Ok(jvm_event) => {
                    count += 1;
                    queues
                        .entry(jvm_event.tid)
                        .or_insert_with(|| VecDeque::new())
                        .push_back(jvm_event);
                }
                Err(e) => {
                    warn!(
                        "Skipping malformed AsyncProfiler event {}: {}",
                        String::from_utf8_lossy(&line),
                        e
                    );
                }
            }
        }
        debug!("Filled up JVM event queue with {} events", count);

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), anyhow::Error> {
        if self.active {
            self.exec_profiler_cmd("stop")?;
            self.active = false;
        }
        Ok(())
    }
}

fn drain_complete_lines(pending: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let complete_length = pending
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap_or(0);
    let complete = pending.drain(..complete_length).collect::<Vec<_>>();
    complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_an_incomplete_json_line_until_newline_arrives() {
        let mut pending = br#"{"timestamp":1"#.to_vec();
        assert!(drain_complete_lines(&mut pending).is_empty());
        assert_eq!(pending, br#"{"timestamp":1"#);

        pending.extend_from_slice(b"}\nsecond\npartial");
        assert_eq!(
            drain_complete_lines(&mut pending),
            vec![br#"{"timestamp":1}"#.to_vec(), b"second".to_vec()]
        );
        assert_eq!(pending, b"partial");
    }
}

impl Drop for AsyncProfilerStackTraceProvider {
    fn drop(&mut self) {
        if self.active && pid_alive(self.pid) {
            if let Err(e) = self.exec_profiler_cmd("stop") {
                warn!(
                    "Failed to stop async-profiler on process {}: {}",
                    self.pid, e
                );
            }
        }
    }
}
