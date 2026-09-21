#![no_std]

pub const STACK_STORAGE_SIZE: usize = 10240;
pub const TASK_COMM_LEN: usize = 16;

#[cfg_attr(feature = "user", derive(Debug, Clone, Copy))]
#[repr(C)]
pub struct Config {
    pub target_tgid: u32,
    pub min_block_us: u64,
    pub max_block_us: u64,
    /// Accept random u32 values below this threshold; 2^32 selects every event.
    pub sample_threshold: u64,
    pub stack_storage_size: u32,
}

#[cfg_attr(feature = "user", derive(Debug, Clone))]
#[repr(C)]
pub struct BlockEvent {
    pub pid: u32,
    pub tgid: u32,
    pub user_stack_id: i64,
    pub kernel_stack_id: i64,
    pub name: [u8; TASK_COMM_LEN],
    pub offtime: u64,
    pub t_start: u64,
    pub t_end: u64,
    pub signal_result: i64,
}

#[cfg_attr(feature = "user", derive(Debug, Clone, Copy, Default))]
#[repr(C)]
pub struct CollectionStats {
    pub eligible_intervals: u64,
    pub eligible_duration_us: u64,
    pub probability_rejections: u64,
    pub selected_intervals: u64,
    pub kernel_stack_failures: u64,
    pub user_stack_failures: u64,
    pub signal_failures: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CollectionStats {}
