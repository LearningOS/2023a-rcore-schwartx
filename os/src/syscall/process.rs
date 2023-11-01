//! Process management syscalls
use core::{mem::size_of, ptr::copy_nonoverlapping};

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::translated_byte_buffer,
    syscall::{SYSCALL_EXIT, SYSCALL_GET_TIME, SYSCALL_TASK_INFO, SYSCALL_YIELD},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, incr_syscalls,
        suspend_current_and_run_next, TaskStatus,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    incr_syscalls(SYSCALL_EXIT);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    incr_syscalls(SYSCALL_YIELD);
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?

pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    incr_syscalls(SYSCALL_GET_TIME);

    if _ts.is_null() {
        return -1;
    }

    // 获取当前时间
    let us = get_time_us();
    let time_val_part = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    // 使用 translated_byte_buffer 函数处理跨页问题
    let time_val_buffers =
        translated_byte_buffer(current_user_token(), _ts as *const u8, size_of::<TimeVal>());
    if time_val_buffers.is_empty() {
        return -1;
    }

    // 逐部分复制数据
    let mut offset = 0;
    for buffer in time_val_buffers {
        unsafe {
            copy_nonoverlapping(
                (&time_val_part as *const TimeVal as *const u8).add(offset),
                buffer.as_mut_ptr(),
                buffer.len(),
            );
        }
        offset += buffer.len();
    }

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    incr_syscalls(SYSCALL_TASK_INFO);
    -1
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    -1
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
