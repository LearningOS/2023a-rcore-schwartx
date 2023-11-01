//! Process management syscalls
use core::{mem::size_of, ptr::copy_nonoverlapping};

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    mm::{translated_byte_buffer, MapPermission, VirtAddr},
    syscall::{SYSCALL_EXIT, SYSCALL_GET_TIME, SYSCALL_TASK_INFO, SYSCALL_YIELD},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, get_start_time,
        get_syscall_times, incr_syscalls, mmap, munmap, suspend_current_and_run_next, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
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

/// Copies the content of a provided reference to a potentially page-split memory location.
pub fn copy_to_user<T: Sized>(user_ptr: *mut T, data: &T, token: usize) -> Result<(), isize> {
    // Safety: Function is inherently unsafe as it manipulates raw pointers and relies on correct token.
    unsafe {
        let buffers = translated_byte_buffer(token, user_ptr as *const u8, size_of::<T>());
        if buffers.is_empty() {
            return Err(-1);
        }

        let mut offset = 0;
        for buffer in buffers {
            copy_nonoverlapping(
                (data as *const T as *const u8).add(offset),
                buffer.as_mut_ptr(),
                buffer.len(),
            );
            offset += buffer.len();
        }
    }

    Ok(())
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

    let us = get_time_us();
    let time_val_part = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    match copy_to_user(_ts, &time_val_part, current_user_token()) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    incr_syscalls(SYSCALL_TASK_INFO);
    let task_info_val = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: get_syscall_times(),
        time: get_time_ms() - get_start_time(),
    };

    match copy_to_user(_ti, &task_info_val, current_user_token()) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if len == 0 {
        return -1;
    }

    // 检查 port 是否有效
    if port & !0x7 != 0 || port & 0x7 == 0 {
        debug!("port is invalid");
        return -1;
    }

    // somethin wrong with `from_bits_truncate`
    let port = match port {
        1 => MapPermission::R,
        2 => MapPermission::W,
        3 => MapPermission::R | MapPermission::W,
        _ => MapPermission::empty(),
    } | MapPermission::U;

    // 计算结束地址，向上取整至页面边界
    let end = VirtAddr::from((start + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));
    let start = VirtAddr::from(start);

    if !start.aligned() {
        debug!("start is not align");
        return -1;
    }

    if !end.aligned() {
        debug!("end is not align");
        return -1;
    }

    mmap(start, end, port)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap ");

    if len == 0 || start % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
        // 如果长度为 0，或者 start 或 len 没有按页对齐，返回错误
        return -1;
    }

    let end = start + len;

    munmap(start.into(), end.into())
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
