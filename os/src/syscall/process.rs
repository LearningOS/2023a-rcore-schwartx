//! Process management syscalls
use core::{mem::size_of, ptr::copy_nonoverlapping};

use alloc::sync::Arc;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    loader::get_app_data_by_name,
    mm::{translated_byte_buffer, translated_refmut, translated_str, MapPermission, VirtAddr},
    syscall::{SYSCALL_EXIT, SYSCALL_GET_TIME, SYSCALL_TASK_INFO, SYSCALL_YIELD},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus,
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
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    current_task().unwrap().incr_syscalls(SYSCALL_EXIT);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    current_task().unwrap().incr_syscalls(SYSCALL_YIELD);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_get_time NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    current_task().unwrap().incr_syscalls(SYSCALL_GET_TIME);

    if ts.is_null() {
        return -1;
    }

    let us = get_time_us();
    let time_val_part = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    match copy_to_user(ts, &time_val_part, current_user_token()) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!(
        "kernel:pid[{}] sys_task_info NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let task = current_task().unwrap();
    task.incr_syscalls(SYSCALL_TASK_INFO);
    let (syscall_times, status, start_time) = task.get_task_info();
    let task_info_val = TaskInfo {
        status,
        syscall_times,
        time: get_time_ms() - start_time,
    };

    match copy_to_user(ti, &task_info_val, current_user_token()) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

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

    current_task().unwrap().mmap(start, end, port)
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    if len == 0 || start % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
        // 如果长度为 0，或者 start 或 len 没有按页对齐，返回错误
        return -1;
    }

    let end = start + len;

    current_task().unwrap().munmap(start.into(), end.into())
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}
