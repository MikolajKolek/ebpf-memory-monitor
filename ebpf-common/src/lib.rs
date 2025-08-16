#![no_std]

use core::cmp::max;
use aya_ebpf::bindings::BPF_ANY;
use aya_ebpf::cty::c_ulong;
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::maps::{Array, HashMap};
use ebpf_memory_monitor_common::RLIMIT_AS_NOT_HIT;
use crate::vmlinux::{mm_struct, signal_struct, task_struct};

#[allow(warnings)]
pub mod vmlinux;

pub fn try_on_do_exit(
    tgid: u32,
    vm_peak: &HashMap<u32, u64>,
    constants: &Array<u64>
) -> Result<u32, i64> {
    if let Some(_) = unsafe { vm_peak.get(&tgid) } {
        let page_shift = *constants.get(0).ok_or(1i64)?;

        let mm: *mut mm_struct = unsafe {
            bpf_probe_read_kernel(&(*(bpf_get_current_task() as *mut task_struct)).mm)
        }?;
        let total_vm = unsafe {
            bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.total_vm as *const u64)
        }?;
        let hiwater_vm = unsafe {
            bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.hiwater_vm as *const u64)
        }?;

        // We need to do a max(total_vm, hiwater_vm) because the hiwater_vm is
        // only updated when total_vm gets lower.
        vm_peak.insert(&tgid, &(max(total_vm, hiwater_vm) << page_shift), BPF_ANY as u64)?;

        Ok(0)
    } else {
        Ok(0)
    }
}

pub fn try_on_may_expand_vm(
    mm: *const mm_struct,
    npages: c_ulong,
    tgid: u32,
    attempted_vm_peak: &HashMap<u32, i64>,
    constants: &Array<u64>
) -> Result<u32, i64> {
    if let Some(value) = unsafe { attempted_vm_peak.get(&tgid) } && *value == RLIMIT_AS_NOT_HIT {
        let rlimit_as: usize = (*constants.get(0).ok_or(1i64)?).try_into().map_err(|_| 1)?;
        let page_shift: u64 = *constants.get(1).ok_or(1i64)?;

        let total_vm = unsafe {
            bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.total_vm as *const u64)
        }?;

        let signal: *mut signal_struct = unsafe {
            bpf_probe_read_kernel(&(*(bpf_get_current_task() as *mut task_struct)).signal)
        }?;
        let current_rlimit_as: u64 = unsafe {
            bpf_probe_read_kernel(&(*signal).rlim.get(rlimit_as).ok_or(1i64)?.rlim_cur)
        }?;

        if total_vm + npages > current_rlimit_as >> page_shift {
            let to_insert: i64 = ((total_vm + npages) << page_shift).try_into().map_err(|_| 1)?;
            attempted_vm_peak.insert(&tgid, &to_insert, BPF_ANY as u64)?;
        }

        Ok(0)
    } else {
        Ok(0)
    }
}
