#![no_std]
#![no_main]

#[allow(warnings)]
mod vmlinux;

use aya_ebpf::bindings::{BPF_ANY, BPF_F_NO_PREALLOC, BPF_F_RDONLY_PROG, BPF_F_WRONLY};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::EbpfContext;
use aya_ebpf::cty::{c_ulong};
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::maps::{Array, HashMap};
use ebpf_memory_monitor_common::{RLIMIT_AS_NOT_HIT};
use crate::vmlinux::{mm_struct, signal_struct, task_struct};

#[kprobe]
pub fn check_rlimit(ctx: ProbeContext) -> u32 {
    try_check_rlimit(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

#[map]
// Constants passed from userspace to the ebpf program before it is loaded.
// CONSTANTS[0] = RLIMIT_AS
// CONSTANTS[1] = PAGE_SHIFT
static CONSTANTS: Array<u64> = Array::with_max_entries(2, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
// The value of max_entries is temporary, and it's set when the ebpf program is loaded.
static ATTEMPTED_VM_PEAK: HashMap<u32, i64> =
    HashMap::<u32, i64>::with_max_entries(0, BPF_F_NO_PREALLOC);

fn try_check_rlimit(ctx: ProbeContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if let Some(value) = unsafe { ATTEMPTED_VM_PEAK.get(&tgid) } && *value == RLIMIT_AS_NOT_HIT {
        let rlimit_as: usize = (*CONSTANTS.get(0).ok_or(1i64)?).try_into().map_err(|_| 1)?;
        let page_shift: u64 = *CONSTANTS.get(1).ok_or(1i64)?;

        let mm: *mut mm_struct = ctx.arg(0).ok_or(1i64)?;
        let total_vm = unsafe {
            bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.total_vm as *const u64)
        }?;

        let signal: *mut signal_struct = unsafe {
            bpf_probe_read_kernel(&(*(bpf_get_current_task() as *mut task_struct)).signal)
        }?;
        let current_rlimit_as: u64 = unsafe {
            bpf_probe_read_kernel(&(*signal).rlim.get(rlimit_as).ok_or(1i64)?.rlim_cur)
        }?;

        let npages: c_ulong = ctx.arg(2).unwrap();

        if total_vm + npages > current_rlimit_as >> page_shift {
            let attempted_vm_peak: i64 = ((total_vm + npages) << page_shift).try_into().map_err(|_| 1)?;
            ATTEMPTED_VM_PEAK.insert(&tgid, &attempted_vm_peak, BPF_ANY as u64)?;
        }

        Ok(0)
    } else {
        Ok(0)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
