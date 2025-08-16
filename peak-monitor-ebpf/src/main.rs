#![no_std]
#![no_main]

#[allow(warnings)]
mod vmlinux;

use crate::vmlinux::{mm_struct, task_struct};
use aya_ebpf::bindings::{BPF_ANY, BPF_F_NO_PREALLOC, BPF_F_RDONLY_PROG, BPF_F_WRONLY};
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;
use core::cmp::max;

#[kprobe]
pub fn check_hiwater_vm(ctx: ProbeContext) -> u32 {
    try_check_hiwater_vm(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

#[map]
// Constants passed from userspace to the ebpf program before it is loaded.
// CONSTANTS[0] = PAGE_SHIFT
static CONSTANTS: Array<u64> = Array::with_max_entries(1, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
// The value of max_entries is temporary, and it's set when the ebpf program is loaded.
static VM_PEAK: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(0, BPF_F_NO_PREALLOC);

fn try_check_hiwater_vm(ctx: ProbeContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if let Some(_) = unsafe { VM_PEAK.get(&tgid) } {
        let page_shift = *CONSTANTS.get(0).ok_or(1i64)?;

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
        VM_PEAK.insert(&tgid, &(max(total_vm, hiwater_vm) << page_shift), BPF_ANY as u64)?;

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
