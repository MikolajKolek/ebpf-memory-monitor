#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_F_NO_PREALLOC, BPF_F_RDONLY_PROG, BPF_F_WRONLY};
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;
use ebpf_common::try_on_do_exit;

#[map]
// Constants passed from userspace to the ebpf program before it is loaded.
// CONSTANTS[0] = PAGE_SHIFT
static CONSTANTS: Array<u64> =
    Array::with_max_entries(1, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
// The value of max_entries is temporary, and it's set when the ebpf program is loaded.
static VM_PEAK: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(0, BPF_F_NO_PREALLOC);

#[kprobe]
pub fn on_do_exit(ctx: ProbeContext) -> u32 {
    try_on_do_exit(
        ctx.tgid(),
        &VM_PEAK,
        &CONSTANTS
    ).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
