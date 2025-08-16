#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_F_NO_PREALLOC, BPF_F_RDONLY_PROG, BPF_F_WRONLY};
use aya_ebpf::EbpfContext;
use aya_ebpf::macros::{fentry, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::FEntryContext;
use ebpf_common::try_on_may_expand_vm;

#[map]
// Constants passed from userspace to the ebpf program before it is loaded.
// CONSTANTS[0] = RLIMIT_AS
// CONSTANTS[1] = PAGE_SHIFT
static CONSTANTS: Array<u64> =
    Array::with_max_entries(2, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
// The value of max_entries is temporary, and it's set when the ebpf program is loaded.
static ATTEMPTED_VM_PEAK: HashMap<u32, i64> =
    HashMap::<u32, i64>::with_max_entries(0, BPF_F_NO_PREALLOC);

#[fentry(function = "may_expand_vm")]
pub fn on_may_expand_vm(ctx: FEntryContext) -> u32 {
    try_on_may_expand_vm(
        unsafe { ctx.arg(0) },
        unsafe { ctx.arg(2) },
        ctx.tgid(),
        &ATTEMPTED_VM_PEAK,
        &CONSTANTS,
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
