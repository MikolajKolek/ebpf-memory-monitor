use aya::maps::{Array, HashMap, MapData};
use aya::programs::KProbe;
use aya::{Ebpf, EbpfLoader};
use libc::{c_long, RLIMIT_AS, RLIM_INFINITY};
use nix::sys::resource::{setrlimit, Resource};
use nix::unistd::{sysconf, SysconfVar};
use std::sync::{Mutex, OnceLock};

pub(crate) struct SharedState {
    // We hold these ebpf objects even if they are never accessed,
    // as when they go out of scope, the programs will be unloaded.
    #[allow(dead_code)]
    pub(crate) rlimit_ebpf: Ebpf,
    #[allow(dead_code)]
    pub(crate) peak_ebpf: Ebpf,
    // TODO: Remove the Mutex if HashMap insert / remove ever become &self instead of &mut self.
    pub(crate) attempted_vm_peak: Mutex<HashMap<MapData, u32, i64>>,
    pub(crate) vm_peak: Mutex<HashMap<MapData, u32, u64>>,
}

pub(crate) static SHARED_STATE: OnceLock<SharedState> = OnceLock::new();

/// Requires the:
/// - `CAP_SYS_RESOURCE`
/// - `CAP_SYS_BPF`
/// - `CAP_PERFMON`
/// capabilities to be set.
pub fn initialize_with_max_listeners(max_listeners: u32) -> anyhow::Result<()> {
    SHARED_STATE.get_or_try_init(|| {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg-based accounting, see https://lwn.net/Articles/837122/
        setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY)?;

        let (rlimit_ebpf, attempted_vm_peak) = initialize_rlimit_ebpf(max_listeners)?;
        let (peak_ebpf, vm_peak) = initialize_peak_ebpf(max_listeners)?;

        Ok::<SharedState, anyhow::Error>(SharedState {
            rlimit_ebpf,
            peak_ebpf,
            attempted_vm_peak: Mutex::new(attempted_vm_peak),
            vm_peak: Mutex::new(vm_peak),
        })
    })?;

    Ok(())
}

fn initialize_rlimit_ebpf(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, i64>)> {
    let mut ebpf: Ebpf = EbpfLoader::new()
        .set_max_entries("ATTEMPTED_VM_PEAK", max_listeners)
        .load(
            aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/rlimit-monitor"
            )))?;

    let mut constants: Array<&mut MapData, u64> = Array::try_from(ebpf.map_mut("CONSTANTS").unwrap())?;
    constants.set(0, &(RLIMIT_AS.try_into().unwrap()), 0)?;
    let page_size: c_long = sysconf(SysconfVar::PAGE_SIZE)?.expect("page size is invalid");
    let page_size: u64 = page_size.ilog2().try_into()?;
    constants.set(1, &page_size, 0)?;

    let program: &mut KProbe = ebpf.program_mut("check_rlimit").unwrap().try_into()?;
    program.load()?;
    program.attach("may_expand_vm", 0)?;

    let attempted_vm_peak = HashMap::try_from(ebpf.take_map("ATTEMPTED_VM_PEAK").unwrap())?;
    Ok((
        ebpf,
        attempted_vm_peak,
    ))
}

fn initialize_peak_ebpf(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, u64>)> {
    let mut ebpf: Ebpf = EbpfLoader::new()
        .set_max_entries("VM_PEAK", max_listeners)
        .load(
            aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/peak-monitor"
            )))?;

    let mut constants: Array<&mut MapData, u64> = Array::try_from(ebpf.map_mut("CONSTANTS").unwrap())?;
    let page_size: c_long = sysconf(SysconfVar::PAGE_SIZE)?.expect("page size is invalid");
    let page_size: u64 = page_size.ilog2().try_into()?;
    constants.set(0, &page_size, 0)?;

    let program: &mut KProbe = ebpf.program_mut("check_hiwater_vm").unwrap().try_into()?;
    program.load()?;
    program.attach("do_exit", 0)?;

    let vm_peak = HashMap::try_from(ebpf.take_map("VM_PEAK").unwrap())?;
    Ok((
        ebpf,
        vm_peak,
    ))
}
