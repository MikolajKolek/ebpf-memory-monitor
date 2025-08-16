use aya::maps::{Array, HashMap, MapData};
use aya::programs::{FEntry, KProbe};
use aya::{Btf, Ebpf, EbpfLoader};
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
    pub(crate) hiwater_ebpf: Ebpf,
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

        let (rlimit_ebpf, attempted_vm_peak) =
            initialize_rlimit_fentry(max_listeners).unwrap_or(
                initialize_rlimit_kprobe(max_listeners)?
            );
        let (hiwater_ebpf, vm_peak) =
            initialize_hiwater_fentry(max_listeners).unwrap_or(
                initialize_hiwater_kprobe(max_listeners)?
            );

        Ok::<SharedState, anyhow::Error>(SharedState {
            rlimit_ebpf,
            hiwater_ebpf,
            attempted_vm_peak: Mutex::new(attempted_vm_peak),
            vm_peak: Mutex::new(vm_peak),
        })
    })?;

    Ok(())
}


fn initialize_rlimit_kprobe(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, i64>)> {
    Ok(initialize_rlimit_program(
        max_listeners,
        aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/rlimit-kprobe-bin"
        )),
        |ebpf| {
            let program: &mut KProbe =
                ebpf.program_mut("on_may_expand_vm").unwrap().try_into()?;
            program.load()?;
            program.attach("may_expand_vm", 0)?;
            Ok(())
        }
    )?)
}

fn initialize_rlimit_fentry(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, i64>)> {
    Ok(initialize_rlimit_program(
        max_listeners,
        aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/rlimit-fentry-bin"
        )),
        |ebpf| {
            let program: &mut FEntry =
                ebpf.program_mut("on_may_expand_vm").unwrap().try_into()?;
            program.load("may_expand_vm", &Btf::from_sys_fs()?)?;
            program.attach()?;
            Ok(())
        }
    )?)
}

fn initialize_rlimit_program<F>(max_listeners: u32, program_data: &[u8], program_loader: F)
    -> anyhow::Result<(Ebpf, HashMap<MapData, u32, i64>)>
where
    F: Fn(&mut Ebpf) -> anyhow::Result<()>,
{
    let mut ebpf: Ebpf = EbpfLoader::new()
        .set_max_entries("ATTEMPTED_VM_PEAK", max_listeners)
        .load(program_data)?;

    let mut constants: Array<&mut MapData, u64> =
        Array::try_from(ebpf.map_mut("CONSTANTS").unwrap())?;
    constants.set(0, &(RLIMIT_AS.try_into().unwrap()), 0)?;
    constants.set(1, &get_page_shift()?, 0)?;

    program_loader(&mut ebpf)?;

    let attempted_vm_peak = HashMap::try_from(ebpf.take_map("ATTEMPTED_VM_PEAK").unwrap())?;
    Ok((
        ebpf,
        attempted_vm_peak,
    ))
}


fn initialize_hiwater_kprobe(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, u64>)> {
    Ok(initialize_hiwater_program(
        max_listeners,
        aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/hiwater-kprobe-bin"
        )),
        |ebpf| {
            let program: &mut KProbe = ebpf.program_mut("on_do_exit").unwrap().try_into()?;
            program.load()?;
            program.attach("do_exit", 0)?;
            Ok(())
        }
    )?)
}

fn initialize_hiwater_fentry(max_listeners: u32) -> anyhow::Result<(Ebpf, HashMap<MapData, u32, u64>)> {
    Ok(initialize_hiwater_program(
        max_listeners,
        aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/hiwater-fentry-bin"
        )),
        |ebpf| {
            let program: &mut FEntry =
                ebpf.program_mut("on_do_exit").unwrap().try_into()?;
            program.load("do_exit", &Btf::from_sys_fs()?)?;
            program.attach()?;
            Ok(())
        }
    )?)
}

fn initialize_hiwater_program<F>(max_listeners: u32, program_data: &[u8], program_loader: F)
    -> anyhow::Result<(Ebpf, HashMap<MapData, u32, u64>)>
where
    F: Fn(&mut Ebpf) -> anyhow::Result<()>,
{
    let mut ebpf: Ebpf = EbpfLoader::new()
        .set_max_entries("VM_PEAK", max_listeners)
        .load(program_data)?;

    let mut constants: Array<&mut MapData, u64> =
        Array::try_from(ebpf.map_mut("CONSTANTS").unwrap())?;
    constants.set(0, &get_page_shift()?, 0)?;

    program_loader(&mut ebpf)?;

    let vm_peak = HashMap::try_from(ebpf.take_map("VM_PEAK").unwrap())?;
    Ok((
        ebpf,
        vm_peak,
    ))
}

fn get_page_shift() -> anyhow::Result<u64> {
    let page_size: c_long = sysconf(SysconfVar::PAGE_SIZE)?.expect("page size is invalid");
    Ok(page_size.ilog2().try_into()?)
}
