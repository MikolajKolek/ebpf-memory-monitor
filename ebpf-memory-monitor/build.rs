use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;
use aya_build::cargo_metadata::Package;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let rlimit_package: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "rlimit-monitor-ebpf")
        .ok_or_else(|| anyhow!("rlimit-monitor-ebpf package not found"))?
        .clone();
    let peak_package: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "peak-monitor-ebpf")
        .ok_or_else(|| anyhow!("peak-monitor-ebpf package not found"))?
        .clone();

    aya_build::build_ebpf([rlimit_package, peak_package])
}
