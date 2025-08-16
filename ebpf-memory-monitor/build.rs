use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;
use aya_build::cargo_metadata::Package;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let rlimit_fentry: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "rlimit-fentry")
        .ok_or_else(|| anyhow!("rlimit-fentry package not found"))?
        .clone();
    let rlimit_kprobe: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "rlimit-kprobe")
        .ok_or_else(|| anyhow!("rlimit-kprobe package not found"))?
        .clone();
    let hiwater_fentry: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "hiwater-fentry")
        .ok_or_else(|| anyhow!("hiwater-fentry package not found"))?
        .clone();
    let hiwater_kprobe: Package = packages
        .iter()
        .find(|Package { name, .. }| name == "hiwater-kprobe")
        .ok_or_else(|| anyhow!("hiwater-kprobe package not found"))?
        .clone();

    aya_build::build_ebpf([rlimit_fentry, rlimit_kprobe, hiwater_fentry, hiwater_kprobe])
}
