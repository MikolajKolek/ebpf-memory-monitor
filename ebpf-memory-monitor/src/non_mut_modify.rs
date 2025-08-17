/// The code in this module is based on the source code of `aya`, version 0.13.1,
/// available at https://github.com/aya-rs/aya under the terms of the MIT license.

use aya::maps::{HashMap, IterableMap, MapData, MapError};
use aya::sys::SyscallError;
use aya::Pod;
use aya_obj::generated::{bpf_attr, bpf_cmd};
use libc::SYS_bpf;
use std::borrow::{Borrow, BorrowMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::{io, mem};

pub(crate) trait NonMutModify<T: BorrowMut<MapData>, K: Pod, V: Pod> {
    fn non_mut_insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError>;

    fn non_mut_remove(&self, key: &K) -> Result<(), MapError>;
}

impl<T: BorrowMut<MapData>, K: Pod, V: Pod> NonMutModify<T, K, V> for HashMap<T, K, V> {
    /// Inserts a key-value pair into the map.
    fn non_mut_insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        insert(self.map(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    fn non_mut_remove(&self, key: &K) -> Result<(), MapError> {
        remove(self.map(), key)
    }
}

fn insert<K: Pod, V: Pod>(
    map: &MapData,
    key: &K,
    value: &V,
    flags: u64,
) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_update_elem(fd, Some(key), value, flags)
        .map(|_| ())
        .map_err(|io_error| {
            SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            }.into()
        })
}

fn remove<K: Pod>(map: &MapData, key: &K) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_delete_elem(fd, key)
        .map(|_| ())
        .map_err(|io_error| {
            SyscallError {
                call: "bpf_map_delete_elem",
                io_error,
            }.into()
        })
}

fn bpf_map_update_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: &V,
    flags: u64,
) -> io::Result<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

fn bpf_map_delete_elem<K: Pod>(fd: BorrowedFd<'_>, key: &K) -> io::Result<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as *const _ as u64;

    sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &mut attr)
}

fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    let ret = unsafe {
        libc::syscall(SYS_bpf, cmd, attr, size_of::<bpf_attr>())
    };

    // `libc::syscall` returns i32 on armv7.
    #[allow(clippy::useless_conversion)]
    match ret.into() {
        ret @ 0.. => Ok(ret),
        _ => Err(io::Error::last_os_error()),
    }
}
