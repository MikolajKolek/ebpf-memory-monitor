#![feature(once_cell_try)]

pub mod init;

use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use ebpf_memory_monitor_common::RLIMIT_AS_NOT_HIT;
use std::io;
use std::io::BufRead;
use aya::maps::{HashMap, MapData};
use aya::Pod;
use crate::init::{initialize_with_max_listeners, SHARED_STATE};

#[test]
fn test_not_main() {
    initialize_with_max_listeners(1024).unwrap();

    println!("Waiting for PIDs to listen to...");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.expect("Failed to read line");

        fn parse_command(line: &str, command: &str) -> Option<u32> {
            if line.starts_with(command) {
                let pid = line.split_whitespace().nth(1)?;
                pid.parse::<u32>().ok()
            } else {
                None
            }
        }

        if line.starts_with("exit") {
            println!("Exiting...");
            return;
        }
        else if line.starts_with("debug") {
            if let Some(shared_state) = SHARED_STATE.get() {
                let vm_peak =
                    shared_state.vm_peak.lock().expect("failed to lock vm_peak");
                let attempted_vm_peak =
                    shared_state.attempted_vm_peak.lock().expect("failed to lock attempted_vm_peak");

                fn print_hash_map<A, B, C>(name: &str, map: &HashMap<A, B, C>)
                where
                    A: Borrow<MapData>,
                    B: Pod + Display,
                    C: Pod + Display
                {
                    println!(
                        "{}: {}",
                        name,
                        map.iter()
                            .map(|el| {
                                let el = el.unwrap();
                                format!("({}: {})", el.0, el.1)
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }

                print_hash_map("VM_PEAK", &vm_peak);
                print_hash_map("ATTEMPTED_VM_PEAK", &attempted_vm_peak);
            } else {
                panic!("ebpf-memory-monitor was not initialized");
            }
        }
        else if let Some(pid) = parse_command(&line, "start ") {
            start_monitoring_process(pid);
            println!("Started monitoring PID {}", pid);
        }
        else if let Some(pid) = parse_command(&line, "stop ") {
            stop_monitoring_process(pid);
            println!("Stopped monitoring PID {}", pid);
        }
        else if let Some(pid) = parse_command(&line, "status ") {
            println!("Process status: {:?}", get_process_status(pid));
        }
        else {
            println!("Invalid command. Please enter a valid command.");
        }
    }
}

/// This method should not be called unless `initialize_with_max_listeners` was successfully called before.
pub fn start_monitoring_process(pid: u32) {
    if let Some(shared_state) = SHARED_STATE.get() {
        let mut attempted_vm_peak = shared_state
            .attempted_vm_peak
            .lock().expect("failed to lock attempted_vm_peak");

        attempted_vm_peak.insert(pid, RLIMIT_AS_NOT_HIT, 0)
            .expect("insert to attempted_vm_peak failed");
        drop(attempted_vm_peak);

        let mut vm_peak = shared_state
            .vm_peak
            .lock().expect("failed to lock vm_peak");
        vm_peak.insert(pid, 0, 0)
            .expect("insert to vm_peak failed");
    } else {
        panic!("ebpf-memory-monitor was not initialized");
    }
}

#[derive(Debug)]
pub struct ProcessStatus {
    pub vm_peak_bytes: u64,
    pub attempted_vm_peak_bytes: Option<u64>,
}

pub fn get_process_status(pid: u32) -> Option<ProcessStatus> {
    if let Some(shared_state) = SHARED_STATE.get() {
        let attempted_vm_peak = shared_state
            .attempted_vm_peak
            .lock().expect("failed to lock attempted_vm_peak")
            .get(&pid, 0).ok()?;
        let vm_peak = shared_state
            .vm_peak
            .lock().expect("failed to lock vm_peak");

        Some(ProcessStatus {
            vm_peak_bytes: vm_peak.get(&pid, 0).ok()?,
            attempted_vm_peak_bytes: if attempted_vm_peak == RLIMIT_AS_NOT_HIT {
                None
            } else {
                Some(attempted_vm_peak.try_into().unwrap())
            },
        })
    } else {
        panic!("ebpf-memory-monitor was not initialized");
    }
}

pub fn stop_monitoring_process(pid: u32) {
    if let Some(shared_state) = SHARED_STATE.get() {
        let mut attempted_vm_peak = shared_state
            .attempted_vm_peak
            .lock().expect("failed to lock attempted_vm_peak");

        attempted_vm_peak.remove(&pid)
            .expect("remove from attempted_vm_peak failed");
        drop(attempted_vm_peak);

        let mut vm_peak = shared_state
            .vm_peak
            .lock().expect("failed to lock vm_peak");
        vm_peak.remove(&pid)
            .expect("remove from vm_peak failed");
    } else {
        panic!("ebpf-memory-monitor was not initialized");
    }
}
