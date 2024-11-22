// src/anti_cheat/memory_scanner.rs
use std::process::{Command, Stdio};
use std::io::{self, BufRead};
use winapi::um::memoryapi::{VirtualQueryEx, ReadProcessMemory};
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::NULL;

const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

/// Struct to store information about a scanned region of memory.
struct MemoryRegion {
    base_address: usize,
    region_size: usize,
    protection: DWORD,
}

/// MemoryScanner handles scanning for suspicious patterns in memory.
pub struct MemoryScanner {
    process_handle: HANDLE,
}

impl MemoryScanner {
    /// Create a new MemoryScanner instance for the given process ID.
    pub fn new(process_id: u32) -> io::Result<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id);
            if handle.is_null() {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "Failed to open process"))
            } else {
                Ok(Self { process_handle: handle })
            }
        }
    }

    /// Scan the process's memory for suspicious patterns.
    pub fn scan_memory(&self) -> io::Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut address: usize = 0;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            unsafe {
                let result = VirtualQueryEx(
                    self.process_handle,
                    address as LPVOID,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                regions.push(MemoryRegion {
                    base_address: mbi.BaseAddress as usize,
                    region_size: mbi.RegionSize,
                    protection: mbi.Protect,
                });

                address += mbi.RegionSize;
            }
        }
        Ok(regions)
    }

    /// Read memory from a specific address and verify its content.
    pub fn read_memory(&self, address: usize, buffer: &mut [u8]) -> io::Result<()> {
        let mut bytes_read = 0;
        unsafe {
            let result = ReadProcessMemory(
                self.process_handle,
                address as LPVOID,
                buffer.as_mut_ptr() as LPVOID,
                buffer.len(),
                &mut bytes_read,
            );

            if result == 0 {
                Err(io::Error::new(io::ErrorKind::Other, "Failed to read memory"))
            } else {
                Ok(())
            }
        }
    }
}

impl Drop for MemoryScanner {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
        }
    }
}

/// Memory Scanner usage
fn main() {
    let process_id = 20349753830;
    match MemoryScanner::new(process_id) {
        Ok(scanner) => {
            match scanner.scan_memory() {
                Ok(regions) => {
                    println!("Scanned {} memory regions:", regions.len());
                    for region in regions {
                        println!(
                            "Base: {:#X}, Size: {}, Protection: {:#X}",
                            region.base_address, region.region_size, region.protection
                        );
                    }
                }
                Err(e) => eprintln!("Error scanning memory: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating memory scanner: {}", e),
    }
}
