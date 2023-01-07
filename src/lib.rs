// dolphin-memory provides an API for hooking into dolphin and accessing runtime memory. It conveniently
// handles mapping of common data types, endian-ness, pointer chains and more. Accessing memory
// in this way is implicitly unsafe, but an effort is being made to ensure the API is as safe
// as it can be for use.


// https://github.com/Tommoa/rs-process-memory

use core::slice;
use std::borrow::BorrowMut;
use std::ffi;
use std::ffi::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem;
use std::ptr;
use std::convert::TryInto;
use std::sync::Mutex;
use std::sync::Once;
use std::usize;

use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;
use sysinfo::{System, Process, ProcessRefreshKind};

use process_memory::Architecture;
use process_memory::{
    CopyAddress, ProcessHandle, ProcessHandleExt, PutAddress, TryIntoProcessHandle,
};
use thiserror::Error;

// MEM1_STRIP_START is  useful for stripping the `8` from the start
// of memory addresses within the MEM1 region.
pub const MEM1_STRIP_START: usize = 0x7FFF_FFFF;

pub const MEM1_START: usize = 0x10000000;
pub const MEM1_END: usize = 0x81800000;
pub const MEM1_SIZE: usize = 0x2000000;
pub const MEM2_SIZE: usize = 0x4000000;

static mut DOLPHIN: Option<Mutex<Dolphin>> = None;
static mut SYSTEM: Option<Mutex<System>> = None;

static INIT_DOLPHIN: Once = Once::new();
static INIT_SYSTEM: Once = Once::new();


fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}

#[derive(Error)]
pub enum ProcessError {
    #[error("failed to find process for dolphin")]
    DolphinNotFound,
    #[error("emulation not running")]
    EmulationNotRunning,
    #[error("unknown error")]
    UnknownError(#[source] io::Error),
}

impl std::fmt::Debug for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EmuRAMAddresses {
    mem_1: usize,
    mem_2: usize,
}



#[derive(Debug, Clone)]
pub struct Dolphin {
    handle: ProcessHandle,
    ram: EmuRAMAddresses,
}

fn get_dolphin<'a>() -> &'a Mutex<Dolphin> {
    unsafe {
        INIT_DOLPHIN.call_once(|| {
            *DOLPHIN.borrow_mut() = Some(Mutex::new(find_dolphin()));
        });
        return DOLPHIN.as_ref().unwrap();
    }
}

fn get_system<'b>() -> &'b Mutex<System> {
    unsafe {
        INIT_SYSTEM.call_once(|| {
            *SYSTEM.borrow_mut() = Some(Mutex::new(System::new_all()));
        });
        return SYSTEM.as_ref().unwrap();
    }
}

fn find_dolphin() -> Dolphin {
    return match Dolphin::new() {
        Ok(dolphin) => dolphin,
        Err(_why) => {
            return Dolphin{handle: ProcessHandle::null_type(), ram: EmuRAMAddresses::default()}
        }
    }
}


// this is to allow the std::ffi::c_void pointer of the
// process_memory::ProcessHandle to be passed through threads.
// This is technically unsafe, but in practice it _shouldn't_ cause
// issues as we're never changing anything about this pointer.
unsafe impl Send for Dolphin {}


#[no_mangle]
pub extern "C" fn init() {
    get_dolphin();
}

#[no_mangle]
#[cfg(target_os = "linux")]
pub extern "C" fn find_pid() -> process_memory::Pid {
    let app_pid = get_pid(vec!["dolphin-emu", "dolphin-emu-qt2", "dolphin-emu-wx"]);
    if app_pid.is_none() {
        return 0
    }
    return app_pid.unwrap();
}

#[no_mangle]
#[cfg(target_os = "windows")]
pub extern "C" fn find_pid() -> process_memory::Pid {
    let app_pid = get_pid(vec!["Dolphin.exe", "DolphinQt1.exe", "DolphinWx.exe"]);
    if app_pid.is_none() {
        return 0
    }
    return app_pid.unwrap();
}


#[no_mangle]
pub extern "C" fn hook() {
    let dolphin = get_dolphin().lock().unwrap();
    if dolphin.is_emulation_running() == false {
        *get_dolphin().lock().unwrap() = find_dolphin();
    }
}

#[no_mangle]
pub extern "C" fn getStatus() -> bool {
    return get_dolphin().lock().unwrap().is_emulation_running();
}

// This is mostly for validating the Struct using regular Dolphin Memory Engine
#[no_mangle]
pub extern "C" fn getMemOne() -> usize {
    return get_dolphin().lock().unwrap().ram.mem_1;
}

// Used for testing what string can find Processes on Mac.
// #[no_mangle]
// pub extern "C" fn check_string(java_str: * const c_char) -> bool {
//     unsafe {
//         let c_str : &CStr = unsafe {
//         assert!(!java_str.is_null());

//         CStr::from_ptr(java_str)
//         };
//         let rust_str = std::str::from_utf8(c_str.to_bytes()).unwrap();
//         return rust_str == "Dolphin.exe";
//     }
// }

// #[no_mangle]
// pub extern "C" fn check_pid_from_str(java_str: * const c_char, output: * mut c_char) {
//         unsafe {
//         let c_str : &CStr = unsafe {
//         assert!(!java_str.is_null());

//         CStr::from_ptr(java_str)
//         };
//         let rust_str = std::str::from_utf8(c_str.to_bytes()).unwrap();
//         let mut pid_str: Vec<&str> = Vec::new();
//         pid_str.push(rust_str);
//         let result = match get_pid(pid_str) {
//             Some(pid_result) => pid_result.to_string(),
//             None => "failure".to_string(),
//         };
//         let c_string: CString = CString::new(result.as_str()).unwrap();
//         let c_str: &CStr = c_string.as_c_str();
//         ptr::copy(c_str.as_ptr(), output, result.len());
//     }
// }


#[no_mangle]
pub extern "C" fn readFromRAM(console_address: usize, size: usize, buf: *mut u8) {
    unsafe {
        match get_dolphin().lock().unwrap().read(size, console_address) {
            Err(_why) => return,
            Ok(vector) => {
                ptr::copy(vector.as_ptr(), buf, size);
            }
        };
    }
}

#[no_mangle]
pub extern "C" fn writeToRAM(console_address: usize, size: usize, buf: * const u8) -> bool {
    unsafe {
        let slice_buf = slice::from_raw_parts::<u8>(buf, size);
        match get_dolphin().lock().unwrap().write(slice_buf, console_address) {
            Err(_why) => return false,
            Ok(_reason) => return true
        }
    }
}



impl Dolphin {
    // new hooks into the Dolphin process and into the gamecube ram. This can block while looking,
    // but more likely it will error on failure. An easy pattern to check this on repeat is to loop and break
    // on success. You can opt-to do something with the error if you choose, but during hook it's really only basic insights.
    #[cfg(target_os = "windows")]
    pub fn new() -> Result<Self, ProcessError> {
        let handle = match get_pid(vec!["Dolphin.exe", "DolphinQt1.exe", "DolphinWx.exe"]) {
            Some(h) => h
            .try_into_process_handle()
            .map_err(|e| ProcessError::UnknownError(e))?,
            None => return Err(ProcessError::DolphinNotFound),
        };
        
        let ram = ram_info(handle)?;
        let handle = handle.set_arch(process_memory::Architecture::Arch32Bit);
        
        Ok(Dolphin { handle, ram})
    }

    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self, ProcessError> {
        let app_pid = get_pid(vec!["dolphin-emu", "dolphin-emu-qt2", "dolphin-emu-wx"]);
        let handle = match get_pid(vec!["dolphin-emu", "dolphin-emu-qt2", "dolphin-emu-wx"]) {
            Some(h) => h
            .try_into_process_handle()
            .map_err(|e| ProcessError::UnknownError(e))?,
            None => return Err(ProcessError::DolphinNotFound),
        };
        let ram: EmuRAMAddresses = EmuRAMAddresses { mem_1: 0, mem_2: 0 };
        if app_pid.is_some() {
            let ram = ram_info(app_pid.unwrap_or(0))?;
        }
        let handle = handle.set_arch(process_memory::Architecture::Arch32Bit);
        
        Ok(Dolphin { handle, ram })
    }

    // #[cfg(target_os = "mac_os")]
    
    // is_emulation_running queries ram info to determine if the emulator is still running.
    #[cfg(target_os = "windows")]
    pub fn is_emulation_running(&self) -> bool {
        match ram_info(self.handle) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    #[cfg(target_os = "linux")]
    pub fn is_emulation_running(&self) -> bool {
        let app_pid = get_pid(vec!["dolphin-emu", "dolphin-emu-qt2", "dolphin-emu-wx"]);
        if app_pid.is_some() {
            return match ram_info(app_pid.unwrap_or(0)) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        return false;
    }

    // read takes a size, starting address and an optional list of pointer offsets,
    // following those addresses until it hits the underyling data.
    //
    // TODO: There's a number of issues with this function. For starters,
    // it only knows how to handle MEM1 addresses. Supporting addresses
    // in the MEM2 space will require some refactoring, but I believe it can
    // be done while maintaining this API.
    // Additionally, this code will have to resolve the addresses given to it
    // every single time it's run, but in all likelihood the addresses will not
    // change that frequently. It would be a good idea to introduce a cache layer here
    // which caches the output address using a hash of the input address + offsets.
    pub fn read(
        &self,
        size: usize,
        starting_address: usize,
    ) -> io::Result<Vec<u8>> {
        // TODO: this should realistically be able to handle picking mem_1 or mem_2,
        // but we'll just stick to mem_1 for now.
        let starting_address = starting_address & MEM1_STRIP_START;
        let mut buffer = vec![0_u8; size];
        let address = self
        .handle
        .get_offset(&[self.ram.mem_1 + starting_address])?;
        
        self.handle.copy_address(address, &mut buffer)?;
        
        return Ok(buffer);
    }
    
    // write a buffer of bytes to the given address or pointer of address.
    pub fn write(
        &self,
        buf: &[u8],
        starting_address: usize
    ) -> io::Result<()> {

        let starting_address = self.handle.get_offset(&[(self.ram.mem_1 + (starting_address & MEM1_STRIP_START))])?;
        self.handle.put_address(starting_address, buf)?;
        
        Ok(())
    }
    
}

// get_pid looks up the process id for the given list of process names


fn get_pid(process_names: Vec<&str>) -> Option<process_memory::Pid> {
    get_system().lock().unwrap().refresh_processes_specifics(ProcessRefreshKind::everything().without_cpu());
    for (_p_pid, p_proc) in get_system().lock().unwrap().processes() {
        if process_names.contains(&p_proc.name()) {
            #[cfg(target_os = "windows")]
            return Some(p_proc.pid().as_u32());
            #[cfg(target_os = "linux")]
            return Some(p_proc.pid().as_u32() as i32);
        }
    }
    None
} 

#[cfg(target_os = "linux")]
fn ram_info(pid: process_memory::Pid) -> Result<EmuRAMAddresses, ProcessError> {
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;
    use std::io::{self, BufRead};

        // Open the path in read-only mode, returns `io::Result<File>`
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
        where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    let mut mem1: Option<usize> = None;
    let mut mem2: Option<usize> = None;

    if let Ok(lines) = read_lines(format!("/proc/{}/maps", pid)) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            let mut line_data: Vec<String> = Vec::new();
            if let Ok(info) = line {
                for split_info in info.split(' ') {
                    if split_info.len() > 0 {
                        line_data.push(split_info.to_string());
                    }
                }
            }
            if line_data.len() < 3 {
                continue;
            }

            let mut found_dev_shm = false;
            for data in &line_data {
                if data.starts_with("/dev/shm/dolphinmem") || data.starts_with("/dev/shm/dolphin-emu") {
                    panic!("Found shm!");
                    found_dev_shm = true;
                    break;
                }
            }
            if !found_dev_shm {
                continue;
            }
            let offset_str: String = line_data.get(2).unwrap().to_string();
            let offset_result = u32::from_str_radix(&offset_str, 16);
            let offset: u32;
            match offset_result {
                Ok(result) => offset = result,
                Err(_err) => continue
            }
            if offset != 0 && offset != 0x2040000 {
                continue;
            }
            let mut first_address: usize = 0;
            let mut second_address: usize = 0;
            let index_dash = line_data.get(0).unwrap().find('-').unwrap();
            let first_address_str = &line_data.get(0).unwrap().to_string()[..index_dash];
            let second_address_str = &line_data.get(0).unwrap().to_string()[index_dash + 1..];

            let first_address_result = usize::from_str_radix(&first_address_str, 16);
            let second_address_result = usize::from_str_radix(&second_address_str, 16);
            if first_address_result.is_ok() {
                first_address = first_address_result.unwrap();
            }
            if second_address_result.is_ok() {
                second_address = second_address_result.unwrap();
            }
            if (second_address - first_address == 0x4000000) && offset == 0x2040000 {
                mem2 = Some(first_address);
                if mem1.is_some() {
                    break;
                }
            }
            if (second_address - first_address == 0x2000000) && offset == 0x0 {
                mem1 = Some(first_address);
            }
        } // End of for line in Line
    } // End of Proc File Management
    if mem1.is_none() {
        return Err(ProcessError::EmulationNotRunning);
    }
    
    Ok(EmuRAMAddresses {
        mem_1: mem1.unwrap_or_default(),
        mem_2: mem2.unwrap_or_default(),
    })
}

// ram_info is a convenient function wrapper for querying the emulated GC heap addresses.
#[cfg(target_os = "windows")]
fn ram_info(process: ProcessHandle) -> Result<EmuRAMAddresses, ProcessError> {
    use winapi::um::memoryapi;
    use winapi::um::psapi;
    use winapi::um::winnt;

    let mut mem1: Option<usize> = None;
    let mut mem2: Option<usize> = None;
    
    let mut p = ptr::null_mut();
    let mut info = winnt::MEMORY_BASIC_INFORMATION::default();
    loop {
        // Attempt to retrieve a range of pages within the virtual address space
        let size = unsafe {
            memoryapi::VirtualQueryEx(
                process.0,
                p,
                &mut info,
                mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
            )
        };
        if size != mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>() {
            break;
        }
        
        // check region size so that we know it's mem2
        if info.RegionSize == MEM2_SIZE {
            let region_base_address = info.BaseAddress as usize;
            
            if let Some(region) = mem1 {
                if region_base_address > region + MEM1_START {
                    // in some cases MEM2 could actually be before MEM1. Once we find
                    // MEM1, ignore regions of this size that are too far away. There
                    // apparently are other non-MEM2 regions of size 0x40000000.
                    break;
                }
            }
            
            // View the comment for MEM1
            let mut ws_info = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                VirtualAddress: info.BaseAddress,
                ..Default::default()
            };
            let page_info = {
                match unsafe { psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                    .try_into()
                    .unwrap(),
                ) }{
                    0 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            };
            if page_info.is_ok() && ws_info.VirtualAttributes.Valid() == 1 {
                // note that mem::transmute_copy triggers undefined behavior
                // if the output type is larger than the pointer.
                //
                // A good safety precaution here would be to check this before
                // calling mem::transmute_copy, just to be safe.
                unsafe {
                    mem2 = Some(mem::transmute_copy(&info.BaseAddress));
                }
            }
        } else if mem1.is_none() && info.RegionSize == MEM1_SIZE && info.Type == winnt::MEM_MAPPED {
            // Here it's likely the right page, but it can happen that multiple pages
            // with these criteria exists and have nothing to do with emulated memory.
            // Only the right page has valid working set information so an additional
            // check is required that it is backed by physical memory.
            let mut ws_info = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                VirtualAddress: info.BaseAddress,
                ..Default::default()
            };
            let page_info = {
                match unsafe { psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                    .try_into()
                    .unwrap(),
                ) }{
                    0 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            };
            if page_info.is_ok() && ws_info.VirtualAttributes.Valid() == 1 {
                // note that mem::transmute_copy triggers undefined behavior
                // if the output type is larger than the pointer.
                //
                // A good safety precaution here would be to check this before
                // calling mem::transmute_copy, just to be safe.
                unsafe {
                    mem1 = Some(mem::transmute_copy(&info.BaseAddress));
                    let mem_val = mem1.unwrap_or_default();
                    print!("{mem_val:?}");
                }
            }
        }
        
        if mem1.is_some() && mem2.is_some() {
            break;
        }
        
        // iter through region size
        unsafe { p = p.add(info.RegionSize) };
    }
    
    if mem1.is_none() {
        return Err(ProcessError::EmulationNotRunning);
    }
    
    Ok(EmuRAMAddresses {
        mem_1: mem1.unwrap_or_default(),
        mem_2: mem2.unwrap_or_default(),
    })
}

#[cfg(target_os = "macos")]
fn ram_info(process: ProcessHandle) -> Result<EmuRAMAddresses, ProcessError> {
    None
}