use clap::Parser;
use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::os::raw::{c_char, c_ulong};
use std::ptr;

const CKR_OK: CkRv = 0;

#[allow(non_camel_case_types)]
type CkRv = c_ulong;
#[allow(non_camel_case_types)]
type CkFlags = c_ulong;
#[allow(non_camel_case_types)]
type CkUlong = c_ulong;
#[allow(non_camel_case_types)]
type CkByte = u8;
#[allow(non_camel_case_types)]
type CkUtf8Char = u8;
#[allow(non_camel_case_types)]
type CkVoidPtr = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct CkVersion {
    major: CkByte,
    minor: CkByte,
}

#[repr(C)]
struct CkInfo {
    cryptoki_version: CkVersion,
    manufacturer_id: [CkUtf8Char; 32],
    flags: CkFlags,
    library_description: [CkUtf8Char; 32],
    library_version: CkVersion,
}

#[repr(C)]
struct CkInterface {
    interface_name: *mut CkUtf8Char,
    function_list: CkVoidPtr,
    flags: CkFlags,
}

type CInitialize = unsafe extern "C" fn(CkVoidPtr) -> CkRv;
type CFinalize = unsafe extern "C" fn(CkVoidPtr) -> CkRv;
type CGetInfo = unsafe extern "C" fn(*mut CkInfo) -> CkRv;
type CGetFunctionList = unsafe extern "C" fn(*mut CkVoidPtr) -> CkRv;

type CGetInterface = unsafe extern "C" fn(
    *mut CkUtf8Char,
    *mut CkVersion,
    *mut *mut CkInterface,
    CkFlags,
) -> CkRv;

type CGetInterfaceList = unsafe extern "C" fn(*mut CkInterface, *mut CkUlong) -> CkRv;

#[repr(C)]
struct CkFunctionListPrefix {
    version: CkVersion,
    c_initialize: Option<CInitialize>,
    c_finalize: Option<CFinalize>,
    c_get_info: Option<CGetInfo>,
    c_get_function_list: Option<CGetFunctionList>,
}

#[derive(Parser, Debug)]
#[command(version, about = "Verify that a PKCS#11 module exposes the PKCS #11 Cryptoki 3.1 interface")]
struct Args {
    /// Filename of the PKCS#11 module
    #[arg(short, long)]
    module: String,
}

fn rv_to_result(rv: CkRv, context: &str) -> Result<(), String> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(format!("{context} failed with CK_RV=0x{rv:x}"))
    }
}

fn padded_bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end().to_owned()
}

unsafe fn get_symbol<'lib, T>(library: &'lib Library, name: &[u8]) -> Result<Symbol<'lib, T>, String> {
    library
        .get::<T>(name)
        .map_err(|err| format!("missing required symbol {}: {err}", String::from_utf8_lossy(name)))
}

fn main() {
    if let Err(err) = run() {
        eprintln!("FAIL: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    unsafe {
        let library = Library::new(&args.module)
            .map_err(|err| format!("failed to load module {}: {err}", args.module))?;

        let c_get_interface_list: Symbol<CGetInterfaceList> =
            get_symbol(&library, b"C_GetInterfaceList\0")?;
        let c_get_interface: Symbol<CGetInterface> = get_symbol(&library, b"C_GetInterface\0")?;

        let mut interface_count: CkUlong = 0;
        rv_to_result(
            c_get_interface_list(ptr::null_mut(), &mut interface_count),
            "C_GetInterfaceList(NULL, &count)",
        )?;
        if interface_count == 0 {
            return Err("C_GetInterfaceList reported zero supported interfaces".to_owned());
        }

        let mut interfaces = Vec::<CkInterface>::with_capacity(interface_count as usize);
        rv_to_result(
            c_get_interface_list(interfaces.as_mut_ptr(), &mut interface_count),
            "C_GetInterfaceList(list, &count)",
        )?;
        interfaces.set_len(interface_count as usize);

        let has_pkcs11_name = interfaces.iter().any(|interface| {
            if interface.interface_name.is_null() {
                return false;
            }
            let name = std::ffi::CStr::from_ptr(interface.interface_name as *const c_char)
                .to_string_lossy();
            name == "PKCS 11"
        });
        if !has_pkcs11_name {
            return Err("C_GetInterfaceList did not include an interface named \"PKCS 11\"".to_owned());
        }

        let mut requested_version = CkVersion { major: 3, minor: 1 };
        let mut interface_name = b"PKCS 11\0".to_vec();
        let mut selected_interface: *mut CkInterface = ptr::null_mut();
        rv_to_result(
            c_get_interface(
                interface_name.as_mut_ptr(),
                &mut requested_version,
                &mut selected_interface,
                0,
            ),
            "C_GetInterface(\"PKCS 11\", 3.1)",
        )?;
        if selected_interface.is_null() {
            return Err("C_GetInterface returned a null CK_INTERFACE pointer".to_owned());
        }

        let selected = &*selected_interface;
        if selected.function_list.is_null() {
            return Err("selected CK_INTERFACE has a null pFunctionList".to_owned());
        }
        let function_list = &*(selected.function_list as *const CkFunctionListPrefix);
        if function_list.version.major != 3 || function_list.version.minor != 1 {
            return Err(format!(
                "selected function list version is {}.{}, expected 3.1",
                function_list.version.major, function_list.version.minor
            ));
        }

        let c_initialize = function_list
            .c_initialize
            .ok_or_else(|| "selected function list has null C_Initialize".to_owned())?;
        let c_finalize = function_list
            .c_finalize
            .ok_or_else(|| "selected function list has null C_Finalize".to_owned())?;
        let c_get_info = function_list
            .c_get_info
            .ok_or_else(|| "selected function list has null C_GetInfo".to_owned())?;

        rv_to_result(c_initialize(ptr::null_mut()), "C_Initialize through 3.1 interface")?;

        let mut info = CkInfo {
            cryptoki_version: CkVersion { major: 0, minor: 0 },
            manufacturer_id: [0; 32],
            flags: 0,
            library_description: [0; 32],
            library_version: CkVersion { major: 0, minor: 0 },
        };
        let info_result = c_get_info(&mut info);
        let finalize_result = c_finalize(ptr::null_mut());
        rv_to_result(finalize_result, "C_Finalize through 3.1 interface")?;
        rv_to_result(info_result, "C_GetInfo through 3.1 interface")?;

        if info.cryptoki_version.major != 3 || info.cryptoki_version.minor != 1 {
            return Err(format!(
                "C_GetInfo through selected interface returned Cryptoki {}.{}, expected 3.1",
                info.cryptoki_version.major, info.cryptoki_version.minor
            ));
        }
        if info.flags != 0 {
            return Err(format!("C_GetInfo flags were 0x{:x}, expected 0x0", info.flags));
        }

        println!(
            "PASS: selected \"PKCS 11\" Cryptoki 3.1 interface from {} ({}, library version {}.{})",
            args.module,
            padded_bytes_to_string(&info.library_description),
            info.library_version.major,
            info.library_version.minor
        );
    }

    Ok(())
}
