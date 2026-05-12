use clap::Parser;
use libloading::{Library, Symbol};
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::collections::HashMap;
use std::env;
use std::ffi::{c_void, CStr};
use std::fs;
use std::os::raw::{c_char, c_ulong};
use std::ptr;

const CKR_OK: CK_RV = 0;
const CK_TRUE: CK_BBOOL = 1;

const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

const CKU_USER: CK_USER_TYPE = 1;

const CKO_PUBLIC_KEY: CK_ULONG = 0x00000002;
const CKO_PRIVATE_KEY: CK_ULONG = 0x00000003;

const CKA_CLASS: CK_ULONG = 0x00000000;
const CKA_TOKEN: CK_ULONG = 0x00000001;
const CKA_LABEL: CK_ULONG = 0x00000003;
const CKA_VALUE: CK_ULONG = 0x00000011;
const CKA_MODULUS: CK_ULONG = 0x00000120;
const CKA_PUBLIC_EXPONENT: CK_ULONG = 0x00000122;

const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;

#[allow(non_camel_case_types)]
type CK_RV = c_ulong;
#[allow(non_camel_case_types)]
type CK_FLAGS = c_ulong;
#[allow(non_camel_case_types)]
type CK_ULONG = c_ulong;
#[allow(non_camel_case_types)]
type CK_BYTE = u8;
#[allow(non_camel_case_types)]
type CK_BBOOL = u8;
#[allow(non_camel_case_types)]
type CK_UTF8CHAR = u8;
#[allow(non_camel_case_types)]
type CK_SLOT_ID = c_ulong;
#[allow(non_camel_case_types)]
type CK_SESSION_HANDLE = c_ulong;
#[allow(non_camel_case_types)]
type CK_OBJECT_HANDLE = c_ulong;
#[allow(non_camel_case_types)]
type CK_MECHANISM_TYPE = c_ulong;
#[allow(non_camel_case_types)]
type CK_USER_TYPE = c_ulong;
#[allow(non_camel_case_types)]
type CK_VOID_PTR = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CK_VERSION {
    major: CK_BYTE,
    minor: CK_BYTE,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CK_INFO {
    cryptoki_version: CK_VERSION,
    manufacturer_id: [CK_UTF8CHAR; 32],
    flags: CK_FLAGS,
    library_description: [CK_UTF8CHAR; 32],
    library_version: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CK_SLOT_INFO {
    slot_description: [CK_UTF8CHAR; 64],
    manufacturer_id: [CK_UTF8CHAR; 32],
    flags: CK_FLAGS,
    hardware_version: CK_VERSION,
    firmware_version: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CK_TOKEN_INFO {
    label: [CK_UTF8CHAR; 32],
    manufacturer_id: [CK_UTF8CHAR; 32],
    model: [CK_UTF8CHAR; 16],
    serial_number: [CK_UTF8CHAR; 16],
    flags: CK_FLAGS,
    max_session_count: CK_ULONG,
    session_count: CK_ULONG,
    max_rw_session_count: CK_ULONG,
    rw_session_count: CK_ULONG,
    max_pin_len: CK_ULONG,
    min_pin_len: CK_ULONG,
    total_public_memory: CK_ULONG,
    free_public_memory: CK_ULONG,
    total_private_memory: CK_ULONG,
    free_private_memory: CK_ULONG,
    hardware_version: CK_VERSION,
    firmware_version: CK_VERSION,
    utc_time: [CK_UTF8CHAR; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CK_MECHANISM_INFO {
    min_key_size: CK_ULONG,
    max_key_size: CK_ULONG,
    flags: CK_FLAGS,
}

#[repr(C)]
struct CK_ATTRIBUTE {
    type_: CK_ULONG,
    p_value: CK_VOID_PTR,
    ul_value_len: CK_ULONG,
}

#[repr(C)]
struct CK_MECHANISM {
    mechanism: CK_MECHANISM_TYPE,
    p_parameter: CK_VOID_PTR,
    ul_parameter_len: CK_ULONG,
}

#[repr(C)]
struct CK_INTERFACE {
    interface_name: *mut CK_UTF8CHAR,
    function_list: CK_VOID_PTR,
    flags: CK_FLAGS,
}

type CInitialize = unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV;
type CFinalize = unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV;
type CGetInfo = unsafe extern "C" fn(*mut CK_INFO) -> CK_RV;
type CGetFunctionList = unsafe extern "C" fn(*mut CK_VOID_PTR) -> CK_RV;
type CGetSlotList = unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, *mut CK_ULONG) -> CK_RV;
type CGetSlotInfo = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV;
type CGetTokenInfo = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV;
type CGetMechanismList = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut CK_ULONG) -> CK_RV;
type CGetMechanismInfo = unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV;
type COpenSession = unsafe extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, *mut CK_SESSION_HANDLE) -> CK_RV;
type CCloseSession = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
type CCloseAllSessions = unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV;
type CLogin = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *mut CK_UTF8CHAR, CK_ULONG) -> CK_RV;
type CLogout = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
type CFindObjectsInit = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
type CFindObjects = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_OBJECT_HANDLE, CK_ULONG, *mut CK_ULONG) -> CK_RV;
type CFindObjectsFinal = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
type CGetAttributeValue = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
type CSignInit = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
type CSign = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;

type CGetInterface = unsafe extern "C" fn(*mut CK_UTF8CHAR, *mut CK_VERSION, *mut *mut CK_INTERFACE, CK_FLAGS) -> CK_RV;
type CGetInterfaceList = unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV;

#[repr(C)]
struct CK_FUNCTION_LIST_PREFIX {
    version: CK_VERSION,
    c_initialize: Option<CInitialize>,
    c_finalize: Option<CFinalize>,
    c_get_info: Option<CGetInfo>,
    c_get_function_list: Option<CGetFunctionList>,
    c_get_slot_list: Option<CGetSlotList>,
    c_get_slot_info: Option<CGetSlotInfo>,
    c_get_token_info: Option<CGetTokenInfo>,
    c_get_mechanism_list: Option<CGetMechanismList>,
    c_get_mechanism_info: Option<CGetMechanismInfo>,
    c_init_token: CK_VOID_PTR,
    c_init_pin: CK_VOID_PTR,
    c_set_pin: CK_VOID_PTR,
    c_open_session: Option<COpenSession>,
    c_close_session: Option<CCloseSession>,
    c_close_all_sessions: Option<CCloseAllSessions>,
    c_get_session_info: CK_VOID_PTR,
    c_get_operation_state: CK_VOID_PTR,
    c_set_operation_state: CK_VOID_PTR,
    c_login: Option<CLogin>,
    c_logout: Option<CLogout>,
    c_create_object: CK_VOID_PTR,
    c_copy_object: CK_VOID_PTR,
    c_destroy_object: CK_VOID_PTR,
    c_get_object_size: CK_VOID_PTR,
    c_get_attribute_value: Option<CGetAttributeValue>,
    c_set_attribute_value: CK_VOID_PTR,
    c_find_objects_init: Option<CFindObjectsInit>,
    c_find_objects: Option<CFindObjects>,
    c_find_objects_final: Option<CFindObjectsFinal>,
    c_encrypt_init: CK_VOID_PTR,
    c_encrypt: CK_VOID_PTR,
    c_encrypt_update: CK_VOID_PTR,
    c_encrypt_final: CK_VOID_PTR,
    c_decrypt_init: CK_VOID_PTR,
    c_decrypt: CK_VOID_PTR,
    c_decrypt_update: CK_VOID_PTR,
    c_decrypt_final: CK_VOID_PTR,
    c_digest_init: CK_VOID_PTR,
    c_digest: CK_VOID_PTR,
    c_digest_update: CK_VOID_PTR,
    c_digest_key: CK_VOID_PTR,
    c_digest_final: CK_VOID_PTR,
    c_sign_init: Option<CSignInit>,
    c_sign: Option<CSign>,
}

struct Dispatch {
    _library: Library,
    functions: &'static CK_FUNCTION_LIST_PREFIX,
}

impl Dispatch {
    fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
        value.ok_or_else(|| format!("selected 3.1 function table has null {name}"))
    }

    unsafe fn load(module: &str) -> Result<Self, String> {
        let library = Library::new(module).map_err(|err| format!("failed to load {module}: {err}"))?;
        let c_get_interface_list: Symbol<CGetInterfaceList> = library
            .get(b"C_GetInterfaceList\0")
            .map_err(|err| format!("missing C_GetInterfaceList: {err}"))?;
        let c_get_interface: Symbol<CGetInterface> = library
            .get(b"C_GetInterface\0")
            .map_err(|err| format!("missing C_GetInterface: {err}"))?;

        let mut count: CK_ULONG = 0;
        ck_ok(c_get_interface_list(ptr::null_mut(), &mut count), "C_GetInterfaceList(NULL, &count)")?;
        if count == 0 {
            return Err("C_GetInterfaceList returned zero interfaces".to_owned());
        }
        let mut interfaces = Vec::<CK_INTERFACE>::with_capacity(count as usize);
        ck_ok(c_get_interface_list(interfaces.as_mut_ptr(), &mut count), "C_GetInterfaceList(list, &count)")?;
        interfaces.set_len(count as usize);
        let has_pkcs11 = interfaces.iter().any(|interface| {
            !interface.interface_name.is_null()
                && CStr::from_ptr(interface.interface_name as *const c_char).to_string_lossy() == "PKCS 11"
        });
        if !has_pkcs11 {
            return Err("C_GetInterfaceList did not list \"PKCS 11\"".to_owned());
        }

        let mut version = CK_VERSION { major: 3, minor: 1 };
        let mut name = b"PKCS 11\0".to_vec();
        let mut selected: *mut CK_INTERFACE = ptr::null_mut();
        ck_ok(
            c_get_interface(name.as_mut_ptr(), &mut version, &mut selected, 0),
            "C_GetInterface(\"PKCS 11\", 3.1)",
        )?;
        if selected.is_null() || (*selected).function_list.is_null() {
            return Err("C_GetInterface returned a null interface/function list".to_owned());
        }
        let functions = &*((*selected).function_list as *const CK_FUNCTION_LIST_PREFIX);
        if functions.version.major != 3 || functions.version.minor != 1 {
            return Err(format!(
                "selected function list version is {}.{}, expected 3.1",
                functions.version.major, functions.version.minor
            ));
        }
        Ok(Self { _library: library, functions })
    }

    unsafe fn initialize(&self) -> CK_RV { Self::required(self.functions.c_initialize, "C_Initialize").unwrap()(ptr::null_mut()) }
    unsafe fn finalize(&self) -> CK_RV { Self::required(self.functions.c_finalize, "C_Finalize").unwrap()(ptr::null_mut()) }
    unsafe fn get_info(&self, info: *mut CK_INFO) -> CK_RV { Self::required(self.functions.c_get_info, "C_GetInfo").unwrap()(info) }
    unsafe fn get_slot_list(&self, token_present: CK_BBOOL, slots: *mut CK_SLOT_ID, count: *mut CK_ULONG) -> CK_RV { Self::required(self.functions.c_get_slot_list, "C_GetSlotList").unwrap()(token_present, slots, count) }
    unsafe fn get_slot_info(&self, slot: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV { Self::required(self.functions.c_get_slot_info, "C_GetSlotInfo").unwrap()(slot, info) }
    unsafe fn get_token_info(&self, slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV { Self::required(self.functions.c_get_token_info, "C_GetTokenInfo").unwrap()(slot, info) }
    unsafe fn get_mechanism_list(&self, slot: CK_SLOT_ID, mechanisms: *mut CK_MECHANISM_TYPE, count: *mut CK_ULONG) -> CK_RV { Self::required(self.functions.c_get_mechanism_list, "C_GetMechanismList").unwrap()(slot, mechanisms, count) }
    unsafe fn get_mechanism_info(&self, slot: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, info: *mut CK_MECHANISM_INFO) -> CK_RV { Self::required(self.functions.c_get_mechanism_info, "C_GetMechanismInfo").unwrap()(slot, mechanism, info) }
    unsafe fn open_session(&self, slot: CK_SLOT_ID, flags: CK_FLAGS, session: *mut CK_SESSION_HANDLE) -> CK_RV { Self::required(self.functions.c_open_session, "C_OpenSession").unwrap()(slot, flags, ptr::null_mut(), ptr::null_mut(), session) }
    unsafe fn close_session(&self, session: CK_SESSION_HANDLE) -> CK_RV { Self::required(self.functions.c_close_session, "C_CloseSession").unwrap()(session) }
    unsafe fn close_all_sessions(&self, slot: CK_SLOT_ID) -> CK_RV { Self::required(self.functions.c_close_all_sessions, "C_CloseAllSessions").unwrap()(slot) }
    unsafe fn login(&self, session: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: *mut CK_UTF8CHAR, pin_len: CK_ULONG) -> CK_RV { Self::required(self.functions.c_login, "C_Login").unwrap()(session, user_type, pin, pin_len) }
    unsafe fn logout(&self, session: CK_SESSION_HANDLE) -> CK_RV { Self::required(self.functions.c_logout, "C_Logout").unwrap()(session) }
    unsafe fn find_objects_init(&self, session: CK_SESSION_HANDLE, attrs: *mut CK_ATTRIBUTE, count: CK_ULONG) -> CK_RV { Self::required(self.functions.c_find_objects_init, "C_FindObjectsInit").unwrap()(session, attrs, count) }
    unsafe fn find_objects(&self, session: CK_SESSION_HANDLE, objects: *mut CK_OBJECT_HANDLE, max_count: CK_ULONG, count: *mut CK_ULONG) -> CK_RV { Self::required(self.functions.c_find_objects, "C_FindObjects").unwrap()(session, objects, max_count, count) }
    unsafe fn find_objects_final(&self, session: CK_SESSION_HANDLE) -> CK_RV { Self::required(self.functions.c_find_objects_final, "C_FindObjectsFinal").unwrap()(session) }
    unsafe fn get_attribute_value(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, attrs: *mut CK_ATTRIBUTE, count: CK_ULONG) -> CK_RV { Self::required(self.functions.c_get_attribute_value, "C_GetAttributeValue").unwrap()(session, object, attrs, count) }
    unsafe fn sign_init(&self, session: CK_SESSION_HANDLE, mechanism: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE) -> CK_RV { Self::required(self.functions.c_sign_init, "C_SignInit").unwrap()(session, mechanism, key) }
    unsafe fn sign(&self, session: CK_SESSION_HANDLE, data: *mut CK_BYTE, data_len: CK_ULONG, signature: *mut CK_BYTE, signature_len: *mut CK_ULONG) -> CK_RV { Self::required(self.functions.c_sign, "C_Sign").unwrap()(session, data, data_len, signature, signature_len) }
}

#[derive(Parser, Debug)]
#[command(version, about = "Run PKCS#11 v3.1 mandatory profile tests")]
struct Args {
    /// Filename of the PKCS#11 module
    #[arg(short, long)]
    module: String,

    /// Test case XML files. If omitted, integrated v3.1 mandatory tests are used.
    #[arg(num_args(0..))]
    tests: Option<Vec<String>>,
}

#[derive(Clone)]
struct Element {
    name: String,
    attrs: HashMap<String, String>,
}

struct Step {
    name: String,
    rv: String,
    is_expectation: bool,
    elements: Vec<Element>,
}

#[derive(Default)]
struct State {
    slots: Vec<CK_SLOT_ID>,
    sessions: Vec<CK_SESSION_HANDLE>,
    objects: Vec<CK_OBJECT_HANDLE>,
    vars: HashMap<String, String>,
}

enum Pending {
    None,
    Rv(CK_RV),
    Info(CK_RV, CK_INFO),
    Count(CK_RV, CK_ULONG),
    Slots(CK_RV, Vec<CK_SLOT_ID>),
    SlotInfo(CK_RV),
    TokenInfo(CK_RV),
    Mechanisms(CK_RV, Vec<CK_MECHANISM_TYPE>),
    MechanismInfo(CK_RV),
    Session(CK_RV, CK_SESSION_HANDLE),
    Objects(CK_RV, Vec<CK_OBJECT_HANDLE>),
    Attributes(CK_RV),
    Signature(CK_RV),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("FAIL: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let dispatch = unsafe { Dispatch::load(&args.module)? };
    let tests = load_tests(&args)?;
    let mut pass = 0usize;
    let mut fail = 0usize;
    for (name, xml) in tests {
        println!("\nTEST {name}");
        match run_test(&dispatch, &xml) {
            Ok(()) => { pass += 1; println!("PASS {name}"); }
            Err(err) => { fail += 1; println!("FAIL {name}: {err}"); }
        }
    }
    println!("\nSUMMARY PASS={pass} FAIL={fail}");
    if fail == 0 { Ok(()) } else { Err(format!("{fail} test file(s) failed")) }
}

fn load_tests(args: &Args) -> Result<Vec<(String, String)>, String> {
    if let Some(paths) = &args.tests {
        let mut out = Vec::new();
        for path in paths {
            out.push((path.clone(), fs::read_to_string(path).map_err(|err| format!("failed to read {path}: {err}"))?));
        }
        return Ok(out);
    }
    Ok(vec![
        ("BL-M-1-31.xml".to_owned(), include_str!("../test-cases/pkcs11-v3.1/mandatory/BL-M-1-31.xml").to_owned()),
        ("EXT-M-1-31.xml".to_owned(), include_str!("../test-cases/pkcs11-v3.1/mandatory/EXT-M-1-31.xml").to_owned()),
        ("AUTH-M-1-31.xml".to_owned(), include_str!("../test-cases/pkcs11-v3.1/mandatory/AUTH-M-1-31.xml").to_owned()),
        ("CERT-M-1-31.xml".to_owned(), include_str!("../test-cases/pkcs11-v3.1/mandatory/CERT-M-1-31.xml").to_owned()),
    ])
}

fn run_test(dispatch: &Dispatch, xml: &str) -> Result<(), String> {
    let steps = parse_steps(xml)?;
    let mut state = State::default();
    let mut pending = Pending::None;
    for step in steps {
        if step.is_expectation {
            verify(&step, &mut pending, &mut state)?;
        } else {
            pending = execute(dispatch, &step, &mut state)?;
        }
    }
    Ok(())
}

fn parse_steps(xml: &str) -> Result<Vec<Step>, String> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut in_root = false;
    let mut steps = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).map_err(|err| err.to_string())? {
            Event::Eof => break,
            Event::Start(e) if e.name().as_ref() == b"PKCS11" => in_root = true,
            Event::End(e) if e.name().as_ref() == b"PKCS11" => in_root = false,
            Event::Empty(e) if in_root && is_call(e.name().as_ref()) => steps.push(step_from_empty(&e)?),
            Event::Start(e) if in_root && is_call(e.name().as_ref()) => steps.push(collect_step(&mut reader, e)?),
            _ => (),
        }
        buf.clear();
    }
    Ok(steps)
}

fn is_call(name: &[u8]) -> bool { name.starts_with(b"C_") }

fn element_from(e: &BytesStart) -> Result<Element, String> {
    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
    let mut attrs = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| err.to_string())?;
        attrs.insert(
            String::from_utf8_lossy(attr.key.as_ref()).to_string(),
            String::from_utf8_lossy(attr.value.as_ref()).to_string(),
        );
    }
    Ok(Element { name, attrs })
}

fn step_from_empty(e: &BytesStart) -> Result<Step, String> {
    let element = element_from(e)?;
    Ok(Step {
        name: element.name,
        rv: element.attrs.get("rv").cloned().unwrap_or_else(|| "OK".to_owned()),
        is_expectation: element.attrs.contains_key("rv"),
        elements: Vec::new(),
    })
}

fn collect_step(reader: &mut Reader<&[u8]>, start: BytesStart) -> Result<Step, String> {
    let top = element_from(&start)?;
    let mut elements = Vec::new();
    let mut depth = 0usize;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).map_err(|err| err.to_string())? {
            Event::Start(e) => { elements.push(element_from(&e)?); depth += 1; }
            Event::Empty(e) => elements.push(element_from(&e)?),
            Event::End(e) => {
                if depth == 0 && e.name().as_ref() == top.name.as_bytes() { break; }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => return Err(format!("unexpected EOF in {}", top.name)),
            _ => (),
        }
        buf.clear();
    }
    Ok(Step {
        name: top.name,
        rv: top.attrs.get("rv").cloned().unwrap_or_else(|| "OK".to_owned()),
        is_expectation: top.attrs.contains_key("rv"),
        elements,
    })
}

fn ck_ok(rv: CK_RV, context: &str) -> Result<(), String> {
    if rv == CKR_OK { Ok(()) } else { Err(format!("{context} returned CK_RV=0x{rv:x}")) }
}

fn expected_ok(step: &Step) -> bool { step.rv == "OK" }
fn verify_rv(rv: CK_RV, step: &Step) -> Result<(), String> {
    if expected_ok(step) && rv != CKR_OK { Err(format!("{} expected OK, got CK_RV=0x{rv:x}", step.name)) } else { Ok(()) }
}

fn execute(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        match step.name.as_str() {
            "C_Initialize" => Ok(Pending::Rv(dispatch.initialize())),
            "C_Finalize" => Ok(Pending::Rv(dispatch.finalize())),
            "C_GetInfo" => {
                let mut info = zeroed::<CK_INFO>();
                let rv = dispatch.get_info(&mut info);
                Ok(Pending::Info(rv, info))
            }
            "C_GetSlotList" => execute_get_slot_list(dispatch, step, state),
            "C_GetSlotInfo" => {
                let mut info = zeroed::<CK_SLOT_INFO>();
                let rv = dispatch.get_slot_info(resolve_slot(step, state)?, &mut info);
                Ok(Pending::SlotInfo(rv))
            }
            "C_GetTokenInfo" => {
                let mut info = zeroed::<CK_TOKEN_INFO>();
                let rv = dispatch.get_token_info(resolve_slot(step, state)?, &mut info);
                Ok(Pending::TokenInfo(rv))
            }
            "C_GetMechanismList" => execute_get_mechanism_list(dispatch, step, state),
            "C_GetMechanismInfo" => {
                let mut info = zeroed::<CK_MECHANISM_INFO>();
                let rv = dispatch.get_mechanism_info(resolve_slot(step, state)?, child_type(step)?, &mut info);
                Ok(Pending::MechanismInfo(rv))
            }
            "C_OpenSession" => {
                let mut session = 0;
                let rv = dispatch.open_session(resolve_slot(step, state)?, child_flags(step), &mut session);
                Ok(Pending::Session(rv, session))
            }
            "C_CloseSession" => Ok(Pending::Rv(dispatch.close_session(resolve_session(step, state)?))),
            "C_CloseAllSessions" => Ok(Pending::Rv(dispatch.close_all_sessions(resolve_slot(step, state)?))),
            "C_Login" => {
                let mut pin = child_value(step, "Pin")
                    .map(|value| resolve_value(&value, state))
                    .unwrap_or_default()
                    .into_bytes();
                Ok(Pending::Rv(dispatch.login(resolve_session(step, state)?, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG)))
            }
            "C_Logout" => Ok(Pending::Rv(dispatch.logout(resolve_session(step, state)?))),
            "C_FindObjectsInit" => {
                let mut values = Vec::<Vec<u8>>::new();
                let mut attrs = build_find_attributes(step, &mut values)?;
                Ok(Pending::Rv(dispatch.find_objects_init(resolve_session(step, state)?, attrs.as_mut_ptr(), attrs.len() as CK_ULONG)))
            }
            "C_FindObjects" => execute_find_objects(dispatch, step, state),
            "C_FindObjectsFinal" => Ok(Pending::Rv(dispatch.find_objects_final(resolve_session(step, state)?))),
            "C_GetAttributeValue" => execute_get_attribute_value(dispatch, step, state),
            "C_SignInit" => {
                let mut mechanism = CK_MECHANISM { mechanism: child_type(step)?, p_parameter: ptr::null_mut(), ul_parameter_len: 0 };
                Ok(Pending::Rv(dispatch.sign_init(resolve_session(step, state)?, &mut mechanism, resolve_key(step, state)?)))
            }
            "C_Sign" => execute_sign(dispatch, step, state),
            other => Err(format!("unsupported XML action {other}")),
        }
    }
}

fn verify(step: &Step, pending: &mut Pending, state: &mut State) -> Result<(), String> {
    match std::mem::replace(pending, Pending::None) {
        Pending::Rv(rv) => verify_rv(rv, step),
        Pending::Info(rv, info) => {
            verify_rv(rv, step)?;
            if let Some(v) = child(step, "CryptokiVersion") {
                let major = attr_u8(v, "major", 3)?;
                let minor = attr_u8(v, "minor", 1)?;
                if info.cryptoki_version.major != major || info.cryptoki_version.minor != minor {
                    return Err(format!("C_GetInfo returned Cryptoki {}.{}, expected {major}.{minor}", info.cryptoki_version.major, info.cryptoki_version.minor));
                }
            }
            if let Some(flags) = child(step, "Flags").and_then(|e| e.attrs.get("value")) {
                if flags == "0x0" && info.flags != 0 { return Err(format!("C_GetInfo flags 0x{:x}, expected 0x0", info.flags)); }
            }
            Ok(())
        }
        Pending::Count(rv, count) => { verify_rv(rv, step)?; bind_count(step, state, count); Ok(()) }
        Pending::Slots(rv, slots) => { verify_rv(rv, step)?; state.slots = slots; bind_slot_vars(state); Ok(()) }
        Pending::SlotInfo(rv) | Pending::TokenInfo(rv) | Pending::MechanismInfo(rv) | Pending::Attributes(rv) => verify_rv(rv, step),
        Pending::Mechanisms(rv, mechanisms) => {
            verify_rv(rv, step)?;
            for ty in children(step, "Type").iter().filter_map(|e| e.attrs.get("value")).filter_map(|v| mechanism_from_name(v)) {
                if !mechanisms.contains(&ty) { return Err(format!("mechanism 0x{ty:x} not returned by C_GetMechanismList")); }
            }
            Ok(())
        }
        Pending::Session(rv, session) => { verify_rv(rv, step)?; state.sessions.push(session); state.vars.insert("${Session}".to_owned(), session.to_string()); Ok(()) }
        Pending::Objects(rv, objects) => { verify_rv(rv, step)?; state.objects = objects; bind_object_vars(state); Ok(()) }
        Pending::Signature(rv) => verify_rv(rv, step),
        Pending::None => Err(format!("{} has no pending call result", step.name)),
    }
}

unsafe fn zeroed<T>() -> T { std::mem::zeroed() }

fn execute_get_slot_list(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        let token_present = if child_value(step, "TokenPresent").as_deref() == Some("false") { 0 } else { CK_TRUE };
        let mut count = slot_list_len(step, state).unwrap_or(0);
        if count == 0 {
            let rv = dispatch.get_slot_list(token_present, ptr::null_mut(), &mut count);
            Ok(Pending::Count(rv, count))
        } else {
            let mut slots = vec![0; count as usize];
            let rv = dispatch.get_slot_list(token_present, slots.as_mut_ptr(), &mut count);
            slots.truncate(count as usize);
            Ok(Pending::Slots(rv, slots))
        }
    }
}

fn execute_get_mechanism_list(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        let mut count = mechanism_list_len(step, state).unwrap_or(0);
        if count == 0 {
            let rv = dispatch.get_mechanism_list(resolve_slot(step, state)?, ptr::null_mut(), &mut count);
            Ok(Pending::Count(rv, count))
        } else {
            let mut mechanisms = vec![0; count as usize];
            let rv = dispatch.get_mechanism_list(resolve_slot(step, state)?, mechanisms.as_mut_ptr(), &mut count);
            mechanisms.truncate(count as usize);
            Ok(Pending::Mechanisms(rv, mechanisms))
        }
    }
}

fn execute_find_objects(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        let max_count = child(step, "Object").and_then(|e| e.attrs.get("length")).and_then(|s| resolve_value(s, state).parse::<CK_ULONG>().ok()).unwrap_or(1);
        let mut objects = vec![0; max_count as usize];
        let mut count = 0;
        let rv = dispatch.find_objects(resolve_session(step, state)?, objects.as_mut_ptr(), max_count, &mut count);
        objects.truncate(count as usize);
        Ok(Pending::Objects(rv, objects))
    }
}

fn execute_get_attribute_value(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        let session = resolve_session(step, state)?;
        let object = state
            .objects
            .first()
            .copied()
            .ok_or_else(|| "no object available".to_owned())?;
        let mut attrs = build_attribute_queries(step)?;
        let rv = dispatch.get_attribute_value(session, object, attrs.as_mut_ptr(), attrs.len() as CK_ULONG);
        if rv != CKR_OK {
            return Ok(Pending::Attributes(rv));
        }

        let mut values = attrs
            .iter()
            .map(|attr| vec![0; attr.ul_value_len as usize])
            .collect::<Vec<_>>();
        for (attr, value) in attrs.iter_mut().zip(values.iter_mut()) {
            attr.p_value = if value.is_empty() {
                ptr::null_mut()
            } else {
                value.as_mut_ptr() as CK_VOID_PTR
            };
        }
        let rv = dispatch.get_attribute_value(session, object, attrs.as_mut_ptr(), attrs.len() as CK_ULONG);
        Ok(Pending::Attributes(rv))
    }
}

fn execute_sign(dispatch: &Dispatch, step: &Step, state: &mut State) -> Result<Pending, String> {
    unsafe {
        let mut data = hex_to_bytes(&child_value(step, "Data").unwrap_or_default())?;
        let mut length = child(step, "Signature").and_then(|e| e.attrs.get("length")).and_then(|s| resolve_value(s, state).parse::<CK_ULONG>().ok()).unwrap_or(0);
        let mut signature = if length == 0 { Vec::new() } else { vec![0; length as usize] };
        let rv = dispatch.sign(resolve_session(step, state)?, data.as_mut_ptr(), data.len() as CK_ULONG, if signature.is_empty() { ptr::null_mut() } else { signature.as_mut_ptr() }, &mut length);
        Ok(Pending::Signature(rv))
    }
}

fn bind_count(step: &Step, state: &mut State, count: CK_ULONG) {
    if step.name == "C_GetSlotList" { state.vars.insert("${SlotList.length}".to_owned(), count.to_string()); }
    if step.name == "C_GetMechanismList" { state.vars.insert("${MechanismList.length}".to_owned(), count.to_string()); }
}
fn bind_slot_vars(state: &mut State) {
    state.vars.insert("${SlotList.length}".to_owned(), state.slots.len().to_string());
    if let Some(slot) = state.slots.first() { state.vars.insert("${SlotList.SlotID[0]}".to_owned(), slot.to_string()); }
}
fn bind_object_vars(state: &mut State) {
    for (i, object) in state.objects.iter().enumerate() { state.vars.insert(format!("${{Object.Object[{i}]}}"), object.to_string()); }
}

fn children<'a>(step: &'a Step, name: &str) -> Vec<&'a Element> { step.elements.iter().filter(|e| e.name == name).collect() }
fn child<'a>(step: &'a Step, name: &str) -> Option<&'a Element> { step.elements.iter().find(|e| e.name == name) }
fn child_value(step: &Step, name: &str) -> Option<String> { child(step, name).and_then(|e| e.attrs.get("value").cloned()) }
fn attr_u8(element: &Element, name: &str, default: u8) -> Result<u8, String> { Ok(element.attrs.get(name).map(|s| s.parse::<u8>()).transpose().map_err(|err| err.to_string())?.unwrap_or(default)) }

fn resolve_value(value: &str, state: &State) -> String {
    if let Some(resolved) = state.vars.get(value) {
        return resolved.clone();
    }
    if value.starts_with("${") && value.ends_with('}') {
        let env_name = &value[2..value.len() - 1];
        if let Ok(resolved) = env::var(env_name) {
            return resolved;
        }
    }
    value.to_owned()
}
fn slot_list_len(step: &Step, state: &State) -> Option<CK_ULONG> { child(step, "SlotList").and_then(|e| e.attrs.get("length")).and_then(|s| resolve_value(s, state).parse().ok()) }
fn mechanism_list_len(step: &Step, state: &State) -> Option<CK_ULONG> { child(step, "MechanismList").and_then(|e| e.attrs.get("length")).and_then(|s| resolve_value(s, state).parse().ok()) }
fn resolve_slot(step: &Step, state: &State) -> Result<CK_SLOT_ID, String> {
    child_value(step, "SlotID")
        .map(|v| {
            let resolved = resolve_value(&v, state);
            resolved.parse::<CK_SLOT_ID>().map_err(|e| format!("invalid SlotID {resolved}: {e}"))
        })
        .unwrap_or_else(|| state.slots.first().copied().ok_or_else(|| "no slot available".to_owned()))
}
fn resolve_session(step: &Step, state: &State) -> Result<CK_SESSION_HANDLE, String> {
    child_value(step, "Session")
        .map(|v| {
            let resolved = resolve_value(&v, state);
            resolved.parse::<CK_SESSION_HANDLE>().map_err(|e| format!("invalid Session {resolved}: {e}"))
        })
        .unwrap_or_else(|| state.sessions.first().copied().ok_or_else(|| "no session available".to_owned()))
}
fn resolve_object(step: &Step, state: &State) -> Result<CK_OBJECT_HANDLE, String> {
    child_value(step, "Object")
        .map(|v| {
            let resolved = resolve_value(&v, state);
            resolved.parse::<CK_OBJECT_HANDLE>().map_err(|e| format!("invalid Object {resolved}: {e}"))
        })
        .unwrap_or_else(|| state.objects.first().copied().ok_or_else(|| "no object available".to_owned()))
}
fn resolve_key(step: &Step, state: &State) -> Result<CK_OBJECT_HANDLE, String> {
    child_value(step, "Key")
        .map(|v| {
            let resolved = resolve_value(&v, state);
            resolved.parse::<CK_OBJECT_HANDLE>().map_err(|e| format!("invalid Key {resolved}: {e}"))
        })
        .unwrap_or_else(|| resolve_object(step, state))
}

fn child_flags(step: &Step) -> CK_FLAGS {
    let flags = child_value(step, "Flags").unwrap_or_default();
    let mut out = 0;
    if flags.contains("RW_SESSION") { out |= CKF_RW_SESSION; }
    if flags.contains("SERIAL_SESSION") { out |= CKF_SERIAL_SESSION; }
    out
}

fn child_type(step: &Step) -> Result<CK_MECHANISM_TYPE, String> {
    child_value(step, "Type").and_then(|v| mechanism_from_name(&v)).ok_or_else(|| format!("missing or unsupported mechanism Type in {}", step.name))
}

fn mechanism_from_name(name: &str) -> Option<CK_MECHANISM_TYPE> {
    match name {
        "RSA_PKCS_KEY_PAIR_GEN" => Some(CKM_RSA_PKCS_KEY_PAIR_GEN),
        "RSA_PKCS" => Some(CKM_RSA_PKCS),
        "SHA256_RSA_PKCS" => Some(CKM_SHA256_RSA_PKCS),
        "SHA512" => Some(CKM_SHA512),
        _ => None,
    }
}

fn build_find_attributes(step: &Step, values: &mut Vec<Vec<u8>>) -> Result<Vec<CK_ATTRIBUTE>, String> {
    let mut attrs = Vec::new();
    for element in children(step, "Attribute") {
        let type_name = element.attrs.get("type").ok_or_else(|| "Attribute without type".to_owned())?;
        if type_name == "LABEL" {
            continue;
        }
        let type_ = attribute_type(type_name)?;
        let mut value = match element.attrs.get("value") {
            Some(v) => attribute_value(type_name, v)?,
            None => vec![0; element.attrs.get("length").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0)],
        };
        let ptr = if value.is_empty() { ptr::null_mut() } else { value.as_mut_ptr() as CK_VOID_PTR };
        let len = value.len() as CK_ULONG;
        values.push(value);
        attrs.push(CK_ATTRIBUTE { type_, p_value: ptr, ul_value_len: len });
    }
    Ok(attrs)
}

fn build_attribute_queries(step: &Step) -> Result<Vec<CK_ATTRIBUTE>, String> {
    let mut attrs = Vec::new();
    for element in children(step, "Attribute") {
        let type_name = element.attrs.get("type").ok_or_else(|| "Attribute without type".to_owned())?;
        attrs.push(CK_ATTRIBUTE {
            type_: attribute_type(type_name)?,
            p_value: ptr::null_mut(),
            ul_value_len: 0,
        });
    }
    Ok(attrs)
}

fn attribute_type(name: &str) -> Result<CK_ULONG, String> {
    match name {
        "CLASS" => Ok(CKA_CLASS),
        "TOKEN" => Ok(CKA_TOKEN),
        "LABEL" => Ok(CKA_LABEL),
        "VALUE" => Ok(CKA_VALUE),
        "MODULUS" => Ok(CKA_MODULUS),
        "PUBLIC_EXPONENT" => Ok(CKA_PUBLIC_EXPONENT),
        _ => Err(format!("unsupported attribute type {name}")),
    }
}

fn attribute_value(type_name: &str, value: &str) -> Result<Vec<u8>, String> {
    match type_name {
        "CLASS" => ulong_bytes(match value { "PUBLIC_KEY" => CKO_PUBLIC_KEY, "PRIVATE_KEY" => CKO_PRIVATE_KEY, _ => value.parse::<CK_ULONG>().map_err(|e| e.to_string())? }),
        "TOKEN" => Ok(vec![if value == "TRUE" { CK_TRUE } else { 0 }]),
        "LABEL" => Ok(value.as_bytes().to_vec()),
        "VALUE" | "MODULUS" | "PUBLIC_EXPONENT" => hex_to_bytes(value),
        _ => Err(format!("unsupported attribute value type {type_name}")),
    }
}

fn ulong_bytes(value: CK_ULONG) -> Result<Vec<u8>, String> { Ok(value.to_ne_bytes().to_vec()) }

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("hex string has odd length".to_owned()); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}
