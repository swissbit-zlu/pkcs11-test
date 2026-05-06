//println!("{:?}", pkcs11_result);
use cryptoki::context::Pkcs11;
use cryptoki::context::CInitializeArgs;
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::MechanismInfo;
use cryptoki::object::Attribute;
use cryptoki::object::AttributeType;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use cryptoki::slot::SlotInfo;
use quick_xml::events::Event;
use quick_xml::events::BytesStart;
use quick_xml::reader::Reader;
use cryptoki::context::Info;
use cryptoki::slot::TokenInfo;
use cryptoki::slot::Limit;
use std::any::Any;
use std::str::from_utf8;
use std::collections::HashMap;
use cryptoki::error::Result;
use cryptoki::object::ObjectHandle;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::object::ObjectClass;
use cryptoki_sys::{CKR_OK, CK_MECHANISM_TYPE, CK_ULONG};
use clap::Parser;
use std::cell::RefCell;
use std::env;
use std::mem;

static STRICT: bool = false;

#[derive(Default)]
struct TestSummary {
    pass: usize,
    fail: usize,
}

thread_local! {
    static TEST_SUMMARY: RefCell<TestSummary> = RefCell::new(TestSummary::default());
}

fn reset_test_summary() {
    TEST_SUMMARY.with(|summary| *summary.borrow_mut() = TestSummary::default());
}

fn report_status(status: &str) {
    TEST_SUMMARY.with(|summary| {
        let mut summary = summary.borrow_mut();
        match status {
            "PASS" => summary.pass += 1,
            "FAIL" => summary.fail += 1,
            _ => (),
        }
    });
    println!("{status}");
}

fn print_test_summary() {
    TEST_SUMMARY.with(|summary| {
        let summary = summary.borrow();
        println!("\nSUMMARY PASS={} FAIL={}", summary.pass, summary.fail);
    });
}

#[derive(Parser, Debug)]
/// Run PKCS#11 conformance tests
///
/// This program currently runs all mandatory conformance test cases from the PKCS#11 v3.1 profiles
/// (Baseline Provider BL-M-1-31, Extended Provider EXT-M-1-31, Authentication Token Provider
/// AUTH-M-1-31, Public Certificates Token Provider CERT-M-1-31)
///
/// See https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html for
/// reference
#[command(version, about)]
struct Args {
    /// filename of the PKCS#11 module
    #[arg(short, long)]
    module: String,

    /// test case (disables integrated tests)
    #[arg(num_args(0..))]
    tests: Option<Vec<String>>,
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| s.get(i..i + 2)
                      .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
            .collect()
    } else {
        None
    }
}

fn limit_to_string(l: &Limit) -> String {
    match l {
        Limit::Max(i) => i.to_string(),
        Limit::Infinite => "0".to_string(),
        Limit::Unavailable => "18446744073709551615".to_string()
    }
}

fn limit_matches(l: &Limit, s: &String) -> bool {
    limit_to_string(l) == *s
}

fn get_slot(slots: &Vec<Slot>, slot_id: &String, variables: &mut HashMap<String, String>) -> Option<Slot> {
    let actual_slotid = substitute_variable(slot_id, &"0".to_owned(), variables);
    for slot in slots {
        if actual_slotid == slot.id().to_string() {
            return Some(*slot);
        }
    }
    None
}

fn get_attribute(e: &BytesStart, key: &str, default: &str) -> String {
    if let Some(attribute) = e.try_get_attribute(key).unwrap() {
        from_utf8(&attribute.value).unwrap().to_owned()
    } else {
        default.to_owned()
    }
}

fn pkcs11_result_to_bytes(pkcs11_result: &Result<()>) -> &[u8] {
    match pkcs11_result {
        Ok(()) => "OK".as_bytes(),
        _ => "unknown error".as_bytes(),
    }
}

fn pkcs11_info_matches(pkcs11_result: &Result<Info>,
    rv: &String,
    cryptoki_version: &(String, String),
    manufacturer_id: &String,
    flags: &String,
    library_version: &(String, String),
    library_description: &String) -> bool {
    match pkcs11_result {
        Ok(info) => {
            if rv == "OK"
                && info.cryptoki_version().major() == cryptoki_version.0.parse::<u8>().unwrap()
                    && info.cryptoki_version().minor() == cryptoki_version.1.parse::<u8>().unwrap()
                    && flags == "0x0"
            {
                true
            } else {
                println!("  CryptokiVersion               {:?}.{:?} vs {:?}.{:?}", info.cryptoki_version().major(), info.cryptoki_version().minor(), cryptoki_version.0.parse::<u8>().unwrap(), cryptoki_version.1.parse::<u8>().unwrap());
                println!("  ManufacturerID (may vary)     {:?} vs {:?}", info.manufacturer_id(), manufacturer_id.trim());
                println!("  Flags                         {:?} vs {:?}", "0x0", flags);
                println!("  LibraryVersion (may vary)     {:?}.{:?} vs {:?}.{:?}", info.library_version().major(), info.library_version().minor(), library_version.0.parse::<u8>().unwrap(), library_version.1.parse::<u8>().unwrap());
                println!("  LibraryDescription (may vary) {:?} vs {:?}", info.library_description(), library_description.trim());
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn substitute_variable(value: &String, actual_value: &String, variables: &mut HashMap<String, String>) -> String {
    if value.starts_with('$') {
        // this is a variable

        // if not yet set, environment variables are used as default
        let var = &value[2..value.len()-1];
        let val = env::var(var);
        if val.is_ok() {
            variables.entry(value.to_owned()).or_insert(val.unwrap().to_owned());
        }

        // if still not set, `actual_value` is used as default
        variables.entry(value.to_owned()).or_insert(actual_value.to_owned());

        variables.get(value).unwrap().to_owned()
    } else {
        // value can stay as it is
        value.to_owned()
    }
}

fn pkcs11_slots_matches(pkcs11_result: &Result<Vec<Slot>>,
    rv: &String,
    slotlist_length: &String,
    slot_id: &Option<String>,
    variables: &mut HashMap<String, String>) -> bool {

    match pkcs11_result {
        Ok(slots) => {
            let actual_slotlist_length = substitute_variable(slotlist_length, &slots.len().to_string(), variables);
            if rv == "OK"
                && actual_slotlist_length == slots.len().to_string() {
                    if slots.len() == 0 || slot_id.is_none() {
                        true
                    } else {
                        let expected_slot_id = slot_id.as_ref().unwrap();
                        let actual_slotid = substitute_variable(expected_slot_id, &slots[0].id().to_string(), variables);
                        if actual_slotid == slots[0].id().to_string() {
                            true
                        } else {
                            println!("  SlotList length {:?} vs {:?} (SlotID doesn't match)", slots.len(), actual_slotlist_length);

                            false
                        }
                    }
            } else {
                println!("  SlotList length {:?} vs {:?}", slots.len(), actual_slotlist_length);

                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn get_raw_mechanism_list(module: &str, slot: Slot) -> std::result::Result<Vec<CK_MECHANISM_TYPE>, String> {
    unsafe {
        let pkcs11_lib = cryptoki_sys::Pkcs11::new(module).map_err(|err| err.to_string())?;
        let mut list = mem::MaybeUninit::uninit();
        let rv = pkcs11_lib.C_GetFunctionList(list.as_mut_ptr());
        if rv != CKR_OK {
            return Err(format!("C_GetFunctionList returned 0x{rv:x}"));
        }

        let function_list = *(*list.as_ptr());
        let get_mechanism_list = function_list
            .C_GetMechanismList
            .ok_or_else(|| "C_GetMechanismList function pointer is null".to_owned())?;

        let mut mechanism_count: CK_ULONG = 0;
        let rv = get_mechanism_list(slot.into(), std::ptr::null_mut(), &mut mechanism_count);
        if rv != CKR_OK {
            return Err(format!("C_GetMechanismList length query returned 0x{rv:x}"));
        }

        let mut mechanisms = vec![0; mechanism_count as usize];
        let rv = get_mechanism_list(slot.into(), mechanisms.as_mut_ptr(), &mut mechanism_count);
        if rv != CKR_OK {
            return Err(format!("C_GetMechanismList returned 0x{rv:x}"));
        }
        mechanisms.truncate(mechanism_count as usize);
        Ok(mechanisms)
    }
}

fn flag_matches(flag: bool, flag_string: &str, flags: &String) -> bool {
    if flags.contains(flag_string) {
        flag
    } else {
        /* Flag Type Representation 
           Each PKCS#11 flag value SHALL be represented using the uppercase C macro names with the
           type prefix omitted for each bit. If multiple bit flags are set then each SHALL be
           present separated by either a space (‘ ‘) or a pipe (‘|’) character.

           we assume that this means some flag is allowed to be true even if it is not caintained
           in flags.
        */
        true
    }
}

fn pkcs11_slot_info_matches(pkcs11_result: &Result<SlotInfo>,
    rv: &String,
    slot_description: &String,
    manufacturer_id: &String,
    flags: &String,
    hardware_version: &(String, String),
    firmware_version: &(String, String)) -> bool {

    match pkcs11_result {
        Ok(info) => {
            if rv == "OK"
                && flag_matches(info.token_present(), "TOKEN_PRESENT", flags)
                    && flag_matches(info.removable_device(), "REMOVABLE_DEVICE", flags)
                    && flag_matches(info.hardware_slot(), "HW_SLOT", flags) {
                true
            } else {
                let mut s = "".to_string();
                if info.token_present() { s += "TOKEN_PRESENT|"; }
                if info.removable_device() { s += "REMOVABLE_DEVICE|"; }
                if info.hardware_slot() { s += "HW_SLOT|"; }
                if !s.is_empty() {
                    // remove last "\"
                    s.pop();
                }
                println!("  SlotDescription (may vary)    {:?} vs {:?}", info.slot_description(), slot_description.trim());
                println!("  ManufacturerID (may vary)     {:?} vs {:?}", info.manufacturer_id(), manufacturer_id.trim());
                println!("  Flags                         {:?} vs {:?}", s, flags);
                println!("  HardwareVersion (may vary)     {:?}.{:?} vs {:?}.{:?}", info.hardware_version().major(), info.hardware_version().minor(), hardware_version.0.parse::<u8>().unwrap(), hardware_version.1.parse::<u8>().unwrap());
                println!("  FirmwareVersion (may vary)     {:?}.{:?} vs {:?}.{:?}", info.firmware_version().major(), info.firmware_version().minor(), firmware_version.0.parse::<u8>().unwrap(), firmware_version.1.parse::<u8>().unwrap());
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_token_info_matches(pkcs11_result: &Result<TokenInfo>,
    rv: &String,
    max_session_count: &String,
    session_count: &String,
    max_rw_session_count: &String,
    rw_session_count: &String,
    max_pin_len: &String,
    min_pin_len: &String,
    total_public_memory: &String,
    free_public_memory: &String,
    total_private_memory: &String,
    free_private_memory: &String,
    label: &String,
    model: &String,
    manufacturer_id: &String,
    serial_number: &String,
    flags: &String,
    hardware_version: &(String, String),
    firmware_version: &(String, String),
    utc_time: &String) -> bool {

    match pkcs11_result {
        Ok(info) => {
            if rv == "OK"
                && limit_matches(&info.max_session_count(), max_session_count)
                    && info.session_count().unwrap() == session_count.parse::<u64>().unwrap()
                    && limit_matches(&info.max_rw_session_count(), max_rw_session_count)
                    && info.rw_session_count().unwrap() == rw_session_count.parse::<u64>().unwrap()
                    && info.max_pin_length() == max_pin_len.parse::<usize>().unwrap()
                    && info.min_pin_length() == min_pin_len.parse::<usize>().unwrap()
                    && ((info.total_private_memory() == Some(total_private_memory.parse::<usize>().unwrap()))
                        || (info.total_private_memory() == None && total_private_memory.parse::<usize>().unwrap() == 0))
                    && ((info.free_private_memory() == Some(free_private_memory.parse::<usize>().unwrap()))
                        || (info.free_private_memory() == None && free_private_memory.parse::<usize>().unwrap() == 0))
                    && ((info.total_public_memory() == Some(total_public_memory.parse::<usize>().unwrap()))
                        || (info.total_public_memory() == None && total_public_memory.parse::<usize>().unwrap() == 0))
                    && ((info.free_public_memory() == Some(free_public_memory.parse::<usize>().unwrap()))
                        || (info.free_public_memory() == None && free_public_memory.parse::<usize>().unwrap() == 0))
                    && flag_matches(info.rng(), "RNG", flags)
                    && flag_matches(info.login_required(), "LOGIN_REQUIRED", flags)
                    && flag_matches(info.user_pin_initialized(), "USER_PIN_INITIALIZED", flags)
                    && flag_matches(info.restore_key_not_needed(), "RESTORE_KEY_NOT_NEEDED", flags)
                    && flag_matches(info.token_initialized(), "TOKEN_INITIALIZED", flags)
                    // FIXME add the other flags
            {
                true
            } else {
                let mut s = "".to_string();
                if info.rng() { s += "RNG"; }
                if info.login_required() { s += "LOGIN_REQUIRED|"; }
                if info.user_pin_initialized() { s += "USER_PIN_INITIALIZED|"; }
                if info.restore_key_not_needed() { s += "RESTORE_KEY_NOT_NEEDED|"; }
                if info.token_initialized() { s += "TOKEN_INITIALIZED|"; }
                if !s.is_empty() {
                    // remove last "\"
                    s.pop();
                }
                println!("  MaxSessionCount {:?} vs {:?}", limit_to_string(&info.max_session_count()), max_session_count);
                println!("  SessionCount {:?} vs {:?}", info.session_count().unwrap(), session_count.parse::<u64>().unwrap());
                println!("  MaxRwSessionCount {:?} vs {:?}", limit_to_string(&info.max_rw_session_count()), max_rw_session_count);
                println!("  RwSessionCount {:?} vs {:?}", info.rw_session_count().unwrap(), rw_session_count.parse::<u64>().unwrap());
                println!("  MaxPinLen {:?} vs {:?}", info.max_pin_length(), max_pin_len.parse::<usize>().unwrap());
                println!("  MinPinLen {:?} vs {:?}", info.min_pin_length(), min_pin_len.parse::<usize>().unwrap());
                println!("  TotalPrivateMemory {:?} vs {:?}", info.total_private_memory(), total_private_memory);
                println!("  FreePrivateMemory {:?} vs {:?}", info.free_private_memory(), free_private_memory);
                println!("  TotalPublicMemory {:?} vs {:?}", info.total_public_memory(), total_public_memory);
                println!("  FreePublicMemory {:?} vs {:?}", info.free_public_memory(), free_public_memory);
                println!("  label (may vary)     {:?} vs {:?}", info.label(), label.trim());
                println!("  ManufacturerID (may vary)     {:?} vs {:?}", info.manufacturer_id(), manufacturer_id.trim());
                println!("  model (may vary)     {:?} vs {:?}", info.model(), model.trim());
                println!("  serialNumber (may vary)     {:?} vs {:?}", info.serial_number(), serial_number.trim());
                println!("  Flags     {:?} vs {:?}", s, flags);
                println!("  HardwareVersion (may vary)     {:?}.{:?} vs {:?}.{:?}", info.hardware_version().major(), info.hardware_version().minor(), hardware_version.0.parse::<u8>().unwrap(), hardware_version.1.parse::<u8>().unwrap());
                println!("  FirmwareVersion (may vary)     {:?}.{:?} vs {:?}.{:?}", info.firmware_version().major(), info.firmware_version().minor(), firmware_version.0.parse::<u8>().unwrap(), firmware_version.1.parse::<u8>().unwrap());
                println!("  utcTime (may vary)     {:?} vs {:?}", info.utc_time(), utc_time.trim());
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_find_objects_matches(pkcs11_result: &Result<Vec<ObjectHandle>>,
    rv: &String,
    object_length: &String) -> bool {

    match pkcs11_result {
        Ok(objects) => {
            if rv == "OK"
                && ((STRICT && objects.len() == object_length.parse::<usize>().unwrap())
                    || (!STRICT && objects.len() >= object_length.parse::<usize>().unwrap()))
                {
                true
            } else {
                if STRICT {
                    println!("  Object length {:?} vs {:?}", objects.len(), object_length.parse::<usize>().unwrap());
                } else {
                    println!("  Object length {:?} >=? {:?}", objects.len(), object_length.parse::<usize>().unwrap());
                }
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_get_attributes_matches(pkcs11_result: &Result<Vec<Attribute>>,
    rv: &String,
    template: &Vec<Attribute>) -> bool {

    match pkcs11_result {
        Ok(attributes) => if rv == "OK" {
            for t_attr in template.iter() {
                let mut found = false;
                for r_attr in attributes {
                    if t_attr == r_attr {
                        found = true;
                        break;
                    }
                    if t_attr.type_id() == Attribute::PublicExponent.type_id() {
                        // may vary
                        found = true;
                        break;
                    }
                    if !STRICT && (t_attr.type_id() == r_attr.type_id()) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    println!("  {:?} not found in {:?}", t_attr, template);
                    return false;
                }
            }
            true
        } else {
            false
        },
        _ => {
            if rv == "OK" {
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_sign_matches(pkcs11_result: &Result<Vec<u8>>,
    rv: &String,
    signature: &String) -> bool {

    match pkcs11_result {
        Ok(s) => if rv == "OK" {
            let sig = hex_to_bytes(signature.as_str()).unwrap();
            if *s == sig {
                return true;
            }
            if !STRICT && (s.is_empty() == sig.is_empty()) {
                return true;
            }
            false
        } else {
            false
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_mechanism_list_matches(pkcs11_result: &std::result::Result<Vec<CK_MECHANISM_TYPE>, String>,
    rv: &String,
    mechanism: &Vec<Mechanism>) -> bool {

    match pkcs11_result {
        Ok(types) => {
            if rv == "OK"
            {
                for m in mechanism {
                    let mut found = false;
                    for t in types {
                        if CK_MECHANISM_TYPE::from(m.mechanism_type()) == *t {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        println!("  {:?} ({:?}) not found in {:?}", m.mechanism_type(), m, types);
                        return false;
                    }
                }
                true
            } else {
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn pkcs11_mechanism_info_matches(pkcs11_result: &Result<MechanismInfo>,
    rv: &String,
    min_key_size: &String,
    max_key_size: &String,
    flags: &String) -> bool {

    match pkcs11_result {
        Ok(info) => {
            if rv == "OK"
                && info.max_key_size() == max_key_size.parse::<usize>().unwrap()
                && info.min_key_size() == min_key_size.parse::<usize>().unwrap()
                && flag_matches(info.digest(), "DIGEST", flags)
                && flag_matches(info.generate_key_pair(), "GENERATE_KEY_PAIR", flags)
                && flag_matches(info.encrypt(), "ENCRYPT", flags)
                && flag_matches(info.decrypt(), "DECRYPT", flags)
                && flag_matches(info.sign(), "SIGN", flags)
                && flag_matches(info.verify(), "VERIFY", flags)
                && flag_matches(info.wrap(), "WRAP", flags)
                && flag_matches(info.unwrap(), "UNWRAP", flags)
            {
                true
            } else {
                let mut s = "".to_string();
                if info.digest() { s+= "DIGEST|";}
                if info.generate_key_pair() { s+= "GENERATE_KEY_PAIR|";}
                if info.encrypt() { s+= "ENCRYPT|";}
                if info.decrypt() { s+= "DECRYPT|";}
                if info.sign() { s+= "SIGN|";}
                if info.verify() { s+= "VERIFY|";}
                if info.wrap() { s+= "WRAP|";}
                if info.unwrap() { s+= "UNWRAP|";}
                if info.generate_key_pair() { s+= "GENERATE_KEY_PAIR|";}
                if info.encrypt() { s+= "ENCRYPT|";}
                if info.decrypt() { s+= "DECRYPT|";}
                if info.sign() { s+= "SIGN|";}
                if info.verify() { s+= "VERIFY|";}
                if info.wrap() { s+= "WRAP|";}
                if info.unwrap() { s+= "UNWRAP|";}
                if !s.is_empty() {
                    // remove last "\"
                    s.pop();
                }
                println!("  MaxKeySize {:?} vs {:?}", info.max_key_size(), max_key_size.parse::<usize>().unwrap());
                println!("  MinKeySize {:?} vs {:?}", info.min_key_size(), min_key_size.parse::<usize>().unwrap());
                println!("  Flags      {:?} vs {:?}", s, flags);
                false
            }
        },
        _ => {
            if rv == "OK" {
                println!("  {:?}", pkcs11_result);
                false
            } else {
                // FIXME check for the correct error
                true
            }
        }
    }
}

fn run_test(test_case: &str, module: &str) {
    let mut reader = Reader::from_str(test_case);

    let mut buf = Vec::new();
    let mut pkcs11 = Vec::new();
    let mut action = "";

    let mut rv = "OK".to_owned();
    let mut cryptoki_version = ("3".to_owned(), "1".to_owned());
    let mut flags = "0x0".to_owned();
    let mut manufacturer_id = "".to_owned();
    let mut library_version = ("1".to_owned(), "0".to_owned());
    let mut library_description = "".to_owned();

    let mut token_present = "true".to_owned();
    let mut variables: HashMap<String, String> = HashMap::new();
    let mut slots: Vec<Slot> = Vec::new();
    let mut slotlist_length = "1".to_owned();
    let mut slot_id: Option<String> = None;
    let mut slot_description = "".to_owned();
    let mut hardware_version = ("1".to_owned(), "0".to_owned());
    let mut firmware_version = ("1".to_owned(), "0".to_owned());

    let mut max_session_count = "0".to_owned();
    let mut session_count = "0".to_owned();
    let mut max_rw_session_count = "0".to_owned();
    let mut rw_session_count = "0".to_owned();
    let mut max_pin_len = "255".to_owned();
    let mut min_pin_len = "4".to_owned();
    let mut total_public_memory = "0".to_owned();
    let mut free_public_memory = "0".to_owned();
    let mut free_private_memory = "0".to_owned();
    let mut total_private_memory = "0".to_owned();
    let mut label = "".to_owned();
    let mut model = "".to_owned();
    let mut serial_number = "".to_owned();
    let mut utc_time = "".to_owned();

    let mut session: Vec<Session> = Vec::new();
    let mut template: Vec<Attribute> = Vec::new();
    let mut attribute_types: Vec<AttributeType> = Vec::new();
    let mut objects: Vec<ObjectHandle> = Vec::new();
    let mut object_length = "1".to_owned();
    let mut index = 0;

    let mut user_type = "".to_owned();
    let mut mechanism: Vec<cryptoki::mechanism::Mechanism> = Vec::new();
    let mut data = "".to_owned();
    let mut signature = "".to_owned();
    let mut max_key_size = "0".to_owned();
    let mut min_key_size = "0".to_owned();
    let mut pin = "".to_owned();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            // exits the loop when reaching end of file
            Ok(Event::Eof) => break,

            Ok(Event::Start(e)) => {
                print!("{}{}", "  ".repeat(index), from_utf8(e.name().as_ref()).unwrap());
                for a in e.attributes().flatten() {
                    print!(" {}={}", from_utf8(a.key.as_ref()).unwrap(), from_utf8(a.value.as_ref()).unwrap());
                }
                println!();
                index += 1;

                match e.name().as_ref() {
                    b"PKCS11" => {
                    },
                    b"C_GetInfo" => {
                            rv = get_attribute(&e, "rv", "OK");
                    },
                    b"C_GetSlotList" => {
                        if action == "C_GetSlotList result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_GetSlotList";
                        }
                    },
                    b"C_GetSlotInfo" => {
                        if action == "C_GetSlotInfo result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_GetSlotInfo";
                        }
                    },
                    b"C_GetTokenInfo" => {
                        if action == "C_GetTokenInfo result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_GetTokenInfo";
                        }
                    },
                    b"Info" => {
                        if action == "C_GetSlotInfo result" || action == "C_GetTokenInfo result" {
                            max_session_count = get_attribute(&e, "MaxSessionCount", "0");
                            session_count = get_attribute(&e, "SessionCount", "0");
                            max_rw_session_count = get_attribute(&e, "MaxRwSessionCount", "0");
                            rw_session_count = get_attribute(&e, "RwSessionCount", "0");
                            max_pin_len = get_attribute(&e, "MaxPinLen", "255");
                            min_pin_len = get_attribute(&e, "MinPinLen", "4");
                            total_public_memory = get_attribute(&e, "TotalPublicMemory", "0");
                            free_public_memory = get_attribute(&e, "FreePublicMemory", "0");
                            free_private_memory = get_attribute(&e, "FreePrivateMemory", "0");
                            total_private_memory = get_attribute(&e, "TotalPrivateMemory", "0");
                        } else if action == "C_GetMechanismInfo result" {
                            min_key_size = get_attribute(&e, "MinKeySize", "0");
                            max_key_size = get_attribute(&e, "MaxKeySize", "0");
                        }
                    },
                    b"C_OpenSession" => {
                        if action == "C_OpenSession result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_OpenSession";
                        }
                    },
                    b"C_FindObjectsInit" => {
                        action = "C_FindObjectsInit";
                    },
                    b"C_FindObjects" => {
                        if action == "C_FindObjects result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_FindObjects";
                        }
                    },
                    b"Template" => {
                        template = Vec::new();
                    },
                    b"C_CloseSession" => {
                        action = "C_CloseSession";
                    },
                    b"C_Login" => {
                        action = "C_Login";
                    },
                    b"C_Logout" => {
                        action = "C_Logout";
                    },
                    b"C_GetAttributeValue" => {
                        if action == "C_GetAttributeValue result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_GetAttributeValue";
                        }
                    },
                    b"C_Sign" => {
                        if action == "C_Sign result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_Sign";
                        }
                    },
                    b"C_GetMechanismList" => {
                        if action == "C_GetMechanismList result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            action = "C_GetMechanismList";
                        }
                    },
                    b"C_GetMechanismInfo" => {
                        if action == "C_GetMechanismInfo result" {
                            rv = get_attribute(&e, "rv", "OK");
                        } else {
                            mechanism = Vec::new();
                            action = "C_GetMechanismInfo";
                        }
                    },
                    b"Mechanism" => {
                        mechanism = Vec::new();
                    },
                    b"MechanismList" => {
                        mechanism = Vec::new();
                    },
                    _ => (),
                }
            }

            Ok(Event::Empty(e)) => {
                print!("{}{}", "  ".repeat(index), from_utf8(e.name().as_ref()).unwrap());
                for a in e.attributes().flatten() {
                    print!(" {}={}", from_utf8(a.key.as_ref()).unwrap(), from_utf8(a.value.as_ref()).unwrap());
                }
                println!();

                match e.name().as_ref() {
                    b"C_Initialize" => {
                        if action.is_empty() {
                            action = "C_Initialize";
                        } else {
                            // process response
                            let p11 = Pkcs11::new(module).unwrap();
                            let pkcs11_result = p11.initialize(CInitializeArgs::OsThreads);
                            pkcs11.push(p11);
                            if let Some(attribute) = e.try_get_attribute("rv").unwrap() {
                                if attribute.value != pkcs11_result_to_bytes(&pkcs11_result) {
                                    report_status("FAIL");
                                } else {
                                    report_status("PASS");
                                }
                            }
                            action = "";
                        }
                    },
                    b"C_GetInfo" => {
                        action = "C_GetInfo";
                    },
                    b"CryptokiVersion" => {
                        cryptoki_version = (get_attribute(&e, "major", "3"), get_attribute(&e, "minor", "1"));
                    },
                    b"Flags" => {
                        flags = get_attribute(&e, "value", "0x0");
                    },
                    b"ManufacturerID" => {
                        manufacturer_id = get_attribute(&e, "value", "");
                    },
                    b"LibraryVersion" => {
                        library_version = (get_attribute(&e, "major", "1"), get_attribute(&e, "minor", "0"));
                    },
                    b"LibraryDescription" => {
                        library_description = get_attribute(&e, "value", "");
                    },
                    b"TokenPresent" => {
                        token_present = get_attribute(&e, "value", "true");
                    },
                    b"SlotList" => {
                        slotlist_length = get_attribute(&e, "length", "1");
                        slot_id = None;
                    },
                    b"SlotID" => {
                        slot_id = Some(get_attribute(&e, "value", "0"));
                    },
                    b"SlotDescription" => {
                        slot_description = get_attribute(&e, "value", "");
                    },
                    b"HardwareVersion" => {
                        hardware_version = (get_attribute(&e, "major", "1"), get_attribute(&e, "minor", "0"));
                    },
                    b"FirmwareVersion" => {
                        firmware_version = (get_attribute(&e, "major", "1"), get_attribute(&e, "minor", "0"));
                    },
                    b"label" => {
                        label = get_attribute(&e, "value", "");
                    },
                    b"model" => {
                        model = get_attribute(&e, "value", "");
                    },
                    b"serialNumber" => {
                        serial_number = get_attribute(&e, "value", "");
                    },
                    b"utcTime" => {
                        utc_time = get_attribute(&e, "value", "");
                    },
                    b"Attribute" => {
                        let mut t = "".to_owned();
                        let mut v = "".to_owned();
                        if let Some(a) = e.try_get_attribute("type").unwrap() {
                            t = from_utf8(&a.value).unwrap().to_owned();
                        }
                        if let Some(a) = e.try_get_attribute("value").unwrap() {
                            v = from_utf8(&a.value).unwrap().to_owned();
                        }
                        if action == "C_GetAttributeValue" {
                            match t.as_str() {
                                "AC_ISSUER" => attribute_types.push(AttributeType::AcIssuer),
                                "ALLOWED_MECHANISM" => attribute_types.push(AttributeType::AllowedMechanisms),
                                "ALWAYS_AUTHENTICATE" => attribute_types.push(AttributeType::AlwaysAuthenticate),
                                "ALWAYS_SENSITIVE" => attribute_types.push(AttributeType::AlwaysSensitive),
                                "APPLICATION" => attribute_types.push(AttributeType::Application),
                                "ATTR_TYPES" => attribute_types.push(AttributeType::AttrTypes),
                                "BASE" => attribute_types.push(AttributeType::Base),
                                "CERTIFICATE_TYPE" => attribute_types.push(AttributeType::CertificateType),
                                "CHECK_VALUE" => attribute_types.push(AttributeType::CheckValue),
                                "CLASS" => attribute_types.push(AttributeType::Class),
                                "COEFFICIENT" => attribute_types.push(AttributeType::Coefficient),
                                "COPYABLE" => attribute_types.push(AttributeType::Copyable),
                                "DECRYPT" => attribute_types.push(AttributeType::Decrypt),
                                "DERIVE" => attribute_types.push(AttributeType::Derive),
                                "DESTROYABLE" => attribute_types.push(AttributeType::Destroyable),
                                "ECPARAMS" => attribute_types.push(AttributeType::EcParams),
                                "EC_POINT" => attribute_types.push(AttributeType::EcPoint),
                                "ENCRYPT" => attribute_types.push(AttributeType::Encrypt),
                                "END_DATE" => attribute_types.push(AttributeType::EndDate),
                                "EXPONENT1" => attribute_types.push(AttributeType::Exponent1),
                                "EXPONENT2" => attribute_types.push(AttributeType::Exponent2),
                                "EXTRACTABLE" => attribute_types.push(AttributeType::Extractable),
                                "HASH_OF_ISSUER_PUBLIC_KEY" => attribute_types.push(AttributeType::HashOfIssuerPublicKey),
                                "HASH_OF_SUBJECT_PUBLIC_KEY" => attribute_types.push(AttributeType::HashOfSubjectPublicKey),
                                "ID" => attribute_types.push(AttributeType::Id),
                                "ISSUER" => attribute_types.push(AttributeType::Issuer),
                                "KEY_GEN_MECHANISM" => attribute_types.push(AttributeType::KeyGenMechanism),
                                "KEY_TYPE" => attribute_types.push(AttributeType::KeyType),
                                "LABEL" => attribute_types.push(AttributeType::Label),
                                "LOCAL" => attribute_types.push(AttributeType::Local),
                                "MODIFIABLE" => attribute_types.push(AttributeType::Modifiable),
                                "MODULUS" => attribute_types.push(AttributeType::Modulus),
                                "MODULUS_BITS" => attribute_types.push(AttributeType::ModulusBits),
                                "NEVER_EXTRACTABLE" => attribute_types.push(AttributeType::NeverExtractable),
                                "OBJECT_ID" => attribute_types.push(AttributeType::ObjectId),
                                "OWNER" => attribute_types.push(AttributeType::Owner),
                                "PRIME" => attribute_types.push(AttributeType::Prime),
                                "PRIME1" => attribute_types.push(AttributeType::Prime1),
                                "PRIME2" => attribute_types.push(AttributeType::Prime2),
                                "PRIVATE" => attribute_types.push(AttributeType::Private),
                                "PRIVATE_EXPONENT" => attribute_types.push(AttributeType::PrivateExponent),
                                "PUBLIC_EXPONENT" => attribute_types.push(AttributeType::PublicExponent),
                                "PUBLIC_KEY_INFO" => attribute_types.push(AttributeType::PublicKeyInfo),
                                "SENSITIVE" => attribute_types.push(AttributeType::Sensitive),
                                "SERIAL_NUMBER" => attribute_types.push(AttributeType::SerialNumber),
                                "SIGN" => attribute_types.push(AttributeType::Sign),
                                "SIGN_RECOVER" => attribute_types.push(AttributeType::SignRecover),
                                "START_DATE" => attribute_types.push(AttributeType::StartDate),
                                "SUBJECT" => attribute_types.push(AttributeType::Subject),
                                "TOKEN" => attribute_types.push(AttributeType::Token),
                                "TRUSTED" => attribute_types.push(AttributeType::Trusted),
                                "UNWRAP" => attribute_types.push(AttributeType::Unwrap),
                                "URL" => attribute_types.push(AttributeType::Url),
                                "VALUE" => attribute_types.push(AttributeType::Value),
                                "VALUE_LEN" => attribute_types.push(AttributeType::ValueLen),
                                "VERIFY" => attribute_types.push(AttributeType::Verify),
                                "VERIFY_RECOVER" => attribute_types.push(AttributeType::VerifyRecover),
                                "WRAP" => attribute_types.push(AttributeType::Wrap),
                                "WRAP_WITH_TRUSTED" => attribute_types.push(AttributeType::WrapWithTrusted),
                                _ => (),
                            }
                        } else {
                            match t.as_str() {
                                "TOKEN" => match v.as_str() {
                                    "TRUE" => template.push(Attribute::Token(true)),
                                    "FALSE" => template.push(Attribute::Token(false)),
                                    _ => (),
                                },
                                "LABEL" => if STRICT {
                                    template.push(Attribute::Label(v.into_bytes()))
                                },
                                "CLASS" => match v.as_str() {
                                    "PUBLIC_KEY" => template.push(Attribute::Class(ObjectClass::PUBLIC_KEY)),
                                    "CERTIFICATE" => template.push(Attribute::Class(ObjectClass::CERTIFICATE)),
                                    "DATA" => template.push(Attribute::Class(ObjectClass::DATA)),
                                    "PRIVATE_KEY" => template.push(Attribute::Class(ObjectClass::PRIVATE_KEY)),
                                    "SECRET_KEY" => template.push(Attribute::Class(ObjectClass::SECRET_KEY)),
                                    "HARDWARE_FEATURE" => template.push(Attribute::Class(ObjectClass::HARDWARE_FEATURE)),
                                    "DOMAIN_PARAMETERS" => template.push(Attribute::Class(ObjectClass::DOMAIN_PARAMETERS)),
                                    "MECHANISM" => template.push(Attribute::Class(ObjectClass::MECHANISM)),
                                    "OTP_KEY" => template.push(Attribute::Class(ObjectClass::OTP_KEY)),
                                    _ => (),
                                },
                                "PUBLIC_EXPONENT" => {
                                    template.push(Attribute::PublicExponent(hex_to_bytes(v.as_str()).unwrap()));
                                },
                                "MODULUS" => {
                                    template.push(Attribute::Modulus(hex_to_bytes(v.as_str()).unwrap()));
                                },
                                _ => (),
                            }
                        }
                    },
                    b"Pin" => {
                        pin = get_attribute(&e, "value", "");
                    },
                    b"Object" => {
                        object_length = get_attribute(&e, "length", "1");
                    },
                    b"C_CloseSession" => {
                        rv = get_attribute(&e, "rv", "OK");
                        let mut status = "FAIL";
                        if !session.is_empty() {
                            session.pop().unwrap().close();
                            if rv == "OK" {
                                status = "PASS";
                            }
                        } else if rv != "OK" {
                            status = "PASS";
                        }
                        report_status(status);
                        action = "";
                    },
                    b"C_CloseAllSessions" => {
                        // process response
                        rv = get_attribute(&e, "rv", "OK");
                        let mut status = "FAIL";
                        // TODO iterate through session deleting all matching the slot
                        if session.is_empty() {
                            if rv == "OK" {
                                status = "PASS";
                            }
                        } else {
                            if rv != "OK" {
                                status = "PASS";
                            }
                        }
                        //if let Some(slot) = get_slot(&slots, &slot_id, &mut variables) {
                        //session.retain(|&s| s.get_session_info().unwrap().slot_id() != slot);
                        //println!("PASS");
                        //} else {
                        //println!("FAIL");
                        //}
                        report_status(status);
                        action = "";
                    },
                    b"C_Finalize" => {
                        if action.is_empty() {
                            action = "C_Finalize";
                        } else {
                            // process response
                            rv = get_attribute(&e, "rv", "OK");
                            let p11 = pkcs11.pop().unwrap();
                            p11.finalize();
                            if rv == "OK" {
                                report_status("PASS");
                            } else {
                                report_status("FAIL");
                            }
                            action = "";
                        }
                    },
                    b"C_Login" => {
                        // process response
                        let mut status = "FAIL";
                        let mut t = UserType::User;
                        let secret = AuthPin::new(substitute_variable(&pin, &pin, &mut variables));
                        match user_type.as_str() {
                            "USER" => t = UserType::User,
                            "SO" => t = UserType::So,
                            "CONTEXT_SPECIFIC" => t = UserType::ContextSpecific,
                            _ => (),
                        }
                        if !session.is_empty() {
                            let pkcs11_result = session[0].login(t, Some(&secret));
                            if let Some(attribute) = e.try_get_attribute("rv").unwrap() {
                                if attribute.value == pkcs11_result_to_bytes(&pkcs11_result) {
                                    status = "PASS";
                                }
                            }
                        }
                        report_status(status);
                        action = "";
                    },
                    b"C_Logout" => {
                        // process response
                        let mut status = "FAIL";
                        if !session.is_empty() {
                            let pkcs11_result = session[0].logout();
                            if let Some(attribute) = e.try_get_attribute("rv").unwrap() {
                                if attribute.value == pkcs11_result_to_bytes(&pkcs11_result) {
                                    status = "PASS";
                                }
                            }
                        }
                        report_status(status);
                        action = "";
                    },
                    b"Data" => {
                        data = get_attribute(&e, "value", "");
                    },
                    b"Signature" => {
                        signature = get_attribute(&e, "value", "");
                    },
                    b"UserType" => {
                        user_type = get_attribute(&e, "value", "");
                    },
                    b"Type" => {
                        if let Some(a) = e.try_get_attribute("value").unwrap() {
                            match from_utf8(&a.value).unwrap() {
                                // TODO add mechanisms that need parameters
                                "AES_KEY_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::AesKeyGen),
                                "AES_ECB" => mechanism.push(cryptoki::mechanism::Mechanism::AesEcb),
                                "AES_KEY_WRAP" => mechanism.push(cryptoki::mechanism::Mechanism::AesKeyWrap),
                                "AES_KEY_WRAP_PAD" => mechanism.push(cryptoki::mechanism::Mechanism::AesKeyWrapPad),
                                "RSA_PKCS_KEY_PAIR_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::RsaPkcsKeyPairGen),
                                "RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::RsaPkcs),
                                "RSA_X509" => mechanism.push(cryptoki::mechanism::Mechanism::RsaX509),
                                "DES_KEY_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::DesKeyGen),
                                "DES2_KEY_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::Des2KeyGen),
                                "DES3_KEY_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::Des3KeyGen),
                                "DES_ECB" => mechanism.push(cryptoki::mechanism::Mechanism::DesEcb),
                                "DES3_ECB" => mechanism.push(cryptoki::mechanism::Mechanism::Des3Ecb),
                                "ECC_KEY_PAIR_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::EccKeyPairGen),
                                "ECC_EDWARDS_KEY_PAIR_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::EccEdwardsKeyPairGen),
                                "ECC_MONTGOMERY_KEY_PAIR_GEN" => mechanism.push(cryptoki::mechanism::Mechanism::EccMontgomeryKeyPairGen),
                                "ECDSA" => mechanism.push(cryptoki::mechanism::Mechanism::Ecdsa),
                                "ECDSA_SHA1" => mechanism.push(cryptoki::mechanism::Mechanism::EcdsaSha1),
                                "ECDSA_SHA224" => mechanism.push(cryptoki::mechanism::Mechanism::EcdsaSha224),
                                "ECDSA_SHA256" => mechanism.push(cryptoki::mechanism::Mechanism::EcdsaSha256),
                                "ECDSA_SHA384" => mechanism.push(cryptoki::mechanism::Mechanism::EcdsaSha384),
                                "ECDSA_SHA512" => mechanism.push(cryptoki::mechanism::Mechanism::EcdsaSha512),
                                "EDDSA" => mechanism.push(cryptoki::mechanism::Mechanism::Eddsa),
                                "SHA1" => mechanism.push(cryptoki::mechanism::Mechanism::Sha1),
                                "SHA224" => mechanism.push(cryptoki::mechanism::Mechanism::Sha224),
                                "SHA256" => mechanism.push(cryptoki::mechanism::Mechanism::Sha256),
                                "SHA384" => mechanism.push(cryptoki::mechanism::Mechanism::Sha384),
                                "SHA512" => mechanism.push(cryptoki::mechanism::Mechanism::Sha512),
                                "SHA1_RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::Sha1RsaPkcs),
                                "SHA224_RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::Sha224RsaPkcs),
                                "SHA256_RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::Sha256RsaPkcs),
                                "SHA384_RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::Sha384RsaPkcs),
                                "SHA512_RSA_PKCS" => mechanism.push(cryptoki::mechanism::Mechanism::Sha512RsaPkcs),
                                _ => (),
                            }
                        }
                    },
                    _ => (),
                }
            }

            Ok(Event::End(e)) => {
                match e.name().as_ref() {
                    b"C_GetInfo" => {
                        let pkcs11_result = pkcs11[0].get_library_info();
                        if pkcs11_info_matches(&pkcs11_result, &rv,
                            &cryptoki_version, &manufacturer_id, &flags, &library_version,
                            &library_description) {
                            report_status("PASS");
                        } else {
                            report_status("FAIL");
                        }
                        action = "";
                    },
                    b"C_GetSlotList" => {
                        if action == "C_GetSlotList" {
                            action = "C_GetSlotList result";
                        } else {
                            if token_present == "true" {
                                let pkcs11_get_slotlist_result = pkcs11[0].get_slots_with_token();
                                if pkcs11_slots_matches(&pkcs11_get_slotlist_result, &rv, &slotlist_length, &slot_id, &mut variables) {
                                    slots = pkcs11_get_slotlist_result.unwrap();
                                    report_status("PASS");
                                } else {
                                    report_status("FAIL");
                                }
                            } else {
                                let pkcs11_result = pkcs11[0].get_all_slots();
                                if pkcs11_slots_matches(&pkcs11_result, &rv, &slotlist_length, &slot_id, &mut variables) {
                                    report_status("PASS");
                                } else {
                                    report_status("FAIL");
                                }
                            }
                            action = "";
                        }
                    },
                    b"C_GetSlotInfo" => {
                        if action == "C_GetSlotInfo" {
                            action = "C_GetSlotInfo result";
                        } else {
                            let mut status = "FAIL";
                            if let Some(slot) = get_slot(&slots, slot_id.as_ref().unwrap_or(&"0".to_owned()), &mut variables) {
                                let pkcs11_result = pkcs11[0].get_slot_info(slot);
                                if pkcs11_slot_info_matches(&pkcs11_result, &rv,
                                    &slot_description, &manufacturer_id, &flags,
                                    &hardware_version, &firmware_version) {
                                    status = "PASS";
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    b"C_GetTokenInfo" => {
                        if action == "C_GetTokenInfo" {
                            action = "C_GetTokenInfo result";
                        } else {
                            let mut status = "FAIL";
                            if let Some(slot) = get_slot(&slots, slot_id.as_ref().unwrap_or(&"0".to_owned()), &mut variables) {
                                let pkcs11_result = pkcs11[0].get_token_info(slot);
                                if pkcs11_token_info_matches(&pkcs11_result, &rv,
                                    &max_session_count,
                                    &session_count,&max_rw_session_count,
                                    &rw_session_count,
                                    &max_pin_len,
                                    &min_pin_len,
                                    &total_public_memory,
                                    &free_public_memory,
                                    &total_private_memory,
                                    &free_private_memory, &label, &model,
                                    &manufacturer_id,
                                    &serial_number, &flags, &hardware_version,
                                    &firmware_version, &utc_time) {
                                    status = "PASS";
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    b"C_OpenSession" => {
                        if action == "C_OpenSession" {
                            action = "C_OpenSession result";
                        } else if let Some(slot) = get_slot(&slots, slot_id.as_ref().unwrap_or(&"0".to_owned()), &mut variables) {
                            let mut status = "FAIL";
                            if flags.contains("RW_SESSION") {
                                let pkcs11_result = pkcs11[0].open_rw_session(slot);
                                if let Ok(s) = pkcs11_result {
                                    session.push(s);
                                    status = "PASS";
                                }
                            } else {
                                let pkcs11_result = pkcs11[0].open_ro_session(slot);
                                if let Ok(s) = pkcs11_result {
                                    session.push(s);
                                    status = "PASS";
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    b"C_FindObjectsInit" => {
                        objects = Vec::new();
                        action = "";
                    },
                    b"C_GetAttributeValue" => {
                        if action == "C_GetAttributeValue" {
                            action = "C_GetAttributeValue result";
                        } else {
                            if session.len() > 0 {
                                let pkcs11_result = session[0].get_attributes(
                                    objects[0], &attribute_types);
                                if pkcs11_get_attributes_matches(&pkcs11_result, &rv, &template) {
                                    report_status("PASS");
                                } else {
                                    report_status("FAIL");
                                }
                            } else {
                                report_status("FAIL");
                            }
                            action = "";
                        }
                    },
                    b"C_Sign" => {
                        if action == "C_Sign" {
                            action = "C_Sign result";
                        } else {
                            if session.len() > 0 {
                                let d = hex_to_bytes(data.as_str()).unwrap();
                                let pkcs11_result = session[0].sign(&mechanism[0], objects[0], &d);
                                if pkcs11_sign_matches(&pkcs11_result, &rv, &signature) {
                                    report_status("PASS");
                                } else {
                                    report_status("FAIL");
                                }
                            } else {
                                report_status("FAIL");
                            }
                            action = "";
                        }
                    },
                    b"C_FindObjects" => {
                        if action == "C_FindObjects" {
                            action = "C_FindObjects result";
                        } else {
                            let mut status = "FAIL";
                            if !session.is_empty() {
                                let pkcs11_result = session[0].find_objects(&template);
                                if pkcs11_find_objects_matches(&pkcs11_result, &rv, &object_length) {
                                    status = "PASS";
                                }
                                if pkcs11_result.is_ok() {
                                    objects = pkcs11_result.unwrap();
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    b"C_GetMechanismList" => {
                        if action == "C_GetMechanismList" {
                            action = "C_GetMechanismList result";
                        } else {
                            let mut status = "FAIL";
                            if let Some(slot) = get_slot(&slots, slot_id.as_ref().unwrap_or(&"0".to_owned()), &mut variables) {
                                let pkcs11_result = get_raw_mechanism_list(module, slot);
                                if pkcs11_mechanism_list_matches(&pkcs11_result, &rv, &mechanism) {
                                    status = "PASS";
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    b"C_GetMechanismInfo" => {
                        if action == "C_GetMechanismInfo" {
                            action = "C_GetMechanismInfo result";
                        } else {
                            let mut status = "FAIL";
                            if let Some(slot) = get_slot(&slots, slot_id.as_ref().unwrap_or(&"0".to_owned()), &mut variables) {
                                let pkcs11_result = pkcs11[0].get_mechanism_info(slot, mechanism[0].mechanism_type());
                                if pkcs11_mechanism_info_matches(&pkcs11_result, &rv, &min_key_size, &max_key_size, &flags) { status = "PASS";
                                }
                            }
                            report_status(status);
                            action = "";
                        }
                    },
                    _ => (),
                }
                index -= 1;
            }

            _ => (),
        }
        // if we don't keep a borrow elsewhere, we can clear the buffer to keep memory usage low
        buf.clear();
    }
}

fn main() {
    let args = Args::parse();

    reset_test_summary();

    if args.tests.is_some() {
        for test in args.tests.unwrap().into_iter() {
            println!("Starting test");
            println!("{:?}", test);
            run_test(std::fs::read_to_string(&test).unwrap().as_str(), &args.module);
        }
    } else {
        println!("Starting test");
        println!("BL-M-1-31.xml");
        const BL: &str = include_str!("test-cases/pkcs11-v3.1/mandatory/BL-M-1-31.xml");
        run_test(BL, &args.module);

        println!("\nStarting test");
        println!("AUTH-M-1-31.xml");
        const AUTH: &str = include_str!("test-cases/pkcs11-v3.1/mandatory/AUTH-M-1-31.xml");
        run_test(AUTH, &args.module);

        println!("\nStarting test");
        println!("AUTH-M-1-31.xml");
        const CERT: &str = include_str!("test-cases/pkcs11-v3.1/mandatory/CERT-M-1-31.xml");
        run_test(CERT, &args.module);

        println!("\nStarting test");
        println!("EXT-M-1-31.xml");
        const EXT: &str = include_str!("test-cases/pkcs11-v3.1/mandatory/EXT-M-1-31.xml");
        run_test(EXT, &args.module);
    }

    print_test_summary();
}
