use std::{collections::HashMap, io::Cursor};

use mach_object::OFile;

use crate::emulated::nac::hooks::___stack_chk_guard;

use super::jelly::{Hook, Jelly};

fn load_binary() -> &'static [u8] {
    include_bytes!("IMDAppleServices")
}
fn get_x64_slice<'a>(binary: &'a [u8]) -> &'a [u8] {
    let mut cur = Cursor::new(binary);
    let OFile::FatFile { magic, files } = OFile::parse(&mut cur).unwrap() else {
        unreachable!();
    };
    let x64 = files
        .iter()
        .map(|(arch, _)| arch)
        .find(|arch| arch.cputype == mach_object::CPU_TYPE_X86_64)
        .unwrap();
    let (offset, size) = (x64.offset as usize, x64.size as usize);
    &binary[offset..(offset + size)]
}

fn load_nac() -> Jelly<'static> {
    let binary = get_x64_slice(load_binary());
    let hooks = {
        macro_rules! add_hook {
            ($hooks:ident, $name:ident) => {
                $hooks.insert(stringify!($name).into(), Box::new(hooks::$name));
            };
            ($hooks:ident, $name:ident, $($names:ident),*) => {
                add_hook!($hooks, $name);
                add_hook!($hooks, $($names),*);
            }
        }
        let mut hooks: HashMap<String, Box<dyn Hook>> = HashMap::new();
        add_hook!(
            hooks,
            _malloc,
            ___stack_chk_guard,
            ___memset_chk,
            _sysctlbyname,
            _memcpy,
            _kIOMasterPortDefault,
            _IORegistryEntryFromPath,
            _kCFAllocatorDefault,
            _IORegistryEntryCreateCFProperty,
            _CFGetTypeID,
            _CFStringGetTypeID,
            _CFDataGetTypeID,
            _CFDataGetLength,
            _CFDataGetBytes,
            _CFRelease,
            _IOObjectRelease,
            //_statfs_INODE64,
            _DASessionCreate,
            _DADiskCreateFromBSDName,
            _kDADiskDescriptionVolumeUUIDKey,
            _DADiskCopyDescription,
            _CFDictionaryGetValue,
            _CFUUIDCreateString,
            _CFStringGetLength,
            _CFStringGetMaximumSizeForEncoding,
            _CFStringGetCString,
            _free,
            _IOServiceMatching,
            _IOServiceGetMatchingService,
            _CFDictionaryCreateMutable,
            _kCFBooleanTrue,
            _CFDictionarySetValue,
            _IOServiceGetMatchingServices,
            _IOIteratorNext,
            ___bzero,
            _IORegistryEntryGetParentEntry,
            _arc4random
        );
        hooks.insert("_statfs$INODE64".into(), Box::new(hooks::_statfs_INODE64));
        hooks
    };
    let mut j = Jelly::new(binary);
    j.setup(hooks);
    j
}
pub fn generate_validation_data<'a>() -> &'a str {
    let binary = get_x64_slice(load_binary());
    "validation data"
}

#[test]
fn test() {
    let binary = load_binary();
    let x64_slice = get_x64_slice(binary);
}

mod hooks {
    #[derive(Deserialize)]
    struct AppleData {
        iokit: HashMap<String, plist::Value>,
        root_disk_uuid: String,
    }
    //const FAKE_DATA: AppleData = plist::from_bytes(include_bytes!("data.plist")).unwrap();
    fn fake_data() -> AppleData {
        plist::from_bytes(include_bytes!("data.plist")).unwrap()
    }
    macro_rules! count {
        () => (0usize);
        ($x:ident) => (1usize);
        ($x:ident, $($xs:ident),*) => { 1usize + count!($($xs),*) };
    }
    macro_rules! hook {
        ($name:ident, |$jelly:ident; $($args:ident),*| $body:block) => {
            #[allow(non_camel_case_types)]
            pub(crate) struct $name;
            impl Hook for $name {
                fn hook(&self, $jelly: &mut Jelly, args: &[u64]) -> u64 {
                    let [$($args),*] = *args else {
                        panic!("invalid number of arguments");
                    };
                    $body
                }
                fn args(&self) -> usize {
                    count!($($args),*)
                }
            }
        };
    }

    use std::collections::HashMap;

    use rand::random;
    use serde::Deserialize;

    use super::super::jelly::{CfObject, Hook, Jelly};

    hook!(_malloc, |jelly; size| { jelly.malloc(size) });
    hook!(___stack_chk_guard, |_jelly;| { 0 });
    hook!(___memset_chk, |jelly; dest, c, len, dest_len| {
        jelly
            .uc
            .mem_write(dest, &vec![c as u8; len as usize])
            .unwrap();
        0
    });
    hook!(_sysctlbyname, |_jelly; name, oldp, oldlenp, newp, newlen| { 0 });
    hook!(_memcpy, |jelly; dest, src, len| {
        let mut buf = vec![0; len as usize];
        jelly.uc.mem_read(src, &mut buf).unwrap();
        jelly.uc.mem_write(dest, &buf).unwrap();
        0
    });
    hook!(_kIOMasterPortDefault, |_jelly;| { 0 });
    hook!(_IORegistryEntryFromPath , |_jelly; _x| { 1 });
    hook!(_kCFAllocatorDefault , |_jelly;| { 0 });
    hook!(_IORegistryEntryCreateCFProperty, |jelly; entry, key, allocator, options| {
        let key_str = jelly.parse_cfstr_ptr(key);
        if let Some(fake) = fake_data().iokit.get(&key_str) {
            let fake = match fake.clone() {
                plist::Value::Data(fake) => CfObject::Data(fake),
                plist::Value::String(fake) => CfObject::String(fake),
                _ => unreachable!("compiled with invalid data.plist")
            };
            jelly.cf_objects.push(fake);
            jelly.cf_objects.len() as u64
        } else {
            0
        }
    });
    hook!(_CFGetTypeID, |jelly; obj| {
        let obj = jelly.cf_objects.get(obj as usize - 1).unwrap();
        return match obj {
            CfObject::Data(_) => 1,
            CfObject::String(_) => 2,
            _ => panic!("invalid object type")
        }
    });
    hook!(_CFStringGetTypeID, |_jelly;| {2});
    hook!(_CFDataGetTypeID, |_jelly;| {1});
    hook!(_CFDataGetLength, |jelly; obj| {
        let CfObject::Data(obj) = jelly.cf_objects.get(obj as usize - 1).unwrap() else {
            panic!("out of bounds read");
        };
        obj.len() as u64
    });
    hook!(_CFDataGetBytes, |jelly; obj, range_start, range_end, buf| {
        let CfObject::Data(obj) = jelly.cf_objects.get(obj as usize - 1).unwrap() else {
            panic!("out of bounds read");
        };
        let range_start = range_start as usize;
        let range_end = range_end as usize;
        let data = &obj[range_start..range_end];
        jelly.uc.mem_write(buf, data).unwrap();
        data.len() as u64
    });
    hook!(_CFRelease, |_jelly;| {0});
    hook!(_IOObjectRelease, |_jelly;| {0});
    hook!(_statfs_INODE64, |_jelly;| {0});
    hook!(_DASessionCreate, |_jelly;| {201});
    hook!(_DADiskCreateFromBSDName, |_jelly;| {202});
    hook!(_kDADiskDescriptionVolumeUUIDKey, |_jelly;| {0});
    hook!(_DADiskCopyDescription, |jelly;| {
        let description = cf_dictionary_create_mutable(jelly);
        let CfObject::Dictionary(d) = jelly.cf_objects.get_mut(description as usize - 1).unwrap() else {
            panic!("invalid object type")
        };
        d.insert("DADiskDescriptionVolumeUUIDKey".to_string(), CfObject::String(fake_data().root_disk_uuid.clone()));
        return description;
    });
    hook!(_CFDictionaryGetValue, |jelly; d, key| {
        let d = jelly.cf_objects.get(d as usize - 1).unwrap();
        let key = if key == 0xc3c3c3c3c3c3c3c3 {
            "DADiskDescriptionVolumeUUIDKey" // Weirdness, this is a hack: https://github.com/beeper/pypush/blob/35020e2a4a4d5fffdf799fc25472c63be3e171db/emulated/nac.py#L247C16-L247C46
        } else {
            let CfObject::String(key) = jelly.cf_objects.get(key as usize - 1).unwrap() else {
                panic!("invalid key");
            };
            key
        };
        let CfObject::Dictionary(d) = d else {
            panic!("invalid object type")
        };
        let Some(val) = d.get(key) else {
            panic!("key not found");
        };
        jelly.cf_objects.push(val.clone());
        return jelly.cf_objects.len() as u64;
    });
    hook!(_CFUUIDCreateString, |_jelly; _x, uuid| {uuid});
    hook!(_CFStringGetLength, |jelly; string| {
        let CfObject::String(string) = jelly.cf_objects.get(string as usize - 1).unwrap() else {
            panic!("invalid object type")
        };
        string.len() as u64
    });
    hook!(_CFStringGetMaximumSizeForEncoding, |_jelly; length, _x| {length});
    hook!(_CFStringGetCString, |jelly; string, buf, buf_len, encoding| {
        let CfObject::String(string) = jelly.cf_objects.get(string as usize - 1).unwrap() else {
            panic!("invalid object type")
        };
        let string = string.as_bytes();
        let string_len = string.len();
        let string_len = if string_len > buf_len as usize {
            buf_len as usize
        } else {
            string_len
        };
        jelly.uc.mem_write(buf, &string[..string_len]).unwrap();
        string_len as u64
    });
    hook!(_free, |_jelly;| {0});
    fn _parse_cstr_ptr(jelly: &mut Jelly, ptr: u64) -> String {
        let mut buf = [0u8; 256];
        let data = jelly.uc.mem_read(ptr, &mut buf).unwrap();
        String::from_utf8(buf.into()).unwrap()
    }
    hook!(_IOServiceMatching, |jelly; name| {
        // skipped a thing here, but I think it should still work
        let name = _parse_cstr_ptr(jelly, name);
        let dd = cf_dictionary_create_mutable(jelly);
        let CfObject::Dictionary(d) = jelly.cf_objects.get_mut(dd as usize - 1).unwrap() else {
            panic!("invalid object type")
        };
        d.insert("IOProviderClass".into(), CfObject::String(name));
        return dd;

    });
    hook!(_IOServiceGetMatchingService, |_jelly;| {92});

    fn cf_dictionary_create_mutable(jelly: &mut Jelly) -> u64 {
        jelly.cf_objects.push(CfObject::Dictionary(HashMap::new()));
        jelly.cf_objects.len() as u64
    }

    hook!(_CFDictionaryCreateMutable, |jelly;| {
        cf_dictionary_create_mutable(jelly)
    });
    hook!(_kCFBooleanTrue, |_jelly;| {0});

    hook!(_CFDictionarySetValue, |jelly; d, key, val| {
        let CfObject::String(key) = jelly.cf_objects.get(key as usize - 1).unwrap().clone() else {
            panic!("invalid key");
        };
        let val = jelly.cf_objects.get(val as usize - 1).unwrap().clone();
        let CfObject::Dictionary(d) = jelly.cf_objects.get_mut(d as usize - 1).unwrap() else {
            panic!("invalid object type")
        };
        d.insert(key.clone(), val.clone());
        0
    });
    hook!(_IOServiceGetMatchingServices, |jelly; port, r#match, existing| {
        jelly.eth_iterator_hack = true;
        jelly.uc.mem_write(existing, &[93]);
        0
    });
    hook!(_IOIteratorNext, |jelly; iterator| {
        if jelly.eth_iterator_hack {
            jelly.eth_iterator_hack = false;
            return 94;
        }
        0
    });
    hook!(___bzero, |jelly; ptr, len| {
        jelly.uc.mem_write(ptr, &vec![0; len as usize]);
        0
    });
    hook!(_IORegistryEntryGetParentEntry, |jelly; entry, _x, parent| {
        // yes, there is an another integer overflow (hack?) in pypush
        jelly.uc.mem_write(parent, &[entry as u8 + 100]);
        0
    });
    hook!(_arc4random, |_jelly;| {
        random::<u32>() as u64
    });
}
