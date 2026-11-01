//! Environment defaults and inheritance for Windows process startup.
use alloc::vec::Vec;

fn environment_separator(entry: &[u8]) -> Option<usize> {
    entry.iter().enumerate().skip(1).find_map(|(i, &byte)| (byte == b'=').then_some(i))
}

#[cfg(test)]
fn environment_value<'a>(environment: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    environment.split(|&byte| byte == 0)
        .take_while(|entry| !entry.is_empty())
        .find_map(|entry| {
            let eq = environment_separator(entry)?;
            entry[..eq].eq_ignore_ascii_case(key).then_some(&entry[eq + 1..])
        })
}

pub(super) fn windows_environment(inherited: &[u8]) -> Vec<u8> {
    let mut entries: Vec<Vec<u8>> = [
        b"COMSPEC=C:\\RETROOS\\COMMAND.COM".to_vec(),
        b"PATH=C:\\RETROOS\\WINDOWS\\SYSTEM32;C:\\RETROOS\\WINDOWS\\SYSTEM;C:\\RETROOS;C:\\".to_vec(),
        b"SystemRoot=C:\\RETROOS\\WINDOWS".to_vec(),
        b"windir=C:\\RETROOS\\WINDOWS".to_vec(),
        b"TEMP=C:\\TEMP".to_vec(),
    ].into();
    for entry in inherited.split(|&byte| byte == 0).take_while(|entry| !entry.is_empty()) {
        let Some(eq) = environment_separator(entry) else { continue };
        if let Some(old) = entries.iter().position(|old| old[..environment_separator(old).unwrap()]
            .eq_ignore_ascii_case(&entry[..eq])) {
            entries[old] = entry.to_vec();
        } else {
            entries.push(entry.to_vec());
        }
    }
    let mut out = Vec::new();
    for entry in entries {
        if out.len() + entry.len() + 2 > 4096 { break; }
        out.extend_from_slice(&entry);
        out.push(0);
    }
    out.push(0);
    out
}

#[cfg(test)]
mod environment_tests {
    use super::{environment_value, windows_environment};

    #[test]
    fn windows_process_receives_config_and_inherited_values() {
        let env = windows_environment(b"temp=D:\\SCRATCH\0MCHOME=C:\\MC\0HOME=D:\\USERMC\0\0");
        assert_eq!(environment_value(&env, b"TEMP"), Some(&b"D:\\SCRATCH"[..]));
        assert_eq!(environment_value(&env, b"MCHOME"), Some(&b"C:\\MC"[..]));
        assert_eq!(environment_value(&env, b"HOME"), Some(&b"D:\\USERMC"[..]));
        assert_eq!(environment_value(&env, b"COMSPEC"), Some(&b"C:\\RETROOS\\COMMAND.COM"[..]));
        assert!(env.ends_with(b"\0\0"));
    }

    #[test]
    fn inherited_hidden_drive_entries_have_distinct_names() {
        let env = windows_environment(b"=C:=C:\\one\0=D:=D:\\two\0=c:=C:\\three\0\0");
        assert_eq!(environment_value(&env, b"=C:"), Some(&b"C:\\three"[..]));
        assert_eq!(environment_value(&env, b"=d:"), Some(&b"D:\\two"[..]));
        assert_eq!(env.split(|&b| b == 0).filter(|entry| entry.starts_with(b"=c:") || entry.starts_with(b"=C:")).count(), 1);
        assert_eq!(environment_value(&env, b""), None);
    }

}
