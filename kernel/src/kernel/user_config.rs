//! RETROOS.INI user preferences and network mounts.
use alloc::{string::{String, ToString}, vec::Vec};
use super::mount_config::{Access, canonical};
#[derive(Clone)]
pub struct SmbMount {
    pub drive: Option<u8>,
    pub server: [u8; 4],
    pub port: u16,
    pub share: String,
    pub path: String,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub access: Access,
    pub subdir: String,
}
impl core::fmt::Debug for SmbMount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SmbMount").field("path", &self.path).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub dos_scaling: Option<crate::kernel::display::DosScaling>,
    pub wifi: Option<crate::kernel::wifi::config::Profile>,
    pub smb: Vec<SmbMount>,
    pub environment: Vec<u8>,
    pub linux_environment: Vec<u8>,
    pub launch: Vec<(String, String)>,
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        macro_rules! unknown {
            ($message:literal) => {{
                crate::compact_println!("RETROOS.INI: {}; ignoring entry", $message);
                continue;
            }};
        }
        let mut config = Self::default();
        for group in ini::parse(bytes)? {
            let section = group.name;
            if section == "bundle" || section == "session" || section.starts_with("mount ") {
                return Err("bundle, mounts and session home belong in BOOT.INI");
            }
            if section == "wifi" {
                if config.wifi.is_some() {
                    return Err("duplicate Wi-Fi section");
                }
                config.wifi = Some(crate::kernel::wifi::config::Profile::default());
            } else if section == "smb" {
                if config.smb.len() >= 8 { return Err("too many SMB mounts"); }
                config.smb.push(SmbMount { drive: None, server: [0;4], port: 445, share: String::new(), path: String::new(),
                    username: String::new(), password: String::new(), domain: String::new(), access: Access::Rw, subdir: "/".into() });
            }
            if !section.eq_ignore_ascii_case("launch") && !matches!(section,
                "wifi" | "smb" | "display" | "system" | "locale" | "clock" | "sound" | "environment" | "linux.environment") {
                crate::compact_println!("RETROOS.INI: unknown section [{}]; ignoring it", section);
                continue;
            }
            for entry in group.entries {
                let (key, value, line) = (entry.key, entry.value, entry.source);
                if section == "linux.environment" {
                    let name = key.as_bytes();
                    if !name[0].is_ascii_alphabetic() && name[0] != b'_' || name.iter().any(|b| !b.is_ascii_alphanumeric() && *b != b'_') {
                        return Err("invalid Linux environment name");
                    }
                    if config.linux_environment.len() + key.len() + value.len() + 2 > 32768 {
                        return Err("Linux environment too large");
                    }
                    config.linux_environment.extend_from_slice(key.as_bytes());
                    config.linux_environment.push(b'=');
                    config.linux_environment.extend_from_slice(value.as_bytes());
                    config.linux_environment.push(0);
                } else if section == "wifi" {
                    let profile=config.wifi.as_mut().ok_or("missing Wi-Fi section")?;
                    match key {
                        "ssid"=>{if !profile.ssid.is_empty() {return Err("duplicate Wi-Fi SSID");}profile.ssid=value.as_bytes().to_vec();},
                        "password"=>{if !profile.password.is_empty() {return Err("duplicate Wi-Fi password");}profile.password=zeroize::Zeroizing::new(value.as_bytes().to_vec());},
                        "autoconnect"=>profile.auto_connect=match value {"true"|"yes"|"1"=>true,"false"|"no"|"0"=>false,_=>return Err("Wi-Fi autoconnect must be true or false")},
                        _=>unknown!("unknown Wi-Fi setting"),
                    }
                } else if section == "smb" {
                    let mount = config.smb.last_mut().ok_or("missing SMB section")?;
                    match key {
                        "drive" => {
                            let bytes = value.as_bytes();
                            if bytes.len() != 1 || !(b'E'..=b'L').contains(&bytes[0].to_ascii_uppercase()) {
                                return Err("SMB drive must be E through L");
                            }
                            mount.drive = Some(bytes[0].to_ascii_uppercase());
                        }
                        "server" => {
                            let octets: Vec<_> = value.split('.').map(|v| v.parse::<u8>()).collect();
                            if octets.len()!=4 || octets.iter().any(|v|v.is_err()) { return Err("SMB server must be IPv4"); }
                            for (i,octet) in octets.into_iter().enumerate() { mount.server[i] = octet.unwrap(); }
                        }
                        "port" => mount.port = value.parse().map_err(|_|"invalid SMB port")?,
                        "share" => mount.share = value.into(), "path" => mount.path = value.into(),
                        "username" => mount.username = value.into(), "password" => mount.password = value.into(),
                        "access" => mount.access = match value {
                            "ro" => Access::Ro, "rw" => Access::Rw,
                            _ => return Err("SMB access must be ro or rw"),
                        },
                        "subdir" => mount.subdir = value.into(),
                        "domain" => mount.domain = value.into(), _ => unknown!("unknown SMB key"),
                    }
                } else if section == "display" {
                    if key != "scaling" { unknown!("unknown display setting"); }
                    use crate::kernel::display::DosScaling;
                    config.dos_scaling = Some(match value {
                        "original_aspect" => DosScaling::OriginalAspect,
                        "fill_screen" => DosScaling::FillScreen,
                        "sharp_pixels" => DosScaling::SharpPixels,
                        "square_pixels" => DosScaling::SquarePixels,
                        _ => return Err("invalid display scaling mode"),
                    });
                } else if section.eq_ignore_ascii_case("launch") {
                    if key.len() >= 16 || key.contains([' ', '\t', '/', '\\', ':']) {
                        return Err("launch key must be a DOS basename under 16 bytes");
                    }
                    if line.len() > 78 {
                        return Err("launch entry too long");
                    }
                    if value.split_ascii_whitespace().any(|flag|
                        !["loadfix", "dos32a", "repair", "iopl3", "xms32k"]
                            .iter().any(|known| flag.eq_ignore_ascii_case(known))
                        && !(flag.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("cpu"))
                            && flag[3..].bytes().all(|b| b.is_ascii_digit())
                            && flag[3..].parse::<u8>().is_ok_and(|n| (5..=100).contains(&n) && n % 5 == 0))) {
                        return Err("unknown launch flag");
                    }
                    config.launch.push((key.to_string(), value.to_string()));
                } else {
                    let key = match (section, key) {
                        ("system", "start") => "START".to_string(),
                        ("locale", "language") => "LOCALE".to_string(),
                        ("locale", "keyboard") => "KEYBOARD".to_string(),
                        ("locale", "codepage") => "CODEPAGE".to_string(),
                        ("clock", "rtc") => "RTC".to_string(),
                        ("clock", "utc_offset") => "UTC_OFFSET".to_string(),
                        ("sound", "sb_audio") => "SB_AUDIO".to_string(),
                        ("sound", "hda_output") => "HDA_OUTPUT".to_string(),
                        ("sound", "volume") => "AUDIO_VOLUME".to_string(),
                        ("environment", _) => key.to_ascii_uppercase(),
                        _ => unknown!("unknown setting"),
                    };
                    config.environment.extend_from_slice(key.as_bytes());
                    config.environment.push(b'=');
                    config.environment.extend_from_slice(value.as_bytes());
                    config.environment.push(0);
                }
            }
        }
        for (i, mount) in config.smb.iter().enumerate() {
            if mount.server == [0; 4] || mount.port == 0
                || mount.username.is_empty() || mount.share.is_empty()
                || mount.share.contains(['/', '\\', ':'])
                || !canonical(&mount.path) || !canonical(&mount.subdir) || mount.path == "/" && mount.access != Access::Ro
                || config.smb[..i].iter().any(|s| s.path == mount.path
                    || mount.drive.is_some() && s.drive == mount.drive)
            {
                return Err("invalid SMB mount");
            }
        }
        config.environment.push(0);
        config.linux_environment.push(0);
        if let Some(profile) = &config.wifi { profile.validate()?; }
        Ok(config)
    }
}

#[cfg(test)]
mod smb_config_tests {
    use super::{Config, Access};
    const MOUNT: &str = "[smb]\nserver=10.0.2.2\nshare=data\nusername=retroos\npassword=secret-test-value\npath=/SMB\n";
    #[test]
    fn smb_credentials_stay_out_of_guest_environment_and_debug_output() {
        let c=Config::parse(MOUNT.as_bytes()).unwrap();
        assert_eq!(c.smb.len(),1); assert_eq!(c.smb[0].port,445);
        assert!(!c.environment.windows(6).any(|w|w==b"secret"));
        assert!(!alloc::format!("{:?}",c).contains("secret-test-value"));
        assert!(crate::kernel::mount_config::Config::parse_boot(MOUNT.as_bytes()).is_err());
    }
    #[test]
    fn smb_drive_letters_are_explicit_and_unique() {
        let config = [MOUNT, "drive=h\n"].concat();
        assert_eq!(Config::parse(config.as_bytes()).unwrap().smb[0].drive, Some(b'H'));
        for letter in ["A", "B", "C", "D", "M", "HH"] {
            assert!(Config::parse([MOUNT, "drive=", letter, "\n"].concat().as_bytes()).is_err());
        }
        let duplicate = [config.as_str(), &config.replace("path=/SMB", "path=/OTHER")].concat();
        assert!(Config::parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn smb_root_is_explicitly_readonly_and_data_keeps_its_access() {
        let root = MOUNT.replace("path=/SMB", "path=/");
        assert!(Config::parse(root.as_bytes()).is_err());
        let root = [root.as_str(), "access=ro\n"].concat();
        assert_eq!(Config::parse(root.as_bytes()).unwrap().smb[0].access, Access::Ro);
        assert_eq!(Config::parse(MOUNT.as_bytes()).unwrap().smb[0].access, Access::Rw);
        assert!(Config::parse([MOUNT, "access=ram\n"].concat().as_bytes()).is_err());
    }
    #[test]
    fn smb_subdirectory_views_require_canonical_paths() {
        let config = [MOUNT, "subdir=/home/retroos\n"].concat();
        assert_eq!(Config::parse(config.as_bytes()).unwrap().smb[0].subdir, "/home/retroos");
        assert!(Config::parse([MOUNT, "subdir=/home/../etc\n"].concat().as_bytes()).is_err());
    }
    #[test]
    fn smb_rejects_invalid_addresses_paths_and_duplicate_mounts() {
        for (old,new) in [("10.0.2.2","10.0.2.999"),("path=/SMB","path=/"),("path=/SMB","path=/net/../SMB"),("share=data","share=../data")] {
            assert!(Config::parse(MOUNT.replace(old,new).as_bytes()).is_err());
        }
        assert!(Config::parse([MOUNT,MOUNT].concat().as_bytes()).is_err());
    }
}

#[cfg(test)]
mod wifi_config_tests {
    use super::Config;
    const PROFILE:&[u8]=b"[wifi]\nssid=test-ap\npassword=private-test-pass\nautoconnect=true\n";
    #[test]
    fn wifi_boot_profile_is_private_and_not_storage_policy() {
        let c=Config::parse(PROFILE).unwrap();let p=c.wifi.as_ref().unwrap();
        assert_eq!(p.ssid,b"test-ap");assert!(p.auto_connect);
        assert!(!c.environment.windows(7).any(|b|b==b"private"));
        assert!(!alloc::format!("{c:?}").contains("private-test-pass"));
        assert!(crate::kernel::mount_config::Config::parse_boot(PROFILE).is_err());
        let disabled=Config::parse(b"[wifi]\nssid=test\npassword=password\nautoconnect=false\n").unwrap();
        assert!(!disabled.wifi.unwrap().auto_connect);
    }
    #[test]
    fn wifi_configuration_rejects_missing_duplicate_and_invalid_fields() {
        for bytes in [b"[wifi]\nssid=test\n".as_slice(), b"[wifi]\nssid=test\npassword=short\n", b"[wifi]\nssid=a\nssid=b\npassword=password\n",b"[wifi]\nssid=test\npassword=password\nautoconnect=maybe\n"] {
            assert!(Config::parse(bytes).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_user_settings_preserve_known_settings() {
        let config = Config::parse(b"[future]\nanything=value\n[display]\nfuture=value\nscaling=fill_screen\n[sound]\nfuture=value\nvolume=50\n").unwrap();
        assert_eq!(config.dos_scaling, Some(crate::kernel::display::DosScaling::FillScreen));
        assert!(config.environment.windows(15).any(|s| s == b"AUDIO_VOLUME=50"));
        assert!(crate::kernel::mount_config::Config::parse_boot(b"[bundle]\nsource=module\n[future]\nanything=value\n").is_err());
    }

    #[test]
    fn display_scaling_user_configuration() {
        use crate::kernel::display::DosScaling;
        for (value, mode) in [
            ("original_aspect", DosScaling::OriginalAspect),
            ("fill_screen", DosScaling::FillScreen),
            ("sharp_pixels", DosScaling::SharpPixels),
            ("square_pixels", DosScaling::SquarePixels),
        ] {
            let ini = alloc::format!("[display]\nscaling={value}\n");
            assert_eq!(Config::parse(ini.as_bytes()).unwrap().dos_scaling, Some(mode));
            let boot = alloc::format!("[bundle]\nsource=module\n{ini}");
            assert!(crate::kernel::mount_config::Config::parse_boot(boot.as_bytes()).is_err());
        }
        assert!(Config::parse(b"[display]\nscaling=invalid\n").is_err());
        assert!(Config::parse(b"[display]\nunknown=fill_screen\n").is_ok());
    }

    #[test]
    fn launch_cpu_percent_is_validated() {
        for flag in ["cpu5", "cpu25", "CPU100"] {
            let ini = alloc::format!("[launch]\nGAME.EXE=repair {}\n", flag);
            assert!(Config::parse(ini.as_bytes()).is_ok());
        }
        for flag in ["cpu", "cpu0", "cpu1", "cpu26", "cpu101", "cpu999999", "cpu+25", "cpu25x"] {
            let ini = alloc::format!("[launch]\nGAME.EXE={}\n", flag);
            assert!(Config::parse(ini.as_bytes()).is_err());
        }
    }

    #[test]
    fn linux_environment_is_separate_and_names_remain_case_sensitive() {
        let c = Config::parse(b"[environment]\nHOME=C:\\DOS\nPATH=C:\\\n[linux.environment]\nHOME=/home/user\nMixed_case=kept\nPATH=\n").unwrap();
        assert!(c.environment.starts_with(b"HOME=C:\\DOS\0"));
        assert!(!c.environment.windows(10).any(|w| w == b"Mixed_case"));
        assert_eq!(c.linux_environment, b"HOME=/home/user\0Mixed_case=kept\0PATH=\0\0");
        assert!(Config::parse(b"[linux.environment]\n1BAD=value\n").is_err());
        assert!(Config::parse(b"[linux.environment]\nBAD-NAME=value\n").is_err());
        assert!(crate::kernel::mount_config::Config::parse_boot(b"[bundle]\nsource=module\n[linux.environment]\nHOME=/home/user\n").is_err());
    }

    #[test]
    fn settings_become_personality_neutral_policy() {
        let c = Config::parse(
            b"[locale]\nlanguage=it-IT\nkeyboard=us\n[system]\nstart=C:\\DN\\DN.COM\n",
        )
        .unwrap();
        assert_eq!(
            c.environment,
            b"LOCALE=it-IT\0KEYBOARD=us\0START=C:\\DN\\DN.COM\0\0"
        );
        assert!(crate::kernel::mount_config::Config::parse(b"[mount \"bad\"]\nsource=UUID=ABCD-X234\npath=/\n").is_err());
    }

    #[test]
    fn clock_settings_are_user_policy() {
        let user = Config::parse(b"[clock]\nrtc=utc\nutc_offset=-07:00\n").unwrap();
        assert_eq!(user.environment, b"RTC=utc\0UTC_OFFSET=-07:00\0\0");
        assert!(crate::kernel::mount_config::Config::parse_boot(b"[bundle]\nsource=module\n[clock]\nrtc=utc\n").is_err());
        assert!(Config::parse(b"[clock]\ntimezone=invalid\n").is_ok());
    }

    #[test]
    fn launch_entries_are_not_limited_to_a_fixed_table() {
        let mut ini = String::from("[launch]\n");
        for i in 0..128 {
            ini.push_str(&alloc::format!("GAME{}.EXE=repair\n", i));
        }
        let config = Config::parse(ini.as_bytes()).unwrap();
        assert_eq!(config.launch.len(), 128);
        assert_eq!(config.launch[127], ("GAME127.EXE".into(), "repair".into()));
    }

    #[test]
    fn launch_overrides_are_preserved_separately_from_environment() {
        let c = Config::parse(
            b"[environment]\nHOME=C:\\MC\n[launch]\nDOOM.EXE=repair\nALADDIN.EXE=xms32k\nCHESS.EXE=\n[locale]\nlanguage=en-US\n",
        ).unwrap();
        assert_eq!(c.environment, b"HOME=C:\\MC\0LOCALE=en-US\0\0");
        assert_eq!(c.launch, alloc::vec![
            ("DOOM.EXE".to_string(), "repair".to_string()),
            ("ALADDIN.EXE".to_string(), "xms32k".to_string()),
            ("CHESS.EXE".to_string(), "".to_string()),
        ]);
        assert!(Config::parse(b"[launch]\nDOOM.EXE=typo\n").is_err());
        assert!(Config::parse(b"[launch]\nC:\\DOOM.EXE=repair\n").is_err());
    }    #[test]
    fn shipped_user_configuration() {
        Config::parse(include_bytes!(env!("RETROOS_TEST_INI"))).unwrap();
    }
}
