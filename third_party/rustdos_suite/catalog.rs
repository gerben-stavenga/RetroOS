//! The games, where they come from, how they are installed, and what the
//! suite does with them.

use super::fetch::Archive;
use super::script::{Cond, Step, Step::*};
use super::{Game, Install, Scenario};

macro_rules! archive {
    ($file:expr, $url:expr, $sha:expr) => {
        Archive { file: $file, url: $url, sha256: $sha }
    };
}

const KEEN1: Archive = archive!(
    "keen1.zip",
    "https://archive.org/download/keen1-sw/keen1.zip",
    "a823802afb03ab3878122370de43ff25dd721df3da2538a4d54951787d63be10"
);
const DOOM: Archive = archive!(
    "doom19s.zip",
    "https://youfailit.net/pub/idgames/idstuff/doom/doom19s.zip",
    "cacf0142b31ca1af00796b4a0339e07992ac5f21bc3f81e7532fe1b5e1b486e6"
);
const HERETIC: Archive = archive!(
    "htic_v12.zip",
    "https://youfailit.net/pub/idgames/idstuff/heretic/htic_v12.zip",
    "5ffbb47e4a5750fef144c312973ee5782266b4a63474b77478103b6c1aaed39d"
);
const WOLF3D: Archive = archive!(
    "wolf3d14.zip",
    "https://maniacsvault.net/ecwolf/files/shareware/wolf3d14.zip",
    "23efc1839b9bd91de43fbd036e55aca94271293dd46d176dafd40378b2f94108"
);
const WOLF3D_ORIGINAL: Archive = archive!(
    "1wolf14.zip",
    "https://archive.org/download/mbcd9495/%231wolf14.zip",
    "3f03d5bf3d29974633f9146b8d5a68ccf545a08df847ccd3f37d84ce29989928"
);
const DUKE3D: Archive = archive!(
    "3dduke13.zip",
    "https://archive.org/download/3dduke13/3dduke13.zip",
    "c67efd179022bc6d9bde54f404c707cbcbdc15423c20be72e277bc2bdddf3d0e"
);
const DESCENT_1: Archive = archive!(
    "dcnt14-1.zip",
    "https://archive.org/download/mbcd9495/dcnt14-1.zip",
    "dfbb7d9e21f9580d49f3958212bc5853cb1d63334147b1f9c01bf6daad2677c4"
);
const DESCENT_2: Archive = archive!(
    "dcnt14-2.zip",
    "https://archive.org/download/mbcd9495/dcnt14-2.zip",
    "bbcb3ded1d053ee0e7f8a18aba929a226b5f12b319a4ab66993cacbc4357f2f8"
);
const RAPTOR: Archive = archive!(
    "1rap12.zip",
    "https://archive.org/download/mbcd9495/%231rap12.zip",
    "6fa845d483290c7ba42da600899f075a87f3bdeb73a1c98add4ce74bda7962fa"
);
const DUKE1: Archive = archive!(
    "1duke.zip",
    "https://archive.org/download/mbcd9495/%231duke.zip",
    "e5e24cb03f1654a1862c73540f481852cd9d747762263804e2e07cea5fd6c1d1"
);
const COSMO: Archive = archive!(
    "1cosmo.zip",
    "https://archive.org/download/mbcd9495/%231cosmo.zip",
    "6947fae305c0ebc2a5c5700576fb393790f80489ce6f586268886dadb01022cd"
);
const JILL: Archive = archive!(
    "jill.zip",
    "https://archive.org/download/JillOfTheJungle/jill.ZIP",
    "123ea8e7a485a98980a88031aa3acb6fd7f1edcfa04fcdf9882d1055f5648d10"
);
const ALLEYCAT: Archive = archive!(
    "alleycat.zip",
    "https://archive.org/download/msdos_Alley_Cat_1984/Alley_Cat_1984.zip",
    "7fadfa306416ce2a6b57da6d6fc44a3f11ee70180c50ab2f34e69b3c4e23bc09"
);
const DIGGER: Archive = archive!(
    "digger.zip",
    "https://archive.org/download/msdos_Digger_1983/Digger_1983.zip",
    "56f9175f869fdef5d98386fbf1d0ebee4d5a5a4a2b4fddd34623c4650a5ed2d1"
);
const SOPWITH: Archive = archive!(
    "sopwith.zip",
    "https://archive.org/download/msdos_Sopwith_1985/Sopwith_1985.zip",
    "eecc217462932d2fcecccbd7751c84c4df3bf38da8b2544d33fe6a000664eac4"
);
const ROGUE: Archive = archive!(
    "rogue.zip",
    "https://archive.org/download/msdos_Rogue_1983/Rogue_1983.zip",
    "1e1da7322963d92ad0a3968aad0263db2d0fa85575f150f6a537d7ad99fddd2a"
);
const SCORCH: Archive = archive!(
    "scorch15.zip",
    "https://archive.org/download/mbcd9495/scorch15.zip",
    "002117403b50071639e293a9005658e4a51c0b0740965fb157a03db38caca395"
);

/// id's De-ICE installer onto C: (into the folder it proposes), and the
/// self-extracting archive it leaves, then the setup program with the
/// title `setup` (left without changes) if there is one.
fn deice(setup: Option<&'static str>) -> Vec<Step> {
    let mut steps = vec![
        WaitFor(Cond::Text("Which drive"), 20000),
        Type("C"),
        WaitFor(Cond::Text("directory name"), 20000),
        Key("enter"),
        WaitFor(Cond::Text("Create it?"), 20000),
        Type("y"),
    ];
    match setup {
        Some(title) => steps.extend([
            WaitFor(Cond::Text(title), 120000),
            Wait(1000),
            PressUntil("escape", Cond::Text("quit to DOS?"), 1000, 10),
            Key("enter"),
            WaitFor(Cond::ShellIdle, 10000),
        ]),
        None => steps.push(WaitFor(Cond::ShellIdle, 120000)),
    }
    steps
}

const INSTALL_INI: &str = "[emulator]\ncycles=20000\n[autoexec]\nd:\ninstall\n";

pub fn games() -> Vec<Game> {
    let unpack = |id, archive, strip| Game { id, archives: vec![archive], install: Install::Unpack { strip } };
    vec![
        unpack("keen1", KEEN1, ""),
        unpack("wolf3d", WOLF3D, "wolf3d14"),
        unpack("jill", JILL, ""),
        unpack("alleycat", ALLEYCAT, "AlleyCat"),
        unpack("digger", DIGGER, "Digger83"),
        unpack("sopwith", SOPWITH, "Sopwith"),
        unpack("rogue", ROGUE, "rogue"),
        unpack("scorch", SCORCH, ""),
        Game {
            id: "doom",
            archives: vec![DOOM],
            install: Install::Installer {
                ini: INSTALL_INI,
                steps: deice(Some("DOOM Setup")),
                wants: &["DOOMS\\DOOM.EXE", "DOOMS\\DOOM1.WAD", "DOOMS\\DEFAULT.CFG"],
            },
        },
        Game {
            id: "heretic",
            archives: vec![HERETIC],
            install: Install::Installer {
                ini: INSTALL_INI,
                steps: deice(Some("Heretic Setup")),
                wants: &["HERETIC\\HERETIC.EXE", "HERETIC\\HERETIC1.WAD", "HERETIC\\HERETIC.CFG"],
            },
        },
        Game {
            id: "wolf3d-original",
            archives: vec![WOLF3D_ORIGINAL],
            install: Install::Installer { ini: INSTALL_INI, steps: deice(None), wants: &["WOLF3D\\WOLF3D.EXE"] },
        },
        Game {
            id: "duke1",
            archives: vec![DUKE1],
            install: Install::Installer { ini: INSTALL_INI, steps: deice(None), wants: &["DUKE\\DN1.EXE"] },
        },
        Game {
            id: "cosmo",
            archives: vec![COSMO],
            install: Install::Installer { ini: INSTALL_INI, steps: deice(None), wants: &["COSMO\\COSMO1.EXE"] },
        },
        Game {
            id: "duke3d",
            archives: vec![DUKE3D],
            install: Install::Installer {
                ini: INSTALL_INI,
                steps: vec![Wait(2000), PressUntil("enter", Cond::ShellIdle, 3000, 30)],
                wants: &["DUKE3D\\DUKE3D.EXE", "DUKE3D\\DUKE3D.GRP"],
            },
        },
        Game {
            id: "descent",
            archives: vec![DESCENT_1, DESCENT_2],
            install: Install::Installer {
                ini: INSTALL_INI,
                steps: vec![
                    WaitFor(Cond::Text("Select Drive"), 20000),
                    Key("enter"),
                    WaitFor(Cond::Text("installation directory"), 20000),
                    Key("enter"),
                    WaitFor(Cond::Text("Create it?"), 20000),
                    Key("enter"),
                    WaitFor(Cond::Text("Install Descent to:"), 20000),
                    Key("enter"),
                    WaitFor(Cond::Text("Press any key to enter setup"), 300000),
                    Key("enter"),
                    WaitFor(Cond::Text("Main Menu"), 20000),
                    Wait(1000),
                    Key("escape"),
                    WaitFor(Cond::ShellIdle, 20000),
                ],
                wants: &["GAMES\\DESCENT\\DESCENT.HOG", "GAMES\\DESCENT\\DESCENT.PIG", "GAMES\\DESCENT\\DCNTSHR.EXE"],
            },
        },
        Game {
            id: "raptor",
            archives: vec![RAPTOR],
            install: Install::Installer {
                ini: INSTALL_INI,
                steps: vec![
                    Wait(2000),
                    PressUntil("enter", Cond::Text("Press [C]"), 3000, 10),
                    Type("c"),
                    WaitFor(Cond::ShellIdle, 60000),
                ],
                wants: &["RAPTOR\\RAP.EXE", "RAPTOR\\SETUP.EXE"],
            },
        },
    ]
}

/// A machine's settings, as `section.key=value` pairs, the later ones
/// winning.
#[derive(Clone, Default)]
struct Hw(Vec<(&'static str, String)>);

impl Hw {
    fn new(cpu: &str, cycles: u32) -> Hw {
        Hw::default().set("emulator.cpu", cpu).set("emulator.cycles", &cycles.to_string())
    }

    fn set(mut self, key: &'static str, value: &str) -> Hw {
        self.0.retain(|(k, _)| *k != key);
        self.0.push((key, value.to_string()));
        self
    }

    fn with(mut self, other: &Hw) -> Hw {
        for (k, v) in &other.0 {
            self = self.set(k, v);
        }
        self
    }

    fn core(self, core: &str) -> Hw {
        self.set("emulator.core", core)
    }

    fn machine(self, machine: &str) -> Hw {
        self.set("emulator.machine", machine)
    }

    /// The configuration with these settings and the startup commands.
    fn ini(&self, autoexec: &str) -> String {
        let mut sections: Vec<(&str, String)> = Vec::new();
        for (key, value) in &self.0 {
            let (section, name) = key.split_once('.').unwrap();
            match sections.iter_mut().find(|(s, _)| *s == section) {
                Some((_, text)) => text.push_str(&format!("{}={}\n", name, value)),
                None => sections.push((section, format!("{}={}\n", name, value))),
            }
        }
        let mut text: String = sections.iter().map(|(s, body)| format!("[{}]\n{}", s, body)).collect();
        text.push_str(&format!("[autoexec]\n{}\n", autoexec));
        text
    }
}

/// The sound hardware variants: the cards a game is played with.
fn sound(name: &str) -> Hw {
    let hw = Hw::default();
    match name {
        // A Sound Blaster 16 with its OPL3, and the Ultrasound: the default.
        "sb16+gus" => hw.set("sound.sbtype", "sb16").set("sound.gus", "true"),
        "sb16" => hw.set("sound.sbtype", "sb16").set("sound.gus", "false"),
        "sbpro2" => hw.set("sound.sbtype", "sbpro2").set("sound.gus", "false"),
        "sb2" => hw.set("sound.sbtype", "sb2").set("sound.opl", "opl2").set("sound.gus", "false"),
        "gus" => hw.set("sound.sbtype", "none").set("sound.gus", "true"),
        // The PC speaker alone.
        "speaker" => hw.set("sound.sbtype", "none").set("sound.gus", "false"),
        "disney" => hw.set("sound.sbtype", "none").set("sound.gus", "false").set("sound.lpt_dac", "disney"),
        "covox" => hw.set("sound.sbtype", "none").set("sound.gus", "false").set("sound.lpt_dac", "covox"),
        "tandy" => hw.set("sound.sbtype", "none").set("sound.gus", "false").set("sound.tandy", "on"),
        _ => panic!("no sound variant {}", name),
    }
}

/// The scenario on both processor cores, which must come out the same:
/// `name-normal` and `name-dynamic`, checked against the golden file
/// `name`.
fn both_cores(game: &'static str, name: &str, hw: &Hw, autoexec: &str, steps: Vec<Step>) -> Vec<Scenario> {
    ["normal", "dynamic"]
        .iter()
        .map(|core| {
            Scenario::new(game, &format!("{}-{}", name, core), hw.clone().core(core).ini(autoexec), steps.clone()).golden(name)
        })
        .collect()
}

fn one(game: &'static str, name: &str, hw: &Hw, autoexec: &str, steps: Vec<Step>) -> Scenario {
    Scenario::new(game, name, hw.ini(autoexec), steps)
}

pub fn scenarios() -> Vec<Scenario> {
    let mut all = Vec::new();
    all.extend(keen1());
    all.extend(wolf3d());
    all.extend(doom());
    all.extend(heretic());
    all.extend(early());
    all.extend(jill());
    all.extend(duke3d());
    all.extend(raptor());
    all.extend(descent());
    all.extend(linked());
    all
}

fn keen1() -> Vec<Scenario> {
    let play = vec![
        Wait(13000),
        Shot("title"),
        Key("enter"),
        Wait(1500),
        Shot("menu"),
        Key("enter"),
        Wait(4000),
        Shot("map"),
        Hold("right", 1500),
        Wait(500),
        Shot("walked"),
        Record("sound", 1000),
        Check(Cond::Running),
    ];
    let mut all = Vec::new();
    all.extend(both_cores("keen1", "ega-3000", &Hw::new("386", 3000).machine("ega"), "keen1", play.clone()));
    all.push(one("keen1", "vga-20000", &Hw::new("486", 20000).machine("vga"), "keen1", play.clone()));
    all.push(one("keen1", "ega-20000-pentium", &Hw::new("pentium", 20000).machine("ega"), "keen1", play));
    all
}

fn wolf3d() -> Vec<Scenario> {
    let play = |sound: bool| {
        let mut steps = vec![
            Wait(4000),
            Shot("signon"),
            Key("enter"),
            Wait(8000),
            Shot("title"),
            Key("enter"),
            Wait(2000),
            Shot("menu"),
            // From "Read This!" up to "New Game", then the episode and
            // the difficulty.
            Keys(&["up", "up", "up", "up", "up", "up", "up", "up"], 300),
            Shot("new-game"),
            Key("enter"),
            Wait(1500),
            Key("enter"),
            Wait(1500),
            Key("enter"),
            Wait(5000),
            Shot("e1m1"),
            Hold("up", 1200),
            Shot("walked"),
            Key("ctrl"),
        ];
        steps.push(if sound { Listen("shot", 1000) } else { Record("shot", 1000) });
        steps.push(Check(Cond::Running));
        steps
    };
    let mut all = Vec::new();
    let base = Hw::new("486", 20000).machine("vga");
    all.extend(both_cores("wolf3d", "sb16", &base.clone().with(&sound("sb16")), "wolf3d", play(true)));
    for card in ["sbpro2", "sb2", "disney", "speaker"] {
        all.push(one("wolf3d", card, &base.clone().with(&sound(card)), "wolf3d", play(true)));
    }
    all.push(one("wolf3d", "386-3000", &Hw::new("386", 3000).machine("vga").with(&sound("sb16")), "wolf3d", play(true)));
    all.push(one(
        "wolf3d-original",
        "sb16",
        &base.clone().with(&sound("sb16")),
        "cd wolf3d\nwolf3d",
        play(true),
    ));
    all
}

/// Doom's settings with these music and sound effects devices (setup's
/// numbers) on the card at `port`.
fn doom_cfg(template: &str, music: u32, sfx: u32, port: u32, irq: u32, dma: u32, mport: i32) -> Vec<u8> {
    let mut out = String::new();
    for line in template.lines() {
        let key = line.split_whitespace().next().unwrap_or("");
        let value = match key {
            "snd_musicdevice" => Some(music.to_string()),
            "snd_sfxdevice" => Some(sfx.to_string()),
            "snd_sbport" => Some(port.to_string()),
            "snd_sbirq" => Some(irq.to_string()),
            "snd_sbdma" => Some(dma.to_string()),
            "snd_mport" => Some(mport.to_string()),
            _ => None,
        };
        match value {
            Some(v) => out.push_str(&format!("{}\t\t{}\n", key, v)),
            None => out.push_str(&format!("{}\n", line)),
        }
    }
    out.into_bytes()
}

/// The settings file Doom's and Heretic's setup writes, which the
/// variants change the sound devices of.
const DOOM_CFG: &str = "mouse_sensitivity\t\t5\nsfx_volume\t\t8\nmusic_volume\t\t8\nshow_messages\t\t1\nkey_right\t\t77\nkey_left\t\t75\nkey_up\t\t72\nkey_down\t\t80\nkey_strafeleft\t\t51\nkey_straferight\t\t52\nkey_fire\t\t29\nkey_use\t\t57\nkey_strafe\t\t56\nkey_speed\t\t54\nuse_mouse\t\t0\nmouseb_fire\t\t0\nmouseb_strafe\t\t1\nmouseb_forward\t\t2\nuse_joystick\t\t0\njoyb_fire\t\t0\njoyb_strafe\t\t1\njoyb_use\t\t3\njoyb_speed\t\t2\nscreenblocks\t\t9\ndetaillevel\t\t0\nsnd_channels\t\t3\nsnd_musicdevice\t\t0\nsnd_sfxdevice\t\t0\nsnd_sbport\t\t544\nsnd_sbirq\t\t7\nsnd_sbdma\t\t1\nsnd_mport\t\t-1\nusegamma\t\t0\n";

/// Doom's and Heretic's sound variants: the card, and the devices set up
/// for it (music, effects, port, IRQ, DMA, MIDI port).
fn id_sound(name: &str) -> (Hw, (u32, u32, u32, u32, u32, i32)) {
    match name {
        "none" => (sound("speaker"), (0, 0, 544, 7, 1, -1)),
        "speaker" => (sound("speaker"), (0, 1, 544, 7, 1, -1)),
        "adlib" => (sound("sb16"), (2, 0, 544, 7, 1, -1)),
        "sb16" => (sound("sb16"), (3, 3, 544, 7, 1, -1)),
        "sbpro2" => (sound("sbpro2"), (3, 3, 544, 7, 1, -1)),
        "sb2" => (sound("sb2"), (3, 3, 544, 7, 1, -1)),
        "gus" => (sound("gus"), (5, 5, 576, 5, 3, -1)),
        "gm" => (sound("sb16"), (8, 3, 544, 7, 1, 816)),
        _ => panic!("no sound variant {}", name),
    }
}

/// A timedemo of the first demo: its result after the game ends, and
/// the picture and sound on the way.
fn timedemo(sound_check: bool) -> Vec<Step> {
    vec![
        Wait(30000),
        Shot("demo-30s"),
        if sound_check { Listen("demo-sound", 2000) } else { Record("demo-sound", 2000) },
        WaitFor(Cond::ShellIdle, 600000),
        Check(Cond::Text("gametics in")),
        Shot("result"),
    ]
}

fn doom() -> Vec<Scenario> {
    let mut all = Vec::new();
    let cfg = |name: &str| {
        let (_, (m, s, p, i, d, mp)) = id_sound(name);
        doom_cfg(DOOM_CFG, m, s, p, i, d, mp)
    };
    let run = "cd dooms\ndoom -timedemo demo1";
    for name in ["none", "speaker", "adlib", "sb16", "sbpro2", "sb2", "gus", "gm"] {
        let (card, _) = id_sound(name);
        let hw = Hw::new("486", 50000).with(&card);
        all.push(one("doom", &format!("timedemo-{}", name), &hw, run, timedemo(name != "none")).file("DOOMS\\DEFAULT.CFG", cfg(name)));
    }
    for cpu in ["386", "pentium"] {
        let hw = Hw::new(cpu, 50000).with(&sound("speaker"));
        all.push(one("doom", &format!("timedemo-none-{}", cpu), &hw, run, timedemo(false)).file("DOOMS\\DEFAULT.CFG", cfg("none")));
    }
    for s in both_cores("doom", "timedemo-sb16-cores", &Hw::new("486", 50000).with(&sound("sb16")), run, timedemo(true)) {
        all.push(s.file("DOOMS\\DEFAULT.CFG", cfg("sb16")));
    }
    // A new game: through the menus into E1M1, walking and shooting.
    let play = vec![
        Wait(8000),
        Shot("title"),
        Key("escape"),
        Wait(1000),
        Key("enter"),
        Wait(800),
        Key("enter"),
        Wait(800),
        Key("enter"),
        Wait(3000),
        Shot("e1m1"),
        Hold("up", 1500),
        Shot("walked"),
        Key("ctrl"),
        Listen("pistol", 1000),
        Check(Cond::Running),
    ];
    all.push(one("doom", "play-sb16", &Hw::new("486", 50000).with(&sound("sb16")), "cd dooms\ndoom", play).file("DOOMS\\DEFAULT.CFG", cfg("sb16")));
    all
}

fn heretic() -> Vec<Scenario> {
    let mut all = Vec::new();
    let run = "cd heretic\nheretic -timedemo demo1";
    for name in ["sb16", "gus", "none"] {
        let (card, (m, s, p, i, d, mp)) = id_sound(name);
        let hw = Hw::new("486", 50000).with(&card);
        all.push(
            one("heretic", &format!("timedemo-{}", name), &hw, run, timedemo(name != "none"))
                .file("HERETIC\\HERETIC.CFG", doom_cfg(DOOM_CFG, m, s, p, i, d, mp)),
        );
    }
    all
}

fn early() -> Vec<Scenario> {
    let mut all = Vec::new();
    let cga = |cycles| Hw::new("386", cycles).machine("cga").with(&sound("speaker"));
    let alleycat = vec![
        Wait(5000),
        Shot("title"),
        Record("title-sound", 1000),
        Key("space"),
        Wait(1500),
        Type("n"),
        Wait(1500),
        Type("k"),
        Wait(1500),
        Key("space"),
        Wait(4000),
        Shot("alley"),
        Hold("right", 1000),
        Wait(1000),
        Shot("moved"),
        Check(Cond::Running),
    ];
    all.extend(both_cores("alleycat", "cga-300", &cga(300), "cat", alleycat.clone()));
    all.push(one("alleycat", "cga-3000", &cga(3000), "cat", alleycat));
    let digger = vec![
        Wait(3000),
        Shot("scores"),
        Key("f1"),
        Wait(4000),
        Shot("level"),
        Hold("left", 1500),
        Wait(500),
        Shot("dug"),
        Record("sound", 1000),
        Check(Cond::Running),
    ];
    all.extend(both_cores("digger", "cga-300", &cga(300), "digger", digger.clone()));
    all.push(one("digger", "cga-3000", &cga(3000), "digger", digger));
    let sopwith = vec![
        Wait(3000),
        Shot("menu"),
        Type("s"),
        Wait(3000),
        Shot("runway"),
        Hold("x", 2000),
        Wait(3000),
        Shot("flying"),
        Record("engine", 1000),
        Check(Cond::Running),
    ];
    all.extend(both_cores("sopwith", "cga-300", &cga(300), "sopwith", sopwith));
    let rogue = vec![
        WaitFor(Cond::Text("Rogue's Name?"), 10000),
        Shot("title"),
        Type("Rodney\n"),
        WaitFor(Cond::Text("Welcome to the Dungeons of Doom"), 10000),
        Shot("dungeon"),
        Type("lll"),
        Wait(2000),
        Shot("moved"),
        Check(Cond::Running),
    ];
    all.extend(both_cores("rogue", "vga-3000", &Hw::new("386", 3000).with(&sound("speaker")), "10rogue", rogue));
    let scorch = vec![
        Wait(6000),
        Shot("menu"),
        Type("s"),
        Wait(3000),
        Shot("player1"),
        Type("Alice\n"),
        Wait(1000),
        Key("enter"),
        Wait(2000),
        Type("Bob\n"),
        Wait(1000),
        Key("enter"),
        Wait(8000),
        Shot("battlefield"),
        Key("space"),
        Record("fire", 4000),
        Shot("fired"),
        Check(Cond::Running),
    ];
    all.push(one("scorch", "vga-3000", &Hw::new("386", 3000).with(&sound("speaker")), "scorch", scorch));
    let cosmo = vec![
        Wait(1500),
        Shot("apogee"),
        Wait(4500),
        Key("space"),
        Wait(4000),
        Key("space"),
        Wait(3000),
        Shot("menu"),
        Type("b"),
        Wait(8000),
        Shot("hint"),
        Key("space"),
        Wait(2000),
        Shot("level1"),
        Hold("right", 1500),
        Shot("walked"),
        Record("sound", 1000),
        Check(Cond::Running),
    ];
    for card in ["sb16", "speaker"] {
        all.push(one("cosmo", card, &Hw::new("386", 20000).machine("vga").with(&sound(card)), "cd cosmo\ncosmo1", cosmo.clone()));
    }
    let duke1 = vec![
        Wait(3000),
        Shot("title"),
        Wait(3000),
        Key("space"),
        Wait(4000),
        Shot("menu"),
        Type("s"),
        Wait(4000),
        Shot("story"),
        Key("space"),
        Wait(3000),
        Key("space"),
        Wait(3000),
        Key("space"),
        Wait(3000),
        Key("space"),
        Wait(3000),
        Shot("level1"),
        Hold("right", 1500),
        Wait(1000),
        Shot("walked"),
        Check(Cond::Running),
    ];
    all.push(one("duke1", "ega-20000", &Hw::new("386", 20000).machine("ega").with(&sound("speaker")), "cd duke\ndn1", duke1));
    all
}

/// Jill's own configuration questions: the Sound Blaster's when it finds
/// one, and the graphics (`video`: c, e or v). Without a controller on the
/// game port it doesn't ask for keyboard or joystick.
fn jill_play(has_sb: bool, video: &'static str) -> Vec<Step> {
    let mut steps = vec![WaitFor(Cond::Text("to configure"), 10000), Type("c")];
    {
        steps.extend([
            WaitFor(Cond::Text("digital sound?"), 5000),
            Type("y"),
            WaitFor(Cond::Text("musical sound track?"), 5000),
            Type("y"),
        ]);
    }
    steps.extend([
        WaitFor(Cond::Text("C)ga E)ga V)ga?"), 5000),
        Type(video),
        Wait(2500),
        Shot("intro"),
        Wait(2500),
        Key("enter"),
        Wait(4000),
        Shot("menu"),
        Key("enter"),
        Wait(4000),
        Shot("map"),
        Hold("right", 1000),
        Wait(500),
        Shot("walked"),
    ]);
    steps.push(if has_sb { Listen("sound", 1000) } else { Record("sound", 1000) });
    steps.push(Check(Cond::Running));
    steps
}

fn jill() -> Vec<Scenario> {
    let mut all = Vec::new();
    let base = Hw::new("386", 20000).machine("vga");
    all.extend(both_cores("jill", "vga-sb16", &base.clone().with(&sound("sb16")), "jill", jill_play(true, "v")));
    for card in ["sbpro2", "sb2"] {
        all.push(one("jill", &format!("vga-{}", card), &base.clone().with(&sound(card)), "jill", jill_play(true, "v")));
    }
    // With no Sound Blaster, Jill still finds one in the AdLib's chip,
    // whose digital sound then has nowhere to go.
    all.push(one("jill", "vga-nosb", &base.clone().with(&sound("speaker")), "jill", jill_play(false, "v")));
    all.push(one("jill", "ega-sb16", &base.clone().with(&sound("sb16")), "jill", jill_play(true, "e")));
    all.push(one("jill", "cga-sb16", &base.clone().with(&sound("sb16")), "jill", jill_play(true, "c")));
    all
}

/// Duke Nukem 3D's setup program: the sound effects card and the music
/// card, by their places in its lists, then saved.
fn duke3d_setup(fx: usize, music: usize) -> Vec<Step> {
    const DOWNS: [&str; 12] = ["down"; 12];
    let mut steps = vec![
        WaitFor(Cond::Text("Main Menu"), 20000),
        Wait(500),
        Key("enter"),
        WaitFor(Cond::Text("Sound Setup"), 5000),
        Wait(500),
        Key("enter"),
        Wait(1500),
        Keys(&DOWNS[..fx], 300),
        Key("enter"),
    ];
    if fx != 0 {
        // The voices, bits, channels and mixing rate, as they are.
        steps.push(PressUntil("enter", Cond::Text("Current Music Card"), 1500, 8));
    }
    steps.extend([
        WaitFor(Cond::Text("Current Music Card"), 5000),
        Wait(500),
        Key("down"),
        Key("enter"),
        Wait(1500),
        Keys(&DOWNS[..music], 300),
        Key("enter"),
        Wait(1500),
        // General MIDI's port, as it is.
        PressUntil("enter", Cond::Text("Current Music Card"), 1500, 3),
        Wait(500),
        Key("escape"),
        WaitFor(Cond::Text("Save and launch"), 5000),
        Key("escape"),
        WaitFor(Cond::Text("before exiting?"), 5000),
        Key("enter"),
        WaitFor(Cond::Not(&Cond::Text("before exiting?")), 10000),
    ]);
    steps
}

/// Duke Nukem 3D after its setup: the logos and the title, the first
/// demo, then a new game.
fn duke3d_play(fx: usize, music: usize, audible: bool) -> Vec<Step> {
    let mut steps = duke3d_setup(fx, music);
    let listen = |label| if audible { Listen(label, 2000) } else { Record(label, 2000) };
    steps.extend([
        // The game at a 3D shooter's speed, its setup slower: a delay loop
        // in it never ends at 50000.
        Cycles(60000),
        Wait(6000),
        Shot("startup"),
        Wait(9000),
        Shot("title"),
        listen("title-sound"),
        Wait(10000),
        Shot("demo-a"),
        listen("demo-sound"),
        Wait(8000),
        Shot("demo-b"),
        Key("escape"),
        Wait(1500),
        Shot("menu"),
        Key("enter"),
        Wait(1000),
        Key("enter"),
        Wait(1000),
        Key("enter"),
        Wait(6000),
        Shot("e1l1"),
        Hold("up", 1500),
        Shot("walked"),
        Key("ctrl"),
        listen("pistol"),
        Check(Cond::Running),
    ]);
    steps
}

fn duke3d() -> Vec<Scenario> {
    let mut all = Vec::new();
    let run = "cd duke3d\nsetup\nduke3d";
    let base = Hw::new("486", 20000);
    // The setup's list numbers: effects None, Ultrasound, Sound Blaster,
    // Sound Man 16, PAS, AWE32, SoundScape, Disney Sound Source; music
    // None, Ultrasound, Sound Blaster, ..., General MIDI (8).
    all.extend(both_cores("duke3d", "sb16", &base.clone().with(&sound("sb16")), run, duke3d_play(2, 2, true)));
    all.push(one("duke3d", "sbpro2", &base.clone().with(&sound("sbpro2")), run, duke3d_play(2, 2, true)));
    all.push(one("duke3d", "gus", &base.clone().with(&sound("gus")), run, duke3d_play(1, 1, true)));
    all.push(one("duke3d", "sb16-gm", &base.clone().with(&sound("sb16")), run, duke3d_play(2, 8, true)));
    all.push(one("duke3d", "disney", &base.clone().with(&sound("disney")), run, duke3d_play(7, 0, true)));
    all.push(one("duke3d", "silent-pentium", &Hw::new("pentium", 20000).with(&sound("speaker")), run, duke3d_play(0, 0, false)));
    all.push(one("duke3d", "setup-50000", &Hw::new("486", 50000).with(&sound("sb16")), "cd duke3d\nsetup", vec![WaitFor(Cond::Text("Main Menu"), 30000), Shot("main-menu")]));
    all
}

/// Raptor's setup, taking the cards it finds, then the game's
/// introduction and its menu.
fn raptor_play(audible: bool) -> Vec<Step> {
    let listen = |label| if audible { Listen(label, 2000) } else { Record(label, 2000) };
    vec![
        WaitFor(Cond::Text("Raptor Setup"), 10000),
        Wait(1000),
        Shot("setup"),
        PressUntil("enter", Cond::Not(&Cond::Text("Raptor Setup")), 1500, 20),
        Cycles(50000),
        Wait(14000),
        Shot("apogee"),
        listen("apogee-sound"),
        Wait(8000),
        Shot("cygnus"),
        Wait(8000),
        Shot("intro"),
        listen("intro-sound"),
        Wait(10000),
        Shot("menu"),
        Key("enter"),
        Wait(3000),
        Shot("new-mission"),
        Check(Cond::Running),
    ]
}

fn raptor() -> Vec<Scenario> {
    let mut all = Vec::new();
    let run = "cd raptor\nsetup\nrap";
    let base = Hw::new("486", 20000);
    all.extend(both_cores("raptor", "gus", &base.clone().with(&sound("sb16+gus")), run, raptor_play(true)));
    for card in ["sb16", "speaker"] {
        all.push(one("raptor", card, &base.clone().with(&sound(card)), run, raptor_play(card != "speaker")));
    }
    all.push(one("raptor", "sbpro2", &base.clone().with(&sound("sbpro2")), run, raptor_play(true)));
    all
}

/// Descent's setup: the sound hardware it detects, saved.
fn descent_setup() -> Vec<Step> {
    vec![
        WaitFor(Cond::Text("Main Menu"), 20000),
        Wait(1000),
        Key("enter"),
        WaitFor(Cond::Text("WARNING"), 5000),
        Key("enter"),
        WaitFor(Cond::Text("Auto detection found"), 30000),
        Wait(1000),
        // "Select this sound card", and the cursor goes on to testing it.
        Key("enter"),
        WaitFor(Cond::Text("Test the current digital"), 10000),
        Wait(1000),
        Key("escape"),
        WaitFor(Cond::Text("Save changes?"), 5000),
        Key("enter"),
        WaitFor(Cond::Not(&Cond::Text("Save changes?")), 10000),
    ]
}

/// Descent after its setup: a new pilot, the first level's briefing,
/// then flying and shooting in the mine.
fn descent_play(audible: bool) -> Vec<Step> {
    let listen = |label| if audible { Listen(label, 2000) } else { Record(label, 2000) };
    let mut steps = descent_setup();
    steps.extend([
        Cycles(80000),
        Wait(6000),
        Shot("interplay"),
        listen("intro-sound"),
        Wait(7000),
        Type("TEST\n"),
        // The keyboard, as the input device.
        Wait(3000),
        Key("enter"),
        Wait(5000),
        Shot("menu"),
        // New game, at the second difficulty.
        Key("enter"),
        Wait(2500),
        Key("enter"),
        Wait(8000),
        Shot("briefing"),
        Key("escape"),
        Wait(8000),
        Shot("cockpit"),
        Hold("a", 2000),
        Shot("flown"),
        Key("ctrl"),
        listen("laser"),
        Check(Cond::Running),
    ]);
    steps
}

fn descent() -> Vec<Scenario> {
    let mut all = Vec::new();
    let run = "cd games\\descent\nsetup\ndescent";
    let base = Hw::new("486", 20000);
    all.extend(both_cores("descent", "gus", &base.clone().with(&sound("sb16+gus")), run, descent_play(true)));
    all.push(one("descent", "sb16", &base.clone().with(&sound("sb16")), run, descent_play(true)));
    all.push(one("descent", "sbpro2", &base.clone().with(&sound("sbpro2")), run, descent_play(true)));
    all.push(one("descent", "sb2", &base.clone().with(&sound("sb2")), run, descent_play(true)));
    all.push(one("descent", "pentium-speaker", &Hw::new("pentium", 20000).with(&sound("speaker")), run, descent_play(false)));
    all
}

/// Two machines playing one game: over IPX, a null-modem cable and a
/// modem call. Both reach the game and play on without the game falling
/// out of step.
fn linked() -> Vec<Scenario> {
    let mut all = Vec::new();
    let play = |mode: u8| {
        vec![
            WaitFor(Cond::Mode(mode), 60000),
            Focus(1),
            WaitFor(Cond::Mode(mode), 30000),
            Focus(0),
            Wait(3000),
            Shot("a-start"),
            Hold("up", 1500),
            Key("ctrl"),
            Focus(1),
            Hold("right", 800),
            Hold("up", 1500),
            Focus(0),
            Wait(20000),
            Check(Cond::Mode(mode)),
            Check(Cond::Colours(16)),
            Shot("a-later"),
            Focus(1),
            Check(Cond::Mode(mode)),
            Check(Cond::Colours(16)),
            Shot("b-later"),
            Check(Cond::Running),
        ]
    };
    let quiet = doom_cfg(DOOM_CFG, 0, 0, 544, 7, 1, -1);
    let hw = Hw::new("486", 50000).with(&sound("speaker"));
    let doom = |name: &str, hw: &Hw, a: &str, b: &str| {
        one("doom", name, hw, &format!("cd dooms\n{}", a), play(0x13))
            .file("DOOMS\\DEFAULT.CFG", quiet.clone())
            .partner(hw.ini(&format!("cd dooms\n{}", b)))
    };
    all.push(doom("net-ipx", &hw.clone().set("network.ipx", "true"), "ipxsetup -nodes 2", "ipxsetup -nodes 2"));
    let cable = hw.clone().set("serial.serial1", "nullmodem");
    all.push(doom("net-nullmodem", &cable, "sersetup -com1", "sersetup -com1"));
    all.push(doom("net-modem", &hw, "sersetup -com2 -answer", "sersetup -com2 -dial 5551234"));
    let quiet_heretic = doom_cfg(DOOM_CFG, 0, 0, 544, 7, 1, -1);
    let ipx = hw.clone().set("network.ipx", "true");
    all.push(
        one("heretic", "net-ipx", &ipx, "cd heretic\nipxsetup -nodes 2", play(0x13))
            .file("HERETIC\\HERETIC.CFG", quiet_heretic)
            .partner(ipx.ini("cd heretic\nipxsetup -nodes 2")),
    );
    all
}
