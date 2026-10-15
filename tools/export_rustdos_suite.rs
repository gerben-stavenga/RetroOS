//! Evaluate the pinned upstream catalog without linking an emulator.
//! Output is a tab-separated stream with Rust Debug values; the importer
//! parses only literal values and the explicitly allowed Step/Cond variants.
#![allow(dead_code)]
use std::time::Duration;
mod fetch {
    #[derive(Clone, Copy, Debug)]
    pub struct Archive { pub file: &'static str, pub url: &'static str, pub sha256: &'static str }
}
mod script {
    #[derive(Clone, Debug)]
    pub enum Cond {
        ShellIdle, Running, Mode(u8), Text(&'static str), Colours(usize), Not(&'static Cond),
    }
    #[derive(Clone, Debug)]
    pub enum Step {
        Cycles(u32), Focus(usize), Wait(u64), Key(&'static str), Keys(&'static [&'static str], u64),
        Hold(&'static str, u64), Type(&'static str), PressUntil(&'static str, Cond, u64, u32),
        WaitFor(Cond, u64), Check(Cond), Shot(&'static str), Listen(&'static str, u64), Record(&'static str, u64),
    }
}
pub enum Install {
    Unpack { strip: &'static str },
    Installer { ini: &'static str, steps: Vec<script::Step>, wants: &'static [&'static str] },
}
pub struct Game { pub id: &'static str, pub archives: Vec<fetch::Archive>, pub install: Install }
pub struct Scenario {
    pub name: String, pub game: &'static str, pub golden: Option<String>, pub ini: String,
    pub files: Vec<(&'static str, Vec<u8>)>, pub steps: Vec<script::Step>,
    pub timeout: Duration, pub expect_fail: Option<&'static str>, pub partner: Option<String>,
}
impl Scenario {
    pub fn new(game: &'static str, variant: &str, ini: String, steps: Vec<script::Step>) -> Self {
        let name = format!("{game}/{variant}");
        Self { game, golden: Some(name.clone()), name, ini, steps, files: vec![],
               timeout: Duration::from_secs(300), expect_fail: None, partner: None }
    }
    pub fn partner(mut self, ini: String) -> Self { self.partner = Some(ini); self.golden = None; self }
    pub fn golden(mut self, key: &str) -> Self { self.golden = Some(format!("{}/{key}", self.game)); self }
    pub fn file(mut self, name: &'static str, bytes: impl Into<Vec<u8>>) -> Self {
        self.files.push((name, bytes.into())); self
    }
    pub fn expect_fail(mut self, why: &'static str) -> Self { self.expect_fail = Some(why); self }
}
#[path = "../third_party/rustdos_suite/catalog.rs"]
mod catalog;
fn main() {
    for game in catalog::games() {
        println!("GAME\t{:?}", game.id);
        for a in game.archives { println!("ARCHIVE\t{:?}\t{:?}\t{:?}", a.file, a.url, a.sha256); }
        match game.install {
            Install::Unpack { strip } => println!("UNPACK\t{strip:?}"),
            Install::Installer { ini, steps, wants } => println!("INSTALL\t{ini:?}\t{steps:?}\t{wants:?}"),
        }
    }
    for s in catalog::scenarios() {
        println!("SCENARIO\t{:?}\t{:?}\t{:?}\t{}", s.name, s.game, s.ini, s.timeout.as_secs());
        println!("GOLDEN\t{:?}", s.golden);
        println!("PARTNER\t{:?}", s.partner);
        println!("EXPECT_FAIL\t{:?}", s.expect_fail);
        for (name, bytes) in s.files { println!("FILE\t{name:?}\t{bytes:?}"); }
        println!("STEPS\t{:?}", s.steps);
    }
}
