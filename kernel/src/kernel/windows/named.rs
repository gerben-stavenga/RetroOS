//! Session named synchronization objects and pagefile-backed sections.
//! Handles and views retain objects independently; names do not keep them alive.
use super::*;
use alloc::sync::{Arc, Weak};
use core::ptr::NonNull;

const BASE: u32 = 0x77000000;
const INVALID: u32 = 0xc000000d;
const TYPE: u32 = 0xc0000024;
struct Backing { address: usize, pages: usize }
impl Drop for Backing {
    fn drop(&mut self) { RETIRED.lock().push((self.address, self.pages)); }
}
enum Value {
    Directory,
    Semaphore { count: u32, maximum: u32 },
    Mutant { owner: u32, recursion: u32 },
    Event { manual: bool, signaled: bool },
    Section { backing: Backing, writable: bool },
}
impl Value {
    fn kind(&self) -> u32 { match self { Self::Directory => 0, Self::Semaphore {..} => 1,
        Self::Mutant {..} => 2, Self::Event {..} => 3, Self::Section {..} => 20 } }
}
struct Object { name: Vec<u16>, value: spin::Mutex<Value> }
static OBJECTS: spin::Mutex<Vec<Weak<Object>>> = spin::Mutex::new(Vec::new());
static RETIRED: spin::Mutex<Vec<(usize, usize)>> = spin::Mutex::new(Vec::new());
// Keep wait-all readiness and consumption atomic with releases on other cores.
pub(super) static WAIT_LOCK: spin::Mutex<()> = spin::Mutex::new(());
#[derive(Default)]
pub(super) struct State {
    handles: Vec<Option<Arc<Object>>>,
    views: Vec<(u32, Arc<Object>)>,
}
impl State {
    fn get(&self, handle: u32) -> Option<Arc<Object>> {
        handle.checked_sub(BASE).filter(|h| h % 4 == 0)
            .and_then(|h| self.handles.get(h as usize / 4)).and_then(Clone::clone)
    }
    fn insert(&mut self, object: Arc<Object>) -> u32 {
        let i = self.handles.iter().position(Option::is_none).unwrap_or(self.handles.len());
        if i == self.handles.len() { self.handles.push(None); }
        self.handles[i] = Some(object); BASE + i as u32 * 4
    }
}
pub(super) fn is_handle(handle: u32) -> bool { handle & 0xff000000 == BASE }
fn collect<A: crate::Arch>(machine: &mut A) {
    for (address, pages) in core::mem::take(&mut *RETIRED.lock()) {
        unsafe { machine.free_shared_pages(NonNull::new(address as *mut u8).unwrap(), pages); }
    }
}
fn open(name: Vec<u16>, flags: u32, kind: u32, create: impl FnOnce() -> Result<Value, u32>)
    -> Result<(Arc<Object>, u32), u32> {
    let mut objects = OBJECTS.lock();
    objects.retain(|o| o.strong_count() != 0);
    for object in objects.iter().filter_map(Weak::upgrade) {
        let matches = object.name.len() == name.len() && object.name.iter().zip(&name).all(|(&a,&b)|
            a == b || flags & 64 != 0 && fold(a) == fold(b));
        if !name.is_empty() && matches {
            if object.value.lock().kind() != kind { return Err(TYPE); }
            if flags & 0x80 == 0 { return Err(0xc0000035); }
            return Ok((object, 0x40000000)); // STATUS_OBJECT_NAME_EXISTS
        }
    }
    let object = Arc::new(Object { name, value: spin::Mutex::new(create()?) });
    if !object.name.is_empty() { objects.push(Arc::downgrade(&object)); }
    Ok((object, 0))
}
fn fold(c: u16) -> u16 { if (65..=90).contains(&c) { c + 32 } else { c } }
fn path(text: &str) -> Vec<u16> { text.encode_utf16().collect() }
fn attributes<A: crate::Arch>(machine: &A, state: &State, address: u32) -> Result<(Vec<u16>, u32), u32> {
    if address == 0 { return Ok((Vec::new(), 0)); }
    if machine.read::<u32>(address as usize) != 24 { return Err(INVALID); }
    let root = machine.read::<u32>(address as usize + 4);
    let name = machine.read::<u32>(address as usize + 8);
    let flags = machine.read::<u32>(address as usize + 12);
    if name == 0 { return if root == 0 { Ok((Vec::new(), flags)) } else { Err(INVALID) }; }
    let length = machine.read::<u16>(name as usize) as usize;
    let pointer = machine.read::<u32>(name as usize + 4);
    if !length.is_multiple_of(2) || length > 65534 || pointer == 0 && length != 0 { return Err(INVALID); }
    let mut name: Vec<_> = (0..length/2).map(|i| machine.read::<u16>(pointer as usize + 2*i)).collect();
    if name.is_empty() { return Ok((name, flags)); }
    if root != 0 {
        let object = state.get(root).ok_or(0xc0000008u32)?;
        if !matches!(*object.value.lock(), Value::Directory) { return Err(TYPE); }
        if name[0] == 92 { return Err(0xc000003bu32); }
        let mut prefix = object.name.clone(); prefix.push(92); prefix.append(&mut name); name = prefix;
    } else if name[0] != 92 { return Err(0xc000003bu32); }
    // Win32 Local/Global aliases within the session's BaseNamedObjects directory.
    let local = path("\\Sessions\\0\\BaseNamedObjects\\Local\\");
    let global = path("\\Sessions\\0\\BaseNamedObjects\\Global\\");
    if name.starts_with(&local) { name = [path("\\Sessions\\0\\BaseNamedObjects\\"), name[local.len()..].to_vec()].concat(); }
    if name.starts_with(&global) { name = [path("\\BaseNamedObjects\\"), name[global.len()..].to_vec()].concat(); }
    Ok((name, flags))
}
pub(super) fn ready(state: &State, handle: u32, id: u32, consume: bool) -> Option<bool> {
    let object = state.get(handle)?;
    let mut value = object.value.lock();
    Some(match &mut *value {
        Value::Semaphore { count, .. } => { let ready = *count != 0; if ready && consume { *count -= 1; } ready },
        Value::Mutant { owner, recursion } => { let ready = *owner == 0 || *owner == id;
            if ready && consume { *owner = id; *recursion += 1; } ready },
        Value::Event { manual, signaled } => { let ready = *signaled; if consume && !*manual { *signaled = false; } ready },
        _ => return None,
    })
}
pub(super) fn release<A: crate::Arch>(machine: &mut A, state: &mut WindowsState) {
    let views = core::mem::take(&mut state.threads.named.views);
    for (base, object) in views {
        memory::call(machine, state, Api::MemoryRelease, base, 0, 1); drop(object);
    }
    state.threads.named.handles.clear(); collect(machine);
}
pub(super) fn call<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, args: [u32; 6]) -> u32 {
    let result = execute(machine, state, args); collect(machine); result.unwrap_or_else(|s|s)
}
fn execute<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, args: [u32; 6]) -> Result<u32,u32> {
    let [op, handle, a, b, c, out] = args;
    let _serial = WAIT_LOCK.lock();
    let id = machine.read::<u32>((state.teb_base + 0x24) as usize);
    if op == 24 {
        if out == 0 { return Err(INVALID); }
        let (name,flags)=attributes(machine,&state.threads.named,a)?;
        if name.is_empty() {return Err(INVALID);}
        let (object,_) = open(name,flags | 0x80,20,||Err(0xc0000034))?;
        let handle=state.threads.named.insert(object);
        machine.write::<u32>(out as usize,handle);
        return Ok(0);
    }
    if matches!(op, 0..=3 | 20) {
        if out == 0 { return Err(INVALID); }
        let (name, mut flags) = attributes(machine, &state.threads.named, a)?;
        if op == 0 {
            if name != path("\\Sessions\\0\\BaseNamedObjects") && name != path("\\BaseNamedObjects") { return Err(0xc0000034); }
            flags |= 0x80;
        }
        let (object, status) = open(name, flags, op, || Ok(match op {
            0 => Value::Directory,
            1 => { if c == 0 || c > i32::MAX as u32 || b > c {return Err(INVALID);}
                Value::Semaphore { count:b, maximum:c } },
            2 => Value::Mutant { owner:if b != 0 {id}else{0}, recursion: (b != 0) as u32 },
            3 => {if b > 1 {return Err(INVALID);} Value::Event {manual:b == 0,signaled:c != 0}},
            20 => {
                let length = b.checked_add(4095).ok_or(INVALID)? & !4095;
                if length == 0 || length as usize / 4096 >= machine.free_page_count() {return Err(0xc0000017);}
                if c != 2 && c != 4 { return Err(INVALID); }
                let pages = length as usize / 4096;
                let backing = Backing {address:machine.alloc_shared_pages(pages).as_ptr() as usize,pages};
                Value::Section {backing,writable:c == 4}
            }, _ => unreachable!()
        }))?;
        let handle = state.threads.named.insert(object);
        machine.write::<u32>(out as usize,handle); return Ok(if op == 0 {0}else{status});
    }
    if op == 22 {
        let i = state.threads.named.views.iter().position(|v|v.0 == handle).ok_or(0xc0000019u32)?;
        memory::call(machine,state,Api::MemoryRelease,handle,0,1);
        state.threads.named.views.swap_remove(i); return Ok(0);
    }
    let object = state.threads.named.get(handle).ok_or(0xc0000008u32)?;
    if op == 9 {state.threads.named.handles[((handle-BASE)/4) as usize] = None;return Ok(0);}
    let mut value = object.value.lock();
    if op == 21 {
        let Value::Section {backing,writable} = &*value else {return Err(TYPE);};
        if out == 0 || a & 65535 != 0 || c != 2 && c != 4 || c == 4 && !*writable {return Err(INVALID);}
        let available = (backing.pages as u32 * 4096).checked_sub(a).filter(|n|*n != 0).ok_or(INVALID)?;
        let length = if b == 0 {available}else{b.checked_add(4095).map(|n|n & !4095).filter(|n|*n <= available).ok_or(INVALID)?};
        let requested = machine.read::<u32>(out as usize);
        let base = memory::call(machine,state,Api::MemoryReserve,requested,length,0);
        if base == 0 {return Err(0xc0000018);}
        unsafe {machine.map_shared_pages(base as usize/4096,NonNull::new((backing.address+a as usize) as *mut u8).unwrap(),length as usize/4096);}
        let permissions = (c == 4) as u32;
        machine.set_page_flags(base as usize/4096,length as usize/4096,c == 4,false);
        memory::adopt_shared(state,base,permissions);
        state.threads.named.views.push((base,object.clone()));
        machine.write::<u32>(out as usize,base);machine.write::<u32>(out as usize+4,length);return Ok(0);
    }
    match (&mut *value,op) {
        (Value::Semaphore {count,maximum},4) => {
            if a == 0 || a > *maximum-*count {return Err(0xc0000047);}
            if out != 0 {machine.write::<u32>(out as usize,*count);} *count += a;
        },
        (Value::Semaphore {count,maximum},10) => {machine.write::<u32>(out as usize,*count);machine.write::<u32>(out as usize+4,*maximum);},
        (Value::Mutant {owner,recursion},5) => {
            if *owner != id || *recursion == 0 {return Err(0xc0000046);}
            if out != 0 {machine.write::<u32>(out as usize,1u32.wrapping_sub(*recursion));}
            *recursion -= 1;if *recursion == 0 {*owner = 0;}
        },
        (Value::Mutant {owner,recursion},11) => {machine.write::<u32>(out as usize,1u32.wrapping_sub(*recursion));machine.write::<u32>(out as usize+4,(*owner == id) as u32);},
        (Value::Event {signaled,..},6|7) => {if out != 0 {machine.write::<u32>(out as usize,*signaled as u32);}*signaled = op == 6;},
        (Value::Event {signaled,manual},12) => {machine.write::<u32>(out as usize,(!*manual) as u32);machine.write::<u32>(out as usize+4,*signaled as u32);},
        _ => return Err(TYPE)
    }
    Ok(0)
}
