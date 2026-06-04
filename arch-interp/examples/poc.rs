//! Proof of concept: RetroOS's arch boundary implemented over a TCG core (Unicorn).
//!
//! It demonstrates that the kernel-facing interface this session produced —
//!   * a `Vcpu` you run,
//!   * guest memory you read/write (`arch::mem()`),
//!   * and a `KernelEvent` that running returns,
//! maps cleanly onto a software CPU, with all four event kinds surfaced exactly
//! as the real event-loop kernel already expects:
//!   * software INT (`INT 0x80`)          -> Syscall/SoftInt event
//!   * unmapped access                    -> demand-paged inside arch, retried (no kernel event)
//!   * `OUT`/`IN`                          -> Port event (to the virtual device layer)
//!   * "timer"                            -> instruction-counted Irq event (deterministic)

use unicorn_engine::{Unicorn, RegisterX86};
use unicorn_engine::unicorn_const::{Arch, Mode, HookType, MemType};
use unicorn_engine::Prot;
use std::collections::BTreeSet;

/// The kernel-visible event `do_arch_execute` returns (RetroOS's `KernelEvent`).
#[derive(Debug, Clone)]
enum KernelEvent {
    Syscall(u32),                                   // INT 0x80, eax = number
    SoftInt(u8),                                    // other INT n
    Port { out: bool, port: u16, val: u32 },        // IN/OUT -> virtual device
    Irq(u8),                                        // instruction-counted timer/device IRQ
    Fault(u64),                                     // unrecoverable access
}

/// Per-Vcpu context the hooks write into (Unicorn hands hooks `&mut Unicorn<Ctx>`).
struct Ctx {
    pending: Option<KernelEvent>,
    mapped: BTreeSet<u64>,   // demand-paged page bases (the software "address space")
    insns: u64,              // approx instructions retired (for the IRQ-cadence log)
}

const CODE_BASE: u64 = 0x1000;
const SLICE: usize = 500;    // instructions per run-slice == timer-IRQ granularity

/// `do_arch_execute`: run the Vcpu until an event, or until SLICE instructions
/// retire (a deterministic timer tick). The HW backend does this with IRET +
/// trap-back; here it's emu_start + hooks.
fn do_arch_execute(uc: &mut Unicorn<Ctx>) -> KernelEvent {
    uc.get_data_mut().pending = None;
    let pc = uc.reg_read(RegisterX86::EIP).unwrap();
    let r = uc.emu_start(pc, 0xFFFF_FFFF, 0, SLICE);
    if let Some(ev) = uc.get_data_mut().pending.take() {
        return ev;                       // a hook stopped us with an event
    }
    match r {
        Ok(()) => {                      // ran the whole slice with no event -> timer tick
            uc.get_data_mut().insns += SLICE as u64;
            KernelEvent::Irq(0)
        }
        Err(_) => KernelEvent::Fault(uc.reg_read(RegisterX86::EIP).unwrap()),
    }
}

fn main() {
    // Hand-assembled 32-bit guest:
    //   mov eax,4 ; mov ebx,0x539 ; int 0x80      -> Syscall(4)
    //   mov eax,0x42 ; mov edx,0xE9 ; out dx,al    -> Port OUT 0xE9
    //   mov eax,0xdeadbeef ; mov [0x40000000],eax  -> demand-paged write
    //   mov ecx,0x800 ; (dec ecx ; jnz)            -> ~4096 insns to exercise IRQ slicing
    //   mov eax,1 ; int 0x80 ; hlt                 -> Syscall(1) = exit
    let code: &[u8] = &[
        0xB8, 0x04,0x00,0x00,0x00,            // mov eax,4
        0xBB, 0x39,0x05,0x00,0x00,            // mov ebx,0x539
        0xCD, 0x80,                           // int 0x80
        0xB8, 0x42,0x00,0x00,0x00,            // mov eax,0x42
        0xBA, 0xE9,0x00,0x00,0x00,            // mov edx,0xE9
        0xEE,                                 // out dx,al
        0xB8, 0xEF,0xBE,0xAD,0xDE,            // mov eax,0xdeadbeef
        0xA3, 0x00,0x00,0x00,0x40,            // mov [0x40000000],eax  (unmapped)
        0xB9, 0x00,0x08,0x00,0x00,            // mov ecx,0x800
        0x49,                                 // dec ecx        <- loop top
        0x75, 0xFD,                           // jnz -3
        0xB8, 0x01,0x00,0x00,0x00,            // mov eax,1
        0xCD, 0x80,                           // int 0x80
        0xF4,                                 // hlt
    ];

    let ctx = Ctx { pending: None, mapped: BTreeSet::new(), insns: 0 };
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, ctx)
        .expect("unicorn init");

    // Map the code page (the rest of the address space is demand-paged on fault).
    uc.mem_map(CODE_BASE, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(CODE_BASE, code).unwrap();
    uc.get_data_mut().mapped.insert(CODE_BASE);

    // --- arch event hooks ---------------------------------------------------
    // Software interrupt -> Syscall/SoftInt event.
    uc.add_intr_hook(|uc: &mut Unicorn<Ctx>, intno: u32| {
        let eax = uc.reg_read(RegisterX86::EAX).unwrap() as u32;
        let ev = if intno == 0x80 { KernelEvent::Syscall(eax) } else { KernelEvent::SoftInt(intno as u8) };
        uc.get_data_mut().pending = Some(ev);
        uc.emu_stop().unwrap();
    }).unwrap();

    // Unmapped access -> demand-page it in the arch MMU and RETRY (no kernel event).
    // This is exactly where COW-fork / demand paging live for the interpreter backend.
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX,
        |uc: &mut Unicorn<Ctx>, _t: MemType, addr: u64, _sz: usize, _v: i64| -> bool {
            let page = addr & !0xFFF;
            uc.mem_map(page, 0x1000, Prot::ALL).ok();
            uc.get_data_mut().mapped.insert(page);
            println!("   [arch ] demand-mapped guest page {:#010x}, retrying access", page);
            true   // retry
        }).unwrap();

    // OUT -> Port event for the virtual device layer.
    uc.add_insn_out_hook(|uc: &mut Unicorn<Ctx>, port: u32, _size: usize, val: u32| {
        uc.get_data_mut().pending = Some(KernelEvent::Port { out: true, port: port as u16, val });
        uc.emu_stop().unwrap();
    }).unwrap();

    // --- the (toy) event-loop kernel ---------------------------------------
    uc.reg_write(RegisterX86::EIP, CODE_BASE).unwrap();
    println!("[kernel] running guest vcpu...");
    let mut irqs = 0;
    loop {
        match do_arch_execute(&mut uc) {
            KernelEvent::Syscall(1) => {
                println!("[kernel] syscall #1 (exit) -> stopping guest");
                break;
            }
            KernelEvent::Syscall(n) => {
                let ebx = uc.reg_read(RegisterX86::EBX).unwrap();
                println!("[kernel] syscall #{n}  (ebx={:#x})  -> serviced", ebx);
            }
            KernelEvent::SoftInt(n)  => println!("[kernel] soft INT {:#x} -> reflect to guest", n),
            KernelEvent::Port{out,port,val} =>
                println!("[kernel] device {} port={:#06x} val={:#x} -> virtual machine",
                         if out {"OUT"} else {"IN "}, port, val),
            KernelEvent::Irq(line) => {
                irqs += 1;
                println!("[kernel] timer IRQ{} @ ~{} insns -> (would inject guest handler)",
                         line, uc.get_data().insns);
            }
            KernelEvent::Fault(a) => { println!("[kernel] unrecoverable fault @ {:#x}", a); break; }
        }
    }
    println!("[done] guest exited cleanly. {} demand-mapped pages, {} timer IRQs.",
             uc.get_data().mapped.len(), irqs);
}
