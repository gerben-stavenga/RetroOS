# Linux under RetroOS: exploration note

## Motivation

An early RetroOS goal was to understand the kernel as an abstraction boundary:
roughly, a kernel is to peripherals what a programming language is to CPU and
memory. A strong test of that idea is whether another kernel can be implemented
against the RetroOS API, just as RetroOS already has metal and hosted
implementations of its architecture boundary.

Modern hardware makes this question practical. Supporting every NIC, GPU, and
other peripheral natively would require a vast amount of obscure,
hardware-specific code. Linux already contains that knowledge. Rather than run
RetroOS on Linux (which would resemble DOSEMU), the interesting direction is to
run Linux as a subordinate kernel inside RetroOS and grant it selected physical
devices.

## Proposed shape

```text
Physical machine
└── RetroOS
    ├── DOS and ordinary RetroOS-managed processes
    └── Linux domain
        ├── Linux scheduler and processes
        ├── mac80211/cfg80211 and network stack
        ├── ath12k and WCN785x firmware
        └── assigned laptop Wi-Fi device
```

RetroOS remains the real kernel. It boots first, owns memory and PCI resources,
schedules the Linux domain, and decides which hardware Linux may access. Linux
provides the complicated peripheral implementation and may export a higher-level
service, such as sockets, back to RetroOS.

This would eventually be better described as a `linux-retroos` port than stock
User-Mode Linux. UML is valuable scaffolding, but its host interface assumes
Linux-specific facilities such as `ptrace`, signals, `epoll`, and Linux memory
mapping semantics. A principled port would call an intentional RetroOS substrate
instead.

## Candidate peripheral-machine interface

The irreducible interface should be a small family of Rust traits rather than a
trait for every device model:

- execution contexts and address spaces;
- events, clocks, and timers;
- exclusive device capabilities;
- PCI configuration and reset;
- ordered, volatile MMIO mappings;
- DMA allocation/mapping with distinct CPU and device addresses;
- interrupt binding and delivery;
- firmware/resource loading.

Linux would translate its ordinary `ioremap`, DMA, PCI, and IRQ APIs onto these
operations. Linux itself would continue to supply workqueues, `sk_buff`, NAPI,
mac80211, cfg80211, WPA, regulatory handling, and the actual device drivers.
The goal is specifically to avoid reproducing those Linux subsystems as RetroOS
APIs.

For a PCI device, the path would look like:

```text
Linux driver
→ Linux PCI/DMA/IRQ APIs
→ linux-retroos architecture layer
→ RetroOS device capability
→ physical MMIO, IOMMU mappings, and interrupts
```

RetroOS would receive a hardware interrupt and turn it into an event for Linux.
DMA buffers would be allocated and pinned by RetroOS, mapped into the Linux
domain, and exposed to the device through an opaque IOVA. An IOMMU could confine
the device to those buffers.

## Relationship to the Linux personality

The existing Linux personality implements a useful subset of Linux syscall
semantics directly in safe Rust. An actual Linux kernel cannot simply replace
its syscall dispatcher: Linux syscalls depend on Linux-owned tasks, address
spaces, file tables, credentials, and scheduling.

A full Linux personality would therefore be a domain facade. RetroOS could ask
the domain to launch an ELF and retain a lightweight handle for focus, process
display, and accounting, while Linux owns and schedules the actual task.
RetroOS schedules the Linux domain; Linux schedules tasks within it.

The current implementation should initially remain as a small `LinuxLite`
personality. Keeping both would provide a useful comparison between internally
implemented semantics and an actual subordinate kernel.

## Prior art and possible research contribution

Linux driver domains, L4Linux, DDE/DDEKit, rump kernels, exokernels, and UML all
cover nearby ground. Merely using Linux drivers from another kernel is therefore
not novel.

The potentially interesting contribution is the recursive abstraction:
discovering the smallest peripheral-machine interface sufficient to host both
RetroOS itself and a largely unmodified modern Linux kernel operating real
hardware. Useful evaluation would include interface size, Linux patch size,
driver modifications, support across several device classes, performance, and
whether the interface remains stable across Linux versions.

## Possible experiment sequence

1. Boot a console-only UML kernel as a RetroOS process.
2. Run one nested Linux userspace program.
3. Derive explicit RetroOS execution, address-space, and event operations from
   that experience.
4. Define device-capability, MMIO, DMA, and interrupt traits.
5. Exercise them with a simple emulated PCI device under QEMU.
6. Add a Linux PCI/DMA/IRQ bridge and run an existing Linux driver.
7. Attempt the laptop's Qualcomm WCN785x/ath12k stack.
8. Export a socket or packet service from Linux back to RetroOS.
9. Separately test RetroOS running recursively against the same abstraction.

This is deliberately an exploration note, not an immediate implementation
commitment. The first milestone is discovering whether the recursive kernel
boundary is coherent; physical Wi-Fi support is a demanding eventual proof.
