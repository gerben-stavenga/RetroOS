# Arch-metal verification

Run the paging proofs with [Kani 0.68.0](https://model-checking.github.io/kani/install-guide.html).

```sh
python3 arch-metal/verify/run.py
```

The runner assembles temporary Rust crates from production source and the
harnesses in this directory.

| Harness | Guarantee | Boundary |
| --- | --- | --- |
| `hardware_pdpte_contract` | Every encoding clears reserved bits and preserves a representable directory address. | Rust encoder. The specification follows [Intel SDM Vol. 3A, Table 4-8](https://cdrdv2-public.intel.com/671190/253668-sdm-vol-3a.pdf) and [AMD APM Vol. 2, legacy-mode PAE](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf). |
| `owned_frame_reference_transition` | Retain adds one reference. Release subtracts one share or transfers the exclusive reference. Another frame's count stays intact. | One operation on resident metadata for an already-owned frame, with atomics treated sequentially. Retain requires fewer than 254 existing references. |
| `reserve_transition_preserves_frame_order` | Donation adds exactly its supplied frame. Taking removes the top frame and preserves the remaining frames. An empty reserve yields no frame. | One CPU-local stack operation. Donation requires a nonzero frame and a spare slot. |
| `replacement_releases_exactly_the_displaced_owned_frame` | Replacement publishes the new slot before requesting release of the old owned backing, including inaccessible owned pages. It leaves the neighboring slot intact and never requests release of borrowed backing. | The incoming reference is already owned. The hardware store and release request are modeled boundaries. |
| `replacement_returns_with_no_stale_user_translations` | The replacement call reports the exact completed prefix. On return, guest reads, writes and instruction fetches use the frame and permissions for that prefix. A displaced exclusive frame cannot be reached, even if the second replacement failed. | Single-core 32-bit PAE, two adjacent user leaves, resident and unchanged permissive parents, non-global translations, and NXE enabled. Leaf replacement, the software guard and the CPU's CR3 reload are modeled. Guest accesses occur at the call boundary. |
| `pae_fork_isolates_the_first_write_in_both_orders` | Parent and child start with the original bytes and no writable translation. Each can write without changing the other's bytes. In either teardown order, the model's counts equal the reachable references and end at zero. | Single core, one present owned writable leaf, an empty child root, and three donated frames across fork and the first writes. Executes production `fork_generic` and `share_and_copy`. Physical copying, COW fault dispatch, root activation and teardown are modeled. |

The CPU model permits either a cached translation or a fresh walk. A leaf
store can leave the old translation cached. The production replacement
handler and its flush wrapper run in the harness. The model clears cached
translations at the CR3 reload.

The remaining single-core proof has to account for references in active and
parked roots, page-table pages, supplied reserves and the list of frames
awaiting return to the kernel. It also needs to establish that supervisor
accesses cannot use invalidated mappings within the call.

A single-core i386 guest under QEMU/KVM also reproduced a counterexample to
unconditional fork success. With a parent and 253 children sharing a table,
the next fork panics in `FrameOwnership::retain` at the 254-reference ceiling.
