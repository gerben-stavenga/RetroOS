#!/usr/bin/env python3
"""Run the paging proof harnesses without compiling the metal crate."""

import os
from pathlib import Path
import re
import subprocess
import tempfile


def item(source, declaration):
    # A rustfmt-style top-level item closes at column zero. Copy its source
    # verbatim, and let the verifier's compiler check its dependencies.
    matches = re.findall(r"^" + re.escape(declaration) + r"\b.*?^\}$",
                         source, re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise SystemExit(f"Expected one top-level {declaration}")
    return matches[0]


def main():
    verify = Path(__file__).resolve().parent
    metal = verify.parent
    paging = (metal / "src/paging2.rs").read_text()
    kani = [os.environ.get("KANI", "kani"), "--output-format", "terse"]
    with tempfile.TemporaryDirectory(prefix="retroos-kani-") as directory:
        proof = Path(directory) / "pae_pdpte.rs"
        proof.write_text(item(paging, "fn encode_pae_pdpte") + "\n\n" + (verify / proof.name).read_text())
        subprocess.run([*kani, str(proof)], check=True)

        proof = Path(directory) / "single_core_fork.rs"
        production = [item(paging, declaration) for declaration in
                      ("pub mod flags", "pub trait Entry", "fn owns_frame",
                       "fn share_and_copy", "fn fork_generic")]
        proof.write_text("\n\n".join([*production, (verify / proof.name).read_text()]))
        subprocess.run([*kani, str(proof)], check=True)
        proof = Path(directory) / "page_supply.rs"
        abi = metal.parent / "arch-abi/src"
        page_size = next(line for line in (abi / "lib.rs").read_text().splitlines()
                         if line.startswith("pub const PAGE_SIZE:"))
        proof.write_text((abi / "page_supply.rs").read_text() + "\n" + page_size
                         + "\n" + (verify / proof.name).read_text())
        subprocess.run([*kani, str(proof)], check=True)
        proof = Path(directory) / "replace_mapping.rs"
        production = [item(paging, declaration) for declaration in
                      ("pub mod flags", "fn owns_frame", "pub(crate) fn replace_mapping")]
        proof.write_text("\n\n".join([*production, (verify / proof.name).read_text()]))
        subprocess.run([*kani, str(proof)], check=True)

        proof = Path(directory) / "single_core_tlb.rs"
        mapping = (metal / "src/mapping.rs").read_text()
        production = [item(mapping, declaration) for declaration in
                      ("pub(crate) struct Replace", "fn validate_range", "fn batch",
                       "pub(crate) fn replace_mappings")]
        flush = item(paging, "pub fn flush_tlb")
        proof.write_text("\n\n".join([
            *production, f"mod paging2 {{\nuse super::sync_hw_pdpt;\n"
                         f"pub(super) use super::PagingGuard;\n{flush}\n}}",
            (verify / proof.name).read_text(),
        ]))
        subprocess.run([*kani, str(proof)], check=True)


if __name__ == "__main__":
    main()
