#!/bin/bash
# Generate rust-project.json and .vscode/settings.json for rust-analyzer.
# Run from the retro-rs directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# --- Detect sysroot_src ---
SYSROOT="$(rustc --print sysroot 2>/dev/null)"
SYSROOT_SRC="$SYSROOT/lib/rustlib/src/rust/library"
if [ ! -d "$SYSROOT_SRC" ]; then
    echo "ERROR: sysroot_src not found at $SYSROOT_SRC" >&2
    echo "Run: rustup component add rust-src" >&2
    exit 1
fi

# --- Discover crates ---
# Library crates: */src/lib.rs (top-level dirs only)
LIB_CRATES=()
for f in */src/lib.rs; do
    [ -f "$f" ] || continue
    name="${f%%/src/lib.rs}"
    LIB_CRATES+=("$name")
done

# App crates: apps/*/src/main.rs
APP_CRATES=()
for f in apps/*/src/main.rs; do
    [ -f "$f" ] || continue
    name="${f#apps/}"
    name="${name%%/src/main.rs}"
    APP_CRATES+=("$name")
done

ALL_CRATES=("${LIB_CRATES[@]}" "${APP_CRATES[@]}")

echo "Library crates: ${LIB_CRATES[*]}"
echo "App crates:     ${APP_CRATES[*]}"

# --- Build crate index (name -> position) ---
declare -A CRATE_INDEX
for i in "${!ALL_CRATES[@]}"; do
    CRATE_INDEX["${ALL_CRATES[$i]}"]=$i
done

# --- Detect dependencies for a crate ---
# Scans source files for `use <lib>::` or `<lib>::` references
detect_deps() {
    local crate_dir="$1"
    local src_dir="$crate_dir/src"
    local deps=()

    for lib in "${LIB_CRATES[@]}"; do
        # Don't depend on yourself
        [ "$crate_dir" = "$lib" ] && continue
        # Grep for use <lib>:: or bare <lib>::
        if grep -rq "use ${lib}::\|${lib}::" "$src_dir" 2>/dev/null; then
            deps+=("$lib")
        fi
    done
    echo "${deps[@]}"
}

# --- Format a deps array as JSON ---
format_deps_json() {
    local deps=("$@")
    if [ ${#deps[@]} -eq 0 ]; then
        echo "[]"
        return
    fi
    local result="["
    local first=true
    for dep in "${deps[@]}"; do
        local idx="${CRATE_INDEX[$dep]}"
        if [ "$first" = true ]; then
            first=false
        else
            result+=", "
        fi
        result+="{\"crate\": $idx, \"name\": \"$dep\"}"
    done
    result+="]"
    echo "$result"
}

# --- Build the crates JSON array ---
build_crates_json() {
    local use_abs_paths="$1"
    local result=""
    local first_crate=true

    for name in "${ALL_CRATES[@]}"; do
        # Determine root_module and source dir
        local src_dir
        local root_module
        if [ -f "$name/src/lib.rs" ]; then
            src_dir="$name"
            if [ "$use_abs_paths" = true ]; then
                root_module="$SCRIPT_DIR/$name/src/lib.rs"
            else
                root_module="$name/src/lib.rs"
            fi
        else
            src_dir="apps/$name"
            if [ "$use_abs_paths" = true ]; then
                root_module="$SCRIPT_DIR/apps/$name/src/main.rs"
            else
                root_module="apps/$name/src/main.rs"
            fi
        fi

        # Detect deps
        local dep_list
        read -ra dep_list <<< "$(detect_deps "$src_dir")"
        local deps_json
        deps_json="$(format_deps_json "${dep_list[@]}")"

        # Cfg
        local cfg
        if [ "$name" = "kernel" ]; then
            cfg='["debug_assertions", "feature=\"kernel\""]'
        else
            cfg='["debug_assertions"]'
        fi

        if [ "$first_crate" = true ]; then
            first_crate=false
        else
            result+=","
        fi

        result+="
    {
      \"display_name\": \"$name\",
      \"root_module\": \"$root_module\",
      \"edition\": \"2024\",
      \"deps\": $deps_json,
      \"is_workspace_member\": true,
      \"cfg\": $cfg,
      \"env\": {
        \"CARGO_CRATE_NAME\": \"$name\"
      },
      \"is_proc_macro\": false
    }"
    done

    echo "$result"
}

# --- Generate rust-project.json (absolute paths) ---
echo "Generating rust-project.json..."
crates_abs="$(build_crates_json true)"
cat > rust-project.json <<REOF
{
  "sysroot_src": "$SYSROOT_SRC",
  "crates": [$crates_abs
  ]
}
REOF
echo "  -> rust-project.json"

# --- Generate .vscode/settings.json (relative paths) ---
echo "Generating .vscode/settings.json..."
mkdir -p .vscode
crates_rel="$(build_crates_json false)"
cat > .vscode/settings.json <<VEOF
{
    "rust-analyzer.linkedProjects": [
        {
            "sysroot_src": "$SYSROOT_SRC",
            "crates": [$crates_rel
            ]
        }
    ],
    "rust-analyzer.checkOnSave": false,
    "rust-analyzer.cargo.buildScripts.enable": false,
    "rust-analyzer.procMacro.enable": false
}
VEOF
echo "  -> .vscode/settings.json"

echo "Done. Restart rust-analyzer to pick up changes."
