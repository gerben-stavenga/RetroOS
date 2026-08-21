def _retroos_build_info_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".rs")
    ctx.actions.run_shell(
        arguments = [ctx.info_file.path, out.path],
        inputs = [ctx.info_file],
        outputs = [out],
        command = """set -eu
status="$1"
out="$2"
describe=unknown
dirty=0

while IFS=' ' read -r key value; do
    case "$key" in
        STABLE_RETROOS_GIT_DESCRIBE) describe="$value" ;;
        STABLE_RETROOS_GIT_DIRTY) dirty="$value" ;;
    esac
done < "$status"

case "$dirty" in
    0) dirty_rust=false ;;
    1) dirty_rust=true ;;
    *) echo "STABLE_RETROOS_GIT_DIRTY must be 0 or 1" >&2; exit 1 ;;
esac

describe_escaped="$(printf '%s' "$describe" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')"

cat > "$out" <<EOF
// Generated from Bazel workspace status; do not edit.
use core::fmt;

pub const GIT_DESCRIBE: &str = "$describe_escaped";
pub const GIT_DIRTY: bool = $dirty_rust;

pub struct VersionBanner;

impl fmt::Display for VersionBanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RetroOS kernel {}", GIT_DESCRIBE)?;
        if GIT_DIRTY {
            f.write_str("*")?;
        }
        Ok(())
    }
}
EOF
""",
        mnemonic = "RetroOSBuildInfo",
        progress_message = "Generating RetroOS build identity",
    )
    return [DefaultInfo(files = depset([out]))]


retroos_build_info = rule(
    implementation = _retroos_build_info_impl,
    attrs = {
        "stamp": attr.int(default = 1, values = [-1, 0, 1]),
    },
)
