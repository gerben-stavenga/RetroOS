"""Independent mke2fs fixtures for ext4 feature compatibility tests."""

def compatibility_image(name, features, extra_args = "", files = 1, repetitions = 1):
    native.genrule(
        name = name + "_image",
        srcs = ["testdata/hello.txt"],
        outs = [name + ".img"],
        cmd = """
set -eu
ROOT="$(@D)/{name}-root"
mkdir -p "$$ROOT"
i=0
while [ "$$i" -lt {files} ]; do
  j=0
  while [ "$$j" -lt {repetitions} ]; do
    cat $(location testdata/hello.txt) >> "$$ROOT/file-$$i.txt"
    j=$$((j + 1))
  done
  i=$$((i + 1))
done
truncate -s 40M "$@"
/usr/sbin/mkfs.ext4 -q -F {extra_args} -O {features} -d "$$ROOT" "$@"
""".format(
            name = name,
            files = files,
            repetitions = repetitions,
            extra_args = extra_args,
            features = features,
        ),
    )
