#!/usr/bin/env python3
"""Translate a run.sh program path into Rust-DOS shell startup lines."""
import re
import sys


def startup_lines(command):
    # Leave explicit multi-line DOS scripts alone. For a program path, change
    # into its directory so games find their WADs, graphics and config files.
    if "\n" in command or "\r" in command:
        return command.splitlines()
    match = re.fullmatch(r'\s*(?:"([^"]+)"|(\S+))(.*)', command)
    if not match:
        return []
    quoted, bare, arguments = match.groups()
    executable = (quoted or bare).replace("/", "\\")
    if "\\" not in executable:
        return [command]
    directory, name = executable.rsplit("\\", 1)
    if not name:
        return [command]
    directory = directory or "\\"
    lines = []
    if len(directory) >= 2 and directory[1] == ":":
        lines.append(directory[:2])
    # Rust-DOS's CD command takes the whole remainder literally, including
    # spaces; quote characters become part of the directory name.
    lines.append(f'CD {directory}')
    lines.append((f'"{name}"' if quoted else name) + arguments)
    return lines


if __name__ == "__main__":
    for line in startup_lines(sys.argv[1]):
        print(line)
