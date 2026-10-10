#!/usr/bin/env python3
"""Checks for Linux volume selection and GRUB path generation."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/grub_module_install.py"
spec = importlib.util.spec_from_file_location("grub_module_install", SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class GrubModuleInstallTest(unittest.TestCase):
    def test_enumerates_supported_non_usb_non_esp_volumes(self):
        devices = {"blockdevices": [
            {"type": "disk", "tran": "sata", "children": [
                {"type": "part", "path": "/dev/sda1", "fstype": "vfat", "uuid": "AAAA-BBBB",
                 "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "size": 100, "mountpoints": ["/boot/efi"]},
                {"type": "part", "path": "/dev/sda2", "fstype": "ext4",
                 "uuid": "ea8c19a0-a2e3-4d14-9fd2-6955c176122c", "size": 200,
                 "mountpoints": ["/"]},
                {"type": "part", "path": "/dev/sda3", "fstype": "btrfs", "uuid": "ignored", "size": 300},
            ]},
            {"type": "disk", "tran": "usb", "children": [
                {"type": "part", "path": "/dev/sdb1", "fstype": "vfat", "uuid": "CCCC-DDDD", "size": 400}
            ]},
        ]}
        with patch.object(installer, "output", return_value=json.dumps(devices)):
            self.assertEqual([v["path"] for v in installer.candidates()], ["/dev/sda2"])

    def test_ambiguous_c_requires_uuid(self):
        volumes = [{"path": "/dev/a", "uuid": "AAAA-BBBB", "fstype": "vfat", "size": 1},
                   {"path": "/dev/b", "uuid": "CCCC-DDDD", "fstype": "vfat", "size": 1}]
        with self.assertRaisesRegex(ValueError, "Select one C: volume"):
            installer.choose_c_volume(volumes, None)
        self.assertEqual(installer.choose_c_volume(volumes, "cccc-dddd"), volumes[1])

    def test_btrfs_host_defaults_to_ram_even_with_ext4_boot(self):
        boot = {"path": "/dev/sda1", "uuid": "ea8c19a0-a2e3-4d14-9fd2-6955c176122c",
                "fstype": "ext4", "size": 1}
        self.assertIsNone(installer.choose_c_for_host([boot], None, False, "btrfs"))
        self.assertEqual(installer.choose_c_for_host([boot], boot["uuid"], False, "btrfs"), boot)
        with self.assertRaisesRegex(ValueError, "either --c-ram or --c-uuid"):
            installer.choose_c_for_host([boot], boot["uuid"], True, "btrfs")

    def test_unmounted_ext4_is_mounted_for_home_creation_then_unmounted(self):
        volume = {"path": "/dev/sdb2", "fstype": "ext4",
                  "uuid": "ea8c19a0-a2e3-4d14-9fd2-6955c176122c", "mountpoints": []}
        with patch.object(installer.subprocess, "run") as run, \
             patch.object(installer, "filesystem", return_value={"uuid": volume["uuid"], "fsroot": "/"}), \
             patch.object(installer, "create_c_home") as create:
            installer.ensure_c_home(volume)
        self.assertEqual(run.call_args_list[0].args[0][:5],
                         ["mount", "-t", "ext4", "-o", "rw"])
        self.assertEqual(run.call_args_list[0].args[0][5], "UUID=" + volume["uuid"])
        temporary = run.call_args_list[0].args[0][6]
        self.assertEqual(create.call_args.args[0], Path(temporary) / "home/retroos")
        self.assertEqual(run.call_args_list[1].args[0], ["umount", temporary])

    def test_custom_ext4_c_directory_is_passed_to_grub(self):
        self.assertEqual(installer.validate_c_dir("/DOS/RETROOS"), "/DOS/RETROOS")
        with self.assertRaises(ValueError):
            installer.validate_c_dir("/home/../etc")
        plan = {"boot_uuid": "AAAA-BBBB", "grub_release": "/retroos/releases/1234",
                "c_uuid": "ea8c19a0-a2e3-4d14-9fd2-6955c176122c", "c_dir": "/DOS/RETROOS",
                "root_uuid": None}
        self.assertIn("subdir=/DOS/RETROOS", installer.mount_configuration(plan))
        self.assertNotIn("retroos.c-root=", installer.grub_entries(plan))
        self.assertIn("RETROOS.INI retroos.config=ini", installer.grub_entries(plan))
        self.assertIn("BOOT.INI retroos.config=boot", installer.grub_entries(plan))
        self.assertNotIn("[environment]", installer.mount_configuration(plan))

    def test_separate_boot_grub_path_and_ram_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            boot = Path(directory)
            release = boot / "retroos/releases/1234"
            self.assertEqual(installer.grub_path(release, {"target": str(boot), "fsroot": "/"}),
                             "/retroos/releases/1234")
            self.assertEqual(installer.grub_path(release, {"target": str(boot), "fsroot": "/@"}),
                             "/@/retroos/releases/1234")
        plan = {"boot_uuid": "AAAA-BBBB", "grub_release": "/retroos/releases/1234",
                "c_uuid": None, "root_uuid": None}
        entries = installer.grub_entries(plan)
        self.assertIn("multiboot2 /retroos/releases/1234/kernel.elf ram-overlay", entries)
        self.assertIn("module2 /retroos/releases/1234/retroos-base.img.gz retroos.mount=/", entries)
        self.assertNotIn("retroos.c-uuid=", entries)

    def test_ram_c_with_physical_linux_root_is_explicit(self):
        text = installer.mount_configuration({"root_uuid": "12345678-1234-1234-1234-123456789abc", "c_uuid": None})
        self.assertIn('source=UUID=12345678-1234-1234-1234-123456789abc\npath=/\naccess=rw', text)
        self.assertIn('source=bundle\npath=/home/retroos\ndrive=C\naccess=ram', text)


if __name__ == "__main__":
    unittest.main()
