#!/usr/bin/env python3
"""Checks for Linux volume selection and GRUB path generation."""

import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import tarfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/grub_module_install.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("grub_module_install", SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class GrubModuleInstallTest(unittest.TestCase):
    def test_grub_update_commands(self):
        for available, expected in [
            ({"update-grub": "/usr/sbin/update-grub", "grub-mkconfig": "/usr/bin/grub-mkconfig"},
             ["update-grub"]),
            ({"grub-mkconfig": "/usr/bin/grub-mkconfig"},
             ["/usr/bin/grub-mkconfig", "-o", "/boot/grub/grub.cfg"]),
            ({"grub2-mkconfig": "/usr/sbin/grub2-mkconfig"},
             ["/usr/sbin/grub2-mkconfig", "-o", "/boot/grub/grub.cfg"]),
        ]:
            with self.subTest(available=available), \
                 patch.object(installer.shutil, "which", side_effect=available.get), \
                 patch.object(installer.subprocess, "run") as run, \
                 patch.object(installer, "grub_config_path", return_value=Path("/boot/grub/grub.cfg")):
                installer.update_grub()
                run.assert_called_once_with(expected, check=True)
                run.reset_mock()
                installer.update_grub("/boot/grub2/grub.cfg")
                override = expected if expected == ["update-grub"] else expected[:2] + ["/boot/grub2/grub.cfg"]
                run.assert_called_once_with(override, check=True)

    def test_grub_update_requires_installed_tools(self):
        with patch.object(installer.shutil, "which", return_value=None), \
             patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "grub-mkconfig is missing"):
                installer.update_grub()
            run.assert_not_called()

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

    def test_one_supported_volume_is_selected_without_a_uuid(self):
        boot = {"path": "/dev/sda1", "uuid": "ea8c19a0-a2e3-4d14-9fd2-6955c176122c",
                "fstype": "ext4", "size": 1}
        self.assertEqual(installer.choose_c_for_host([boot], None, False), boot)
        self.assertEqual(installer.choose_c_for_host([boot], boot["uuid"], False), boot)
        fat = {"path": "/dev/sdb1", "uuid": "AAAA-BBBB", "fstype": "vfat", "size": 1}
        self.assertEqual(installer.choose_c_for_host([fat], None, False), fat)
        self.assertIsNone(installer.choose_c_for_host([], None, False))
        self.assertIsNone(installer.choose_c_for_host([fat], None, True))
        with self.assertRaisesRegex(ValueError, "Select one C: volume"):
            installer.choose_c_for_host([boot, fat], None, False)
        with self.assertRaisesRegex(ValueError, "either --c-ram or --c-uuid"):
            installer.choose_c_for_host([boot], boot["uuid"], True)

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
        self.assertEqual(create.call_args.args[0], Path(temporary) / "DOS")
        self.assertEqual(run.call_args_list[1].args[0], ["umount", temporary])

    def test_new_home_uses_installing_users_uid_and_gid(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "retroos"
            with patch.dict(installer.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1001"}), \
                 patch.object(installer.os, "chown") as chown:
                installer.create_c_home(home)
            chown.assert_called_once_with(home, 1000, 1001)
            self.assertEqual(home.stat().st_mode & 0o7777, 0o755)
            with patch.object(installer.os, "chown") as chown:
                installer.create_c_home(home)
            chown.assert_not_called()

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

    def test_configs_load_from_selected_c_instead_of_boot_filesystem(self):
        for fstype, c_dir, expected in [("ext4", "/DOS", "/DOS/RETROOS"), ("vfat", None, "/RETROOS")]:
            plan = {"boot_uuid": "AAAA-BBBB", "grub_release": "/boot/retroos/releases/1234",
                    "c_uuid": "CCCC-DDDD", "c_dir": c_dir, "c_fstype": fstype}
            entries = installer.grub_entries(plan)
            self.assertIn("search --no-floppy --fs-uuid --set=root AAAA-BBBB", entries)
            self.assertIn("search --no-floppy --fs-uuid --set=retroos_config CCCC-DDDD", entries)
            self.assertIn(f"module2 ($retroos_config){expected}/RETROOS.INI retroos.config=ini", entries)
            self.assertIn(f"module2 ($retroos_config){expected}/BOOT.INI retroos.config=boot", entries)
            self.assertNotIn("module2 /boot/retroos/RETROOS.INI", entries)
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "grub.cfg"
                config.write_text(entries)
                installer.subprocess.run(["grub-script-check", str(config)], check=True)

    def test_seed_configs_and_showcase_preserves_disk_edits_on_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            (stage / "showcase/GAMES").mkdir(parents=True)
            (stage / "BOOT.INI").write_text("boot mounts")
            (stage / "RETROOS.INI").write_text("legacy settings")
            game = stage / "showcase/GAMES/TEST.EXE"
            game.write_bytes(b"game")
            game.chmod(0o555)
            home = root / "C"
            home.mkdir()
            with patch.object(installer.os, "chown"):
                self.assertEqual(installer.seed_c_files(home, stage, True), 1)
                self.assertEqual((home / "RETROOS/RETROOS.INI").read_text(), "legacy settings")
                self.assertEqual((home / "GAMES/TEST.EXE").stat().st_mode & 0o777, 0o755)
                (home / "RETROOS/RETROOS.INI").write_text("edited in RetroOS")
                (home / "RETROOS/BOOT.INI").write_text("custom mounts")
                (home / "GAMES/TEST.EXE").write_bytes(b"user game")
                self.assertEqual(installer.seed_c_files(home, stage, True), 0)
            self.assertEqual((home / "RETROOS/RETROOS.INI").read_text(), "edited in RetroOS")
            self.assertEqual((home / "RETROOS/BOOT.INI").read_text(), "custom mounts")
            self.assertEqual((home / "GAMES/TEST.EXE").read_bytes(), b"user game")

    def test_unmounted_fat_is_mounted_at_c_root_and_cleaned_up_on_failure(self):
        volume = {"fstype": "vfat", "uuid": "AAAA-BBBB", "mountpoints": []}
        with patch.object(installer.subprocess, "run") as run, \
             patch.object(installer, "filesystem", return_value={"uuid": "AAAA-BBBB", "fsroot": "/"}), \
             patch.object(installer, "create_c_home"):
            with self.assertRaisesRegex(RuntimeError, "seed failed"):
                with installer.mounted_c_home(volume) as home:
                    self.assertNotIn("home/retroos", str(home))
                    raise RuntimeError("seed failed")
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[:6], ["mount", "-t", "vfat", "-o", "rw", "UUID=AAAA-BBBB"])
        self.assertEqual(run.call_args_list[1].args[0], ["umount", command[6]])

    def test_migration_keeps_custom_mounts_but_updates_selected_c(self):
        previous = ('[bundle]\nsource=module\nsubdir=/\n'
                    '[mount "old-data"]\nsource=UUID=AAAA-BBBB\npath=/old\ndrive=C\naccess=rw\n'
                    '[mount "extra"]\nsource=UUID=EEEE-FFFF\npath=/extra\ndrive=D\naccess=ro\n')
        text = installer.migrate_boot_configuration({"c_uuid": "CCCC-DDDD", "root_uuid": None}, previous)
        self.assertNotIn("AAAA-BBBB", text)
        self.assertIn("CCCC-DDDD", text)
        self.assertIn('mount "extra"', text)
        self.assertIn("EEEE-FFFF", text)
        ram = installer.migrate_boot_configuration({"c_uuid": None, "root_uuid": None}, previous)
        self.assertIn("source=bundle", ram)
        self.assertNotIn("AAAA-BBBB", ram)

    def test_prepare_copy_showcase_and_legacy_settings_without_writing_c(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image.img"
            image.write_bytes(b"image")
            boot = root / "boot"
            boot.mkdir()
            (boot / "RETROOS.INI").write_text("legacy user settings")
            (root / "etc").mkdir()
            (root / "etc/RETROOS.INI").write_text("default")
            game = root / "TEST.DAT"
            game.write_bytes(b"game")
            with tarfile.open(root / "showcase.tar", "w") as archive:
                archive.add(game, arcname="GAMES/TEST.DAT")
            volume = {"path": "/dev/data", "uuid": "CCCC-DDDD", "fstype": "vfat",
                      "size": 100, "mountpoints": []}
            boot_fs = {"uuid": "AAAA-BBBB", "fstype": "ext4", "target": str(root), "fsroot": "/"}
            def extract(image, name, target):
                target.write_bytes(name.encode())
            with patch.object(installer, "ROOT", root), \
                 patch.object(installer, "STAGE_ROOT", root / "stage"), \
                 patch.object(installer.os, "geteuid", return_value=1000), \
                 patch.object(installer, "candidates", return_value=[volume]), \
                 patch.object(installer, "filesystem", return_value=boot_fs), \
                 patch.object(installer, "grub_config_path", return_value=root / "grub.cfg"), \
                 patch.object(installer, "extract_boot_file", side_effect=extract):
                installer.prepare(image, boot, volume["uuid"], None, copy_showcase=True)
                stage = Path((root / "stage/selected").read_text().strip())
                self.assertEqual((stage / "RETROOS.INI").read_text(), "legacy user settings")
                self.assertTrue((stage / "showcase/GAMES/TEST.DAT").is_file())
                self.assertIn("showcase/GAMES/TEST.DAT", json.loads((stage / "checksums.json").read_text()))
                installer.prepare(image, boot, volume["uuid"], None)
                no_showcase = Path((root / "stage/selected").read_text().strip())
                self.assertNotEqual(stage, no_showcase)
                self.assertFalse((no_showcase / "showcase").exists())

    def test_core_directory_supplies_matching_files_without_usb_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kernel").mkdir()
            (root / "kernel/kernel.elf").write_bytes(b"kernel")
            (root / "retroos-base.img.gz").write_bytes(b"core")
            output = root / "output"
            installer.extract_boot_file(root, "kernel.elf", output)
            self.assertEqual(output.read_bytes(), b"kernel")
            installer.extract_boot_file(root, "retroos-base.img.gz", output)
            self.assertEqual(output.read_bytes(), b"core")

    def test_module_cli_accepts_copy_showcase(self):
        with patch.object(sys, "argv", ["installer", "--prepare", "--copy-showcase"]), \
             patch.object(installer, "prepare") as prepare:
            installer.main()
        self.assertTrue(prepare.call_args.args[-1])

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
        self.assertIn('source=UUID=12345678-1234-1234-1234-123456789abc\npath=/\naccess=ro', text)
        self.assertIn('source=bundle\npath=/dos\ndrive=C\naccess=ram', text)


if __name__ == "__main__":
    unittest.main()
