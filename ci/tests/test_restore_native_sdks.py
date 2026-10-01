import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("restore_native_sdks", Path(__file__).parents[1] / "restore_native_sdks.py")
restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore)


class RestoreSelectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.packages = Path(self.tmp.name) / "packages"
        self.assets = {"libraries": {}}
        for name, (_, config) in restore.PACKAGES.items():
            relative = name.lower() + "/9.0.0"
            self.assets["libraries"][name + "/9.0.0"] = {"type": "package", "path": relative}
            for rid in restore.RIDS:
                path = self.packages / relative / "sdk" / rid / config
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# fixture only\n", encoding="utf-8")

    def test_resolves_exact_assets_for_each_supported_rid(self):
        for rid in restore.RIDS:
            with self.subTest(rid=rid):
                roots = restore.resolve_sdks(self.assets, self.packages, rid)
                self.assertEqual(set(roots), {entry[0] for entry in restore.PACKAGES.values()})
                self.assertTrue(all(version == "9.0.0" for _, version in roots.values()))
                self.assertTrue(all(root.name == rid for root, _ in roots.values()))

    def test_does_not_select_unrestored_newer_or_older_directories(self):
        for version in ("1.0.0", "99.0.0"):
            root = self.packages / "salts.native" / version / "sdk/linux-x64/lib/cmake/Salts"
            root.mkdir(parents=True)
            (root / "SaltsConfig.cmake").write_text("# stale\n")
        self.assertEqual(restore.resolve_sdks(self.assets, self.packages, "linux-x64")["SALTS_ROOT"][1], "9.0.0")

    def test_missing_selected_sdk_does_not_fall_back(self):
        selected = self.packages / "salts.native/9.0.0/sdk/linux-x64/lib/cmake/Salts/SaltsConfig.cmake"
        selected.unlink()
        stale = self.packages / "salts.native/8.0.0/sdk/linux-x64/lib/cmake/Salts"
        stale.mkdir(parents=True)
        (stale / "SaltsConfig.cmake").write_text("# stale\n")
        with self.assertRaisesRegex(ValueError, "missing"):
            restore.resolve_sdks(self.assets, self.packages, "linux-x64")

    def test_missing_and_ambiguous_package_fail(self):
        original = self.assets["libraries"].pop("Salts.Native/9.0.0")
        with self.assertRaisesRegex(ValueError, "found 0"):
            restore.resolve_sdks(self.assets, self.packages, "linux-x64")
        self.assets["libraries"]["Salts.Native/9.0.0"] = original
        self.assets["libraries"]["salts.native/9.1.0"] = original
        with self.assertRaisesRegex(ValueError, "found 2"):
            restore.resolve_sdks(self.assets, self.packages, "linux-x64")

    def test_escaping_and_absolute_paths_fail(self):
        for path in ("../../../escape", str(Path(self.tmp.name).resolve() / "absolute")):
            with self.subTest(path=path):
                self.assets["libraries"]["Salts.Native/9.0.0"]["path"] = path
                with self.assertRaises(ValueError):
                    restore.resolve_sdks(self.assets, self.packages, "linux-x64")

    def test_unknown_rid_fails(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            restore.resolve_sdks(self.assets, self.packages, "linux-arm64")

    def test_environment_newline_injection_fails(self):
        path = Path(self.tmp.name) / "env"
        with self.assertRaises(ValueError):
            restore.write_lines(path, ["SALTS_ROOT=good\nOTHER=bad"])
        self.assertFalse(path.exists())

    def test_environment_output_is_utf8_and_preserves_spaces(self):
        path = Path(self.tmp.name) / "env"
        restore.write_lines(path, ["SALTS_ROOT=C:/SDK path/Salts"])
        self.assertEqual(path.read_bytes(), b"SALTS_ROOT=C:/SDK path/Salts\n")


if __name__ == "__main__":
    unittest.main()
