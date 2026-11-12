import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from patcher.agy import patcher as agy
from patcher.ide import patcher as ide
from patcher.ide.discovery import VersionStatus


# Окружение проверок из Windows x64 agy 1.5.5.
AUTH_PREFIX = bytes.fromhex("45 31 c9 e8 5b 04 00 00 48 85 db 75 41")
AUTH_SUFFIX = bytes.fromhex("48 8b 54 24 70 48 89 50 60 48 8b 54 24 78 48 89 50 68")
AUTH_ORIG = bytes.fromhex("80 78 08 00 74 3b")
AUTH_PATCH = bytes.fromhex("c6 40 08 01 90 90")
CLI_ORIG = bytes.fromhex("48 85 c0 0f 84 01 00 00 00 80 78 08 00 0f 85 01 00 00 00")
CLI_PATCH = CLI_ORIG[:9] + bytes.fromhex("48 85 c0 90") + CLI_ORIG[13:]
UPDATER = (
    b'let result=resume(await wait(fetch({existingBinaryValid:valid,existingValidVersion:version,'
    b'releaseBaseUrl:url,retryOptions:retry,outputChannel:log})));'
    b'if(result.unreachableFallback)return report==null||report({cacheHit:!0,\n'
    b'downloadReason:"manifest_unreachable_fallback",cliVersion:version,...details}),binary;'
)


def _binary(auth=AUTH_ORIG, cli=CLI_ORIG, machine=0x8664):
    header = bytearray(0x46)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    struct.pack_into("<4sH", header, 0x40, b"PE\x00\x00", machine)
    return bytes(header) + AUTH_PREFIX + auth + AUTH_SUFFIX + cli


class IdeBackendTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name, "agy.exe")
        self.backup = self.path.with_suffix(".exe.agybak")
        self.path.write_bytes(_binary())
        copy_to_user_bin = patch.object(agy, "_copy_to_user_bin")
        copy_to_user_bin.start()
        self.addCleanup(copy_to_user_bin.stop)

    def test_existing_cli_patch_keeps_original_backup(self):
        self.backup.write_bytes(_binary())
        self.path.write_bytes(_binary(cli=CLI_PATCH))

        self.assertTrue(agy.do_patch_agy(str(self.path), ide_backend=True))
        self.assertEqual(self.path.read_bytes(), _binary(auth=AUTH_PATCH, cli=CLI_PATCH))
        self.assertTrue(agy.do_patch_agy(str(self.path), ide_backend=True))
        self.assertEqual(self.backup.read_bytes(), _binary())

        with patch("patcher.cli.confirmed", return_value=True):
            agy.do_restore_agy(str(self.path), ide_backend=True)
        self.assertEqual(self.path.read_bytes(), _binary())

    def test_cli_also_applies_known_backend_signature(self):
        self.assertTrue(agy.do_patch_agy(str(self.path)))
        self.assertEqual(self.path.read_bytes(), _binary(auth=AUTH_PATCH, cli=CLI_PATCH))
        self.assertEqual(agy.get_status(self.path)[0], "patched")
        self.assertEqual(self.backup.read_bytes(), _binary())

    def test_ide_refuses_ambiguous_signature_or_other_architecture(self):
        ambiguous = _binary() + AUTH_PREFIX + AUTH_PATCH + AUTH_SUFFIX
        for binary in (ambiguous, _binary(machine=0xAA64), b"MZ"):
            with self.subTest(size=len(binary)):
                self.path.write_bytes(binary)
                self.assertFalse(agy.do_patch_agy(str(self.path), ide_backend=True))
                self.assertEqual(self.path.read_bytes(), binary)
                self.assertFalse(self.backup.exists())

    @unittest.skipUnless(sys.platform == "win32", "IDE backend is discovered on Windows")
    def test_ide_upgrades_installation_with_main_js_already_patched(self):
        app = self.path.parent / "app"
        main_js = app / "out" / "main.js"
        extension = app / "extensions" / "agy" / "vscode" / "extension.js"
        main_js.parent.mkdir(parents=True)
        extension.parent.mkdir(parents=True)
        original = b"// " + b"x" * 4096 + b"\r\nresetIsTierGCPTos(),this.user.isGoogleInternal\r\n"
        patched = original.replace(b"this.user.isGoogleInternal", b"true")
        main_js.write_bytes(patched)
        main_js.with_suffix(".js.bak").write_bytes(original)
        extension.write_bytes(UPDATER)

        with (
            patch.object(ide, "find_ide_backend", return_value=str(self.path)),
            patch.object(ide, "check_ag_version", return_value=(VersionStatus.OK, "2.6.0")),
            patch.object(ide, "print_panel") as panel,
        ):
            ide.do_patch(str(main_js))
            self.assertEqual(panel.call_args.args[0], "PATCH COMPLETE")
            self.assertEqual(main_js.read_bytes(), patched)
            self.assertEqual(self.path.read_bytes(), _binary(auth=AUTH_PATCH))
            pinned = extension.read_bytes()
            self.assertIn(b'if(valid&&version){log.appendLine(', pinned)
            self.assertIn(b'return binary;}' + UPDATER, pinned)

            ide.do_patch(str(main_js))
            self.assertEqual(extension.read_bytes(), pinned)
            with patch("patcher.cli.confirmed", return_value=True):
                ide.do_restore(str(main_js))
            self.assertEqual(extension.read_bytes(), UPDATER)
            self.assertEqual(main_js.read_bytes(), original)
            self.assertEqual(self.path.read_bytes(), _binary())

    @unittest.skipUnless(sys.platform == "win32", "IDE backend is discovered on Windows")
    def test_missing_backend_does_not_report_complete(self):
        main_js = self.path.with_name("main.js")
        content = b"first\r\nresetIsTierGCPTos(),this.user.isGoogleInternal\r\n"
        main_js.write_bytes(content)
        with (
            patch.object(ide, "find_ide_backend", return_value=""),
            patch.object(ide, "check_ag_version", return_value=(VersionStatus.OK, "2.6.0")),
            patch.object(ide, "_ide_cache_dirs", return_value=[]),
            patch.object(ide, "print_panel") as panel,
        ):
            ide.do_patch(str(main_js))
        self.assertEqual(panel.call_args.args[0], "MAIN.JS PATCHED")
        self.assertEqual(main_js.read_bytes(), content.replace(b"this.user.isGoogleInternal", b"true"))
        self.assertEqual(main_js.with_suffix(".js.bak").read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
