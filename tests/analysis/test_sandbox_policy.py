import tempfile
import unittest
from pathlib import Path

from pmca.analysis.sandbox_policy import (
    SandboxPolicyError,
    build_sandbox_policy,
    render_sandboxie_ini,
    validate_sandbox_policy,
    write_sandboxie_ini,
)


EXPECTED_PROBE_INI = """[A6400UpdaterLab]
Enabled=y
FileRootPath={sandbox_root}
AutoDelete=n
AutoRecover=n
DropAdminRights=y
RestrictDevices=y
SysCallLockDown=y
UseRuleSpecificity=y
AllowRawDiskRead=n
BlockLocalLoop=y
BlockNetParam=y
BlockNetworkFiles=y
AllowNetworkAccess=*,n
NetworkAccess=*,Block
ClosePrintSpooler=y
CopyLimitKb=65536
CopyLimitSilent=y
ProcessLimit=12
NotifyInternetAccessDenied=y
NotifyStartRunAccessDenied=y
ProcessGroup=<StartRunAccess>,powershell.exe
ClosedIpcPath=!<StartRunAccess>,*
"""


class SandboxPolicyTests(unittest.TestCase):
    def test_probe_policy_is_exact_and_renders_deterministically(self):
        policy = build_sandbox_policy("probe")
        validated = validate_sandbox_policy(policy)

        self.assertEqual(validated, policy)
        self.assertIsNot(validated, policy)
        self.assertIsNot(validated["settings"], policy["settings"])

        with tempfile.TemporaryDirectory() as temporary:
            repository_root = Path(temporary)
            expected_root = (
                repository_root
                / ".artifacts"
                / "sandbox"
                / "a6400-updater"
                / "box-root"
            ).resolve()
            expected = EXPECTED_PROBE_INI.format(sandbox_root=expected_root)
            self.assertEqual(
                render_sandboxie_ini(policy, repository_root),
                expected,
            )
            self.assertEqual(
                render_sandboxie_ini(policy, repository_root),
                expected,
            )

    def test_updater_profile_has_a_different_fixed_allowlist(self):
        probe = build_sandbox_policy("probe")
        updater = build_sandbox_policy("updater")

        self.assertEqual(probe["allowed_processes"], ["powershell.exe"])
        self.assertEqual(
            updater["allowed_processes"],
            ["Update_ILCE6400V200.exe"],
        )
        self.assertIn(
            ["ProcessGroup", "<StartRunAccess>,Update_ILCE6400V200.exe"],
            updater["settings"],
        )

    def test_unsafe_or_ambiguous_policy_is_rejected(self):
        cases = []

        missing_drop_rights = build_sandbox_policy("probe")
        missing_drop_rights["settings"].remove(["DropAdminRights", "y"])
        cases.append(missing_drop_rights)

        permissive_network = build_sandbox_policy("probe")
        self._replace(permissive_network, "NetworkAccess", "*,Allow")
        cases.append(permissive_network)

        raw_disk = build_sandbox_policy("probe")
        self._replace(raw_disk, "AllowRawDiskRead", "y")
        cases.append(raw_disk)

        direct_host_write = build_sandbox_policy("probe")
        direct_host_write["settings"].append(["OpenFilePath", "C:\\Users"])
        cases.append(direct_host_write)

        unknown_setting = build_sandbox_policy("probe")
        unknown_setting["settings"].append(["MysteryOption", "y"])
        cases.append(unknown_setting)

        absolute_output = build_sandbox_policy("probe")
        absolute_output["trace_root"] = "C:/trace"
        cases.append(absolute_output)

        traversing_root = build_sandbox_policy("probe")
        traversing_root["sandbox_root"] = ".artifacts/sandbox/../outside"
        cases.append(traversing_root)

        duplicate_setting = build_sandbox_policy("probe")
        duplicate_setting["settings"].append(["Enabled", "y"])
        cases.append(duplicate_setting)

        wrong_allowlist = build_sandbox_policy("probe")
        wrong_allowlist["allowed_processes"] = ["powershell.exe", "cmd.exe"]
        cases.append(wrong_allowlist)

        boolean_schema = build_sandbox_policy("probe")
        boolean_schema["schema_version"] = True
        cases.append(boolean_schema)

        for policy in cases:
            with self.subTest(policy=policy):
                with self.assertRaises(SandboxPolicyError):
                    validate_sandbox_policy(policy)

    def test_render_rejects_a_repository_root_that_is_a_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository_file = Path(temporary) / "not-a-directory"
            repository_file.write_text("x", encoding="utf-8")

            with self.assertRaises(SandboxPolicyError):
                render_sandboxie_ini(build_sandbox_policy("probe"), repository_file)

    def test_writer_is_confined_to_the_fixed_ignored_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository_root = Path(temporary)
            output = (
                repository_root
                / ".artifacts"
                / "sandbox"
                / "a6400-updater"
                / "Sandboxie.ini"
            )
            write_sandboxie_ini(
                output,
                build_sandbox_policy("probe"),
                repository_root,
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                render_sandboxie_ini(build_sandbox_policy("probe"), repository_root),
            )

            with self.assertRaises(SandboxPolicyError):
                write_sandboxie_ini(
                    repository_root / "Sandboxie.ini",
                    build_sandbox_policy("probe"),
                    repository_root,
                )

    @staticmethod
    def _replace(policy, name, value):
        for setting in policy["settings"]:
            if setting[0] == name:
                setting[1] = value
                return
        raise AssertionError(f"missing setting: {name}")


if __name__ == "__main__":
    unittest.main()
