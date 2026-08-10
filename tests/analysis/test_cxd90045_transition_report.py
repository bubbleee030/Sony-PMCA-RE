import ast
import copy
import json
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = (
    REPOSITORY_ROOT
    / "analysis"
    / "a6400-cxd90045-transition-boundary.json"
)


class Cxd90045TransitionReportTests(unittest.TestCase):
    def _validator(self):
        try:
            from pmca.analysis.cxd90045_transition_report import (
                Cxd90045TransitionReportError,
                validate_cxd90045_transition_report,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"CXD90045 transition validator is missing: {exc}")
        return validate_cxd90045_transition_report, Cxd90045TransitionReportError

    def _document(self):
        if not REPORT_PATH.is_file():
            self.fail(f"CXD90045 transition report is missing: {REPORT_PATH}")
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_report_locates_persistent_updater_partition_boundary(self):
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 5)
        self.assertTrue(document["host_transfer"]["raw_fdat_sent"])
        self.assertFalse(document["host_transfer"]["transform_before_usb"])
        self.assertEqual(
            [item["version"] for item in document["generation4_packages"]["examples"]],
            ["2.00", "4.00", "4.01"],
        )
        self.assertTrue(
            all(
                item["offline_decode_validated"]
                for item in document["generation4_packages"]["examples"]
            )
        )
        self.assertTrue(document["shared_static_artifacts"]["partinf_identical"])
        self.assertTrue(document["shared_static_artifacts"]["up_sh_identical"])
        self.assertTrue(
            document["shared_static_artifacts"]["secure_apps_identical"]
        )
        self.assertEqual(document["updater_partition"]["device"], "/dev/nflasha1")
        self.assertEqual(
            document["updater_partition"]["payload_partition_images"],
            ["nflasha3", "nflasha5", "nflasha7", "nflasha15"],
        )
        self.assertFalse(document["updater_partition"]["included_in_payload"])
        self.assertEqual(
            document["updater_partition"]["selection_stage"],
            "unresolved-before-or-outside-normal-userspace",
        )
        self.assertFalse(document["updater_partition"]["contents_acquired"])
        self.assertFalse(document["updater_partition"]["cbc_stage_located"])
        self.assertFalse(document["updater_partition"]["signature_verifier_located"])
        self.assertFalse(document["updater_partition"]["trust_anchor_located"])
        self.assertEqual(
            document["visible_runtime"]["normal_init_bootmode_values"],
            ["USB_CHARGE", "ADJUST", "BIS"],
        )
        self.assertEqual(
            document["visible_runtime"]["lsi_handoff"],
            "numeric-mode-via-message-queue",
        )
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])
        self.assertFalse(document["model_mismatch_safe"])

        stale_phrases = (
            "placing selection of the updater system before this normal userspace path",
            "plus pre-userspace mode selection",
            "selected before normal userspace",
        )
        serialized = json.dumps(document, sort_keys=True)
        for phrase in stale_phrases:
            self.assertNotIn(phrase, serialized)

    def test_packaged_selector_scan_stops_before_a_partition_selector_join(self):
        """Fails if an opaque packaged selector is mistaken for a boot selector."""
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 5)
        self.assertEqual(
            document["packaged_selector_scan"],
            {
                "updater_flag_state_proven": True,
                "lsi_notification_proven": True,
                "lsi_flag_delivery_path_proven": True,
                "packaged_flag_consumer_proven": True,
                "nflasha1_selector_join_proven": False,
                "updater_partition_selector_present": False,
                "bootin_direct_updater_selector": False,
                "external_or_opaque_selector_unresolved": True,
            },
        )
        evidence = document["packaged_selector_evidence"]
        self.assertEqual(len(evidence["libobj_literal_consumers"]), 4)
        self.assertEqual(
            [record["owner"]["start"] for record in evidence["libobj_literal_consumers"]],
            [0x83E5B8, 0x83E79C, 0x83F854, 0x83FA4C],
        )
        self.assertEqual(
            evidence["bootin"]["documented_application_modes"],
            ["normal", "adj", "usbj"],
        )
        self.assertEqual(evidence["bootin"]["named_reference_search"]["hits"], 0)
        self.assertFalse(
            evidence["selector_assessment"]["nflasha1_selector_join_proven"]
        )
        self.assertFalse(
            evidence["selector_assessment"][
                "numeric_or_indirect_selector_analysis_complete"
            ]
        )

    def test_packaged_lsi_delivery_stops_at_local_flag_state(self):
        """Fails if the proven LSI delivery is omitted or promoted to a selector."""
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertIn("lsi_delivery", document["packaged_selector_evidence"])
        evidence = document["packaged_selector_evidence"]["lsi_delivery"]
        self.assertEqual(
            evidence["sender"],
            {
                "source": "ud_send_lsi",
                "owner": {"start": 0x8734, "end": 0x87FC},
                "backup_read": {
                    "site": 0x8746,
                    "symbol": "Backup_read",
                    "record_id": 0x4B0000,
                },
                "message_allocation": {
                    "site": 0x876C,
                    "symbol": "osal_valloc_msg_wait",
                    "destination": 0x804B0376,
                    "size": 4,
                },
                "message_source_id": 0x004B0379,
                "source_id_store_site": 0x8786,
                "mode_parse_site": 0x878A,
                "mode_store_site": 0x8790,
                "send_site": 0x8794,
                "receive_site": 0x87B0,
                "receive_timeout_ms": 3000,
            },
        )
        self.assertEqual(
            evidence["receiver_registration"],
            {
                "source": "libobj",
                "owner": {"start": 0x83EBA8, "end": 0x83EC60},
                "queue_id": 0x004B0376,
                "queue_id_load_site": 0x83EC02,
                "callback": 0x83E5B8,
                "context": 0x1420D00,
                "registration_site": 0x83EC0E,
                "symbol": "osal_reg_msg_queue_cb",
            },
        )
        self.assertEqual(evidence["osal_dispatch"]["normalized_queue_id"], 0x376)
        self.assertEqual(evidence["osal_dispatch"]["queue_id_mask"], 0x7FFF)
        self.assertEqual(evidence["flag_callback"]["mode_payloads"], [2, 3, 4, 6])
        self.assertEqual(
            evidence["flag_callback"]["payload_routes"],
            [
                {
                    "mode": 2,
                    "compare_site": 0x83E5F2,
                    "branch_site": 0x83E5F4,
                    "branch_target": 0x83E660,
                    "extra_mode_path": None,
                },
                {
                    "mode": 3,
                    "compare_site": 0x83E5FE,
                    "branch_site": 0x83E602,
                    "branch_target": 0x83E61A,
                    "guard_branch_site": 0x83E600,
                    "guard_mismatch_target": 0x83E60A,
                    "extra_mode_path": "/setting/updater/mode3",
                },
                {
                    "mode": 4,
                    "compare_site": 0x83E5F6,
                    "branch_site": 0x83E5F8,
                    "branch_target": 0x83E614,
                    "extra_mode_path": "/setting/updater/mode1",
                },
                {
                    "mode": 6,
                    "compare_site": 0x83E5FA,
                    "branch_site": 0x83E5FC,
                    "branch_target": 0x83E604,
                    "extra_mode_path": "/setting/updater/mode6",
                },
            ],
        )
        self.assertTrue(evidence["claims"]["packaged_lsi_flag_delivery_path_proven"])
        self.assertTrue(evidence["claims"]["local_flag_state_management_proven"])
        self.assertTrue(evidence["claims"]["success_acknowledgement_path_proven"])
        self.assertFalse(evidence["claims"]["all_payloads_acknowledged_proven"])
        self.assertFalse(
            evidence["claims"]["pre_normal_partition_selector_join_proven"]
        )
        self.assertTrue(
            evidence["claims"]["external_or_opaque_selector_unresolved"]
        )

    def test_report_rejects_promoted_or_reconstructive_claims(self):
        validate, error_type = self._validator()
        document = self._document()
        candidates = []

        for field in (
            "camera_executed",
            "bypass_established",
            "installable",
            "model_mismatch_safe",
        ):
            candidate = copy.deepcopy(document)
            candidate[field] = True
            candidates.append(candidate)

        for field in (
            "included_in_payload",
            "contents_acquired",
            "cbc_stage_located",
            "signature_verifier_located",
            "trust_anchor_located",
        ):
            candidate = copy.deepcopy(document)
            candidate["updater_partition"][field] = True
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["updater_partition"]["selection_stage"] = "normal-userspace"
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["conclusion"] = "The updater partition is selected before normal userspace."
        candidates.append(candidate)

        for unsafe_conclusion in (
            "The updater partition is chosen prior to normal userspace.",
            "Every payload receives an acknowledgement.",
            "Recovery is validated and camera testing is eligible.",
            "The package is installable.",
        ):
            candidate = copy.deepcopy(document)
            candidate["conclusion"] = unsafe_conclusion
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["key_bytes"] = "not-allowed"
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["unexpected"] = "field"
        candidates.append(candidate)

        for field, value in document["packaged_selector_scan"].items():
            candidate = copy.deepcopy(document)
            candidate["packaged_selector_scan"][field] = not value
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["packaged_selector_evidence"]["libobj_literal_consumers"][0][
            "owner"
        ]["start"] += 2
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(error_type):
                validate(candidate)

    def test_real_packaged_selector_sources_match_when_available(self):
        from pmca.analysis.cxd90045_transition_report import (
            PACKAGED_SELECTOR_EVIDENCE,
        )
        from tools.static import export_a6400_packaged_selector_scan as exporter

        if not exporter.sources_available() or not exporter.dependencies_available():
            self.skipTest("pinned selector sources or parsers are unavailable")
        self.assertEqual(exporter.build_raw_export(), PACKAGED_SELECTOR_EVIDENCE)

        with mock.patch.object(exporter, "_sha256", return_value="0" * 64):
            with self.assertRaises(RuntimeError):
                exporter.build_raw_export()
        with mock.patch.object(exporter, "_cstring", return_value="wrong"):
            with self.assertRaises(RuntimeError):
                exporter.build_raw_export()

    def test_real_lsi_delivery_instruction_mutation_is_rejected(self):
        """Fails if the exporter stops checking the LSI payload store."""
        from tools.static import export_a6400_packaged_selector_scan as exporter

        if not exporter.sources_available() or not exporter.dependencies_available():
            self.skipTest("pinned selector sources or parsers are unavailable")
        original = exporter._elf._instruction

        def corrupt_payload_store(blob, mappings, deps, site):
            if site == 0x8790:
                return original(blob, mappings, deps, 0x8792)
            return original(blob, mappings, deps, site)

        with mock.patch.object(
            exporter._elf,
            "_instruction",
            side_effect=corrupt_payload_store,
        ):
            with self.assertRaises(RuntimeError):
                exporter.build_raw_export()

    def test_lsi_delivery_rejects_a_false_normalized_queue_join(self):
        """Fails if unequal low-15-bit queue identifiers are called a join."""
        from pmca.analysis.cxd90045_transition_report import (
            PACKAGED_SELECTOR_EVIDENCE,
        )
        from tools.static import export_a6400_packaged_selector_scan as exporter

        if not exporter.sources_available() or not exporter.dependencies_available():
            self.skipTest("pinned selector sources or parsers are unavailable")
        osal = PACKAGED_SELECTOR_EVIDENCE["lsi_delivery"]["osal_dispatch"]
        with mock.patch.dict(osal, {"normalized_queue_id": 0x377}):
            with self.assertRaises(RuntimeError):
                exporter.build_raw_export()

    def test_lsi_delivery_rejects_path_branch_and_ack_mutations(self):
        """Pins the callback's path selection and conditional success reply."""
        from tools.static import export_a6400_packaged_selector_scan as exporter

        if not exporter.sources_available() or not exporter.dependencies_available():
            self.skipTest("pinned selector sources or parsers are unavailable")
        original = exporter._elf._transport._instruction

        for site, replacement in (
            (0x83E604, 0x83E606),
            (0x83E5F4, 0x83E5F6),
            (0x83E61E, 0x83E61C),
            (0x83E624, 0x83E626),
        ):
            def corrupt(blob, mappings, deps, requested_site, *, _site=site, _replacement=replacement):
                if requested_site == _site:
                    return original(blob, mappings, deps, _replacement)
                return original(blob, mappings, deps, requested_site)

            with self.subTest(site=hex(site)), mock.patch.object(
                exporter._elf._transport, "_instruction", side_effect=corrupt
            ):
                with self.assertRaises(RuntimeError):
                    exporter.build_raw_export()

    def test_validator_has_no_device_crypto_or_execution_backend(self):
        source_path = (
            REPOSITORY_ROOT
            / "pmca"
            / "analysis"
            / "cxd90045_transition_report.py"
        )
        if not source_path.is_file():
            self.fail(f"CXD90045 transition validator is missing: {source_path}")
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(
            imported_roots.isdisjoint(
                {"Crypto", "Cryptodome", "ctypes", "subprocess", "usb"}
            )
        )
        folded = source.casefold()
        for forbidden in (
            "deviceiocontrol",
            "private_key",
            "writefirmware",
            "writememory",
            "aes_decrypt",
        ):
            self.assertNotIn(forbidden, folded)


if __name__ == "__main__":
    unittest.main()
