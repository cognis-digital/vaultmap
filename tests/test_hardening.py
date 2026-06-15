"""Hardening tests: edge cases, bad inputs, and expected error paths."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultmap.core import (
    Vault,
    Entry,
    VaultError,
    derive_key,
    encrypt_blob,
    decrypt_blob,
)
from vaultmap import cli


class TestDeriveKeyValidation(unittest.TestCase):
    def test_empty_password_raises(self):
        with self.assertRaises(VaultError):
            derive_key("", b"somesalt")

    def test_empty_salt_raises(self):
        with self.assertRaises(VaultError):
            derive_key("password", b"")

    def test_zero_iterations_raises(self):
        with self.assertRaises(VaultError):
            derive_key("password", b"somesalt", iterations=0)

    def test_negative_iterations_raises(self):
        with self.assertRaises(VaultError):
            derive_key("password", b"somesalt", iterations=-1)


class TestBase64Validation(unittest.TestCase):
    def test_invalid_base64_in_nonce_raises(self):
        key = derive_key("pw", b"saltsaltsaltsalt", iterations=1000)
        blob = encrypt_blob(key, b"data")
        with self.assertRaises(VaultError):
            decrypt_blob(key, "not!valid!base64!!!!", blob["ciphertext"], blob["mac"])

    def test_invalid_base64_in_ciphertext_raises(self):
        key = derive_key("pw", b"saltsaltsaltsalt", iterations=1000)
        blob = encrypt_blob(key, b"data")
        with self.assertRaises(VaultError):
            decrypt_blob(key, blob["nonce"], "!!!invalid!!!", blob["mac"])


class TestVaultLoadEdgeCases(unittest.TestCase):
    def _write_raw(self, d: str, name: str, content: str) -> str:
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_missing_file_raises(self):
        with self.assertRaises(VaultError):
            Vault.load("/nonexistent/path/vault.vlt", "pw")

    def test_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write_raw(d, "bad.vault", "not json at all {{{")
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")

    def test_json_array_at_root_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write_raw(d, "arr.vault", "[1, 2, 3]")
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")

    def test_wrong_magic_raises(self):
        with tempfile.TemporaryDirectory() as d:
            doc = {"magic": "OTHER", "version": 1, "kdf": {}}
            path = self._write_raw(d, "v.vault", json.dumps(doc))
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")

    def test_missing_kdf_raises(self):
        with tempfile.TemporaryDirectory() as d:
            doc = {"magic": "VAULTMAP", "version": 1}
            path = self._write_raw(d, "v.vault", json.dumps(doc))
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")

    def test_kdf_missing_salt_raises(self):
        with tempfile.TemporaryDirectory() as d:
            doc = {
                "magic": "VAULTMAP",
                "version": 1,
                "kdf": {"name": "pbkdf2_sha256", "iterations": 1000},
            }
            path = self._write_raw(d, "v.vault", json.dumps(doc))
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")

    def test_missing_nonce_raises(self):
        import base64
        with tempfile.TemporaryDirectory() as d:
            doc = {
                "magic": "VAULTMAP",
                "version": 1,
                "kdf": {
                    "name": "pbkdf2_sha256",
                    "iterations": 1000,
                    "salt": base64.b64encode(b"a" * 16).decode(),
                },
                "ciphertext": "YQ==",
                "mac": "YQ==",
                # "nonce" intentionally missing
            }
            path = self._write_raw(d, "v.vault", json.dumps(doc))
            with self.assertRaises(VaultError):
                Vault.load(path, "pw")


class TestFromPayloadEdgeCases(unittest.TestCase):
    def test_empty_entries_list_ok(self):
        payload = {"magic": "VAULTMAP", "entries": []}
        v = Vault.from_payload(payload)
        self.assertEqual(v.entries, [])

    def test_entries_not_list_raises(self):
        payload = {"magic": "VAULTMAP", "entries": "not-a-list"}
        with self.assertRaises(VaultError):
            Vault.from_payload(payload)

    def test_entry_missing_required_id_raises(self):
        payload = {"magic": "VAULTMAP", "entries": [{"name": "Oops"}]}
        with self.assertRaises(VaultError):
            Vault.from_payload(payload)

    def test_entry_not_dict_raises(self):
        payload = {"magic": "VAULTMAP", "entries": ["not-a-dict"]}
        with self.assertRaises(VaultError):
            Vault.from_payload(payload)

    def test_unknown_fields_stripped_not_crash(self):
        payload = {
            "magic": "VAULTMAP",
            "entries": [{"id": "x", "name": "X", "future_field": "ignored"}],
        }
        v = Vault.from_payload(payload)
        self.assertEqual(len(v.entries), 1)


class TestSummaryEdgeCases(unittest.TestCase):
    def test_empty_vault_summary(self):
        v = Vault(iterations=1000)
        s = v.summary()
        self.assertEqual(s["entry_count"], 0)
        self.assertEqual(s["net_worth"], 0.0)
        self.assertEqual(s["total_assets"], 0.0)
        self.assertEqual(s["total_liabilities"], 0.0)
        self.assertEqual(s["readiness_pct"], 0.0)

    def test_negative_value_entry_counted_as_liability(self):
        v = Vault(iterations=1000)
        v.add(Entry(id="a", name="Debt", category="other", value=-500.0))
        s = v.summary()
        self.assertEqual(s["total_liabilities"], 500.0)
        self.assertEqual(s["total_assets"], 0.0)
        self.assertEqual(s["net_worth"], -500.0)


class TestCLIHardening(unittest.TestCase):
    def setUp(self):
        os.environ["VAULTMAP_PASSWORD"] = "testpw"

    def test_add_empty_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.vault")
            cli.main(["init", path])
            rc = cli.main(["add", path, "--id", "", "--name", "X"])
            self.assertEqual(rc, 1)

    def test_add_empty_name_fails(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.vault")
            cli.main(["init", path])
            rc = cli.main(["add", path, "--id", "a", "--name", ""])
            self.assertEqual(rc, 1)

    def test_load_missing_vault_exits_nonzero(self):
        rc = cli.main(["list", "/no/such/file.vault"])
        self.assertNotEqual(rc, 0)

    def test_summary_missing_vault_exits_nonzero(self):
        rc = cli.main(["summary", "/no/such/file.vault"])
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
