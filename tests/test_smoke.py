"""Smoke tests for VAULTMAP. Standard library only, no network."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultmap import TOOL_NAME, TOOL_VERSION, Vault, Entry, VaultError
from vaultmap.core import derive_key, encrypt_blob, decrypt_blob
from vaultmap import cli


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self):
        key = derive_key("pw", b"saltsaltsaltsalt", iterations=1000)
        blob = encrypt_blob(key, b"secret payload")
        out = decrypt_blob(key, blob["nonce"], blob["ciphertext"], blob["mac"])
        self.assertEqual(out, b"secret payload")

    def test_tamper_detected(self):
        key = derive_key("pw", b"saltsaltsaltsalt", iterations=1000)
        blob = encrypt_blob(key, b"secret")
        bad = bytearray(__import__("base64").b64decode(blob["ciphertext"]))
        bad[0] ^= 0xFF
        bad_b64 = __import__("base64").b64encode(bytes(bad)).decode()
        with self.assertRaises(VaultError):
            decrypt_blob(key, blob["nonce"], bad_b64, blob["mac"])

    def test_wrong_password(self):
        k1 = derive_key("right", b"saltsaltsaltsalt", iterations=1000)
        k2 = derive_key("wrong", b"saltsaltsaltsalt", iterations=1000)
        blob = encrypt_blob(k1, b"data")
        with self.assertRaises(VaultError):
            decrypt_blob(k2, blob["nonce"], blob["ciphertext"], blob["mac"])


class TestVault(unittest.TestCase):
    def test_add_summary(self):
        v = Vault(iterations=1000)
        v.add(Entry(id="a", name="Bank", category="bank", institution="X",
                    value=100.0, beneficiary="Jane", location="safe"))
        v.add(Entry(id="b", name="Loan", category="liability", value=40.0))
        s = v.summary()
        self.assertEqual(s["entry_count"], 2)
        self.assertEqual(s["total_assets"], 100.0)
        self.assertEqual(s["total_liabilities"], 40.0)
        self.assertEqual(s["net_worth"], 60.0)
        self.assertIn("b", s["missing_beneficiary"])

    def test_duplicate_id(self):
        v = Vault(iterations=1000)
        v.add(Entry(id="a", name="X"))
        with self.assertRaises(VaultError):
            v.add(Entry(id="a", name="Y"))

    def test_category_normalized(self):
        e = Entry(id="x", name="N", category="BOGUS").normalized()
        self.assertEqual(e.category, "other")

    def test_save_load_roundtrip(self):
        import tempfile
        v = Vault(iterations=1000)
        v.add(Entry(id="a", name="Bank", value=10.0))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.vault")
            v.save(path, "pw")
            loaded = Vault.load(path, "pw")
            self.assertEqual(len(loaded.entries), 1)
            self.assertEqual(loaded.entries[0].name, "Bank")
            with self.assertRaises(VaultError):
                Vault.load(path, "badpw")


class TestCLI(unittest.TestCase):
    def _run(self, argv, env=None):
        if env:
            os.environ.update(env)
        return cli.main(argv)

    def test_version_meta(self):
        self.assertEqual(TOOL_NAME, "vaultmap")
        self.assertTrue(TOOL_VERSION)

    def test_full_flow(self):
        import tempfile
        os.environ["VAULTMAP_PASSWORD"] = "testpw"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.vault")
            self.assertEqual(self._run(["init", path]), 0)
            self.assertEqual(self._run([
                "add", path, "--id", "a", "--name", "Bank",
                "--category", "bank", "--value", "100",
                "--beneficiary", "Jane", "--location", "safe",
                "--institution", "X",
            ]), 0)
            self.assertEqual(self._run(["--format", "json", "summary", path]), 0)
            self.assertEqual(self._run(["--format", "json", "list", path]), 0)
            self.assertEqual(self._run(["remove", path, "--id", "a"]), 0)
            # removing again should fail
            self.assertEqual(self._run(["remove", path, "--id", "a"]), 1)

    def test_missing_password(self):
        os.environ.pop("VAULTMAP_PASSWORD", None)
        self.assertEqual(cli.main(["summary", "nope.vault"]), 1)


if __name__ == "__main__":
    unittest.main()
