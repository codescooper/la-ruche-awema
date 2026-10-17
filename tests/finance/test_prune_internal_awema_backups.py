import datetime as dt
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("prune-internal-awema-backups.py")
SPEC = importlib.util.spec_from_file_location("backup_retention", MODULE)
retention = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retention)


class BackupRetentionTests(unittest.TestCase):
    def make_archive(self, root: Path, name: str, body: bytes = b"ciphertext"):
        path = root / name
        path.write_bytes(body)
        (root / (name + ".sha256")).write_text(
            hashlib.sha256(body).hexdigest() + "  " + name + "\n", encoding="ascii")
        return path

    def test_only_targets_exact_awema_families_and_preserves_recovery_points(self):
        now = dt.datetime(2026, 10, 11, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            retention.ROOT = root.resolve()
            for day in range(1, 7):
                stamp = f"202610{day:02d}T040000Z"
                self.make_archive(root, f"awema-ai-{stamp}.tgz.age")
                self.make_archive(root, f"awema-runtime-{stamp}.tar.age")
                self.make_archive(root, f"awema-{stamp}.tgz.age")
            self.make_archive(root, "awema-ai-20261011T040000Z.tgz.age")
            self.make_archive(root, "awema-ai-20261002T160409Z.tgz.age")
            self.make_archive(root, "awema-ai-20261007T064752Z.tgz.age")
            self.make_archive(root, "awema-runtime-20261007T064458Z.tar.age")
            self.make_archive(root, "afrocodeurs-20261010T040000Z.tgz.age")
            self.make_archive(root, "cinelight-selfhost-20261010T040000Z.tgz.age")
            plan = retention.build_plan(root, now)
            target_names = {item["name"] for item in plan["targets"]}
            kept_names = {item["name"] for item in plan["kept"]}
            self.assertIn("awema-ai-20261002T160409Z.tgz.age", kept_names)
            self.assertIn("awema-runtime-20261007T064458Z.tar.age", kept_names)
            self.assertNotIn("afrocodeurs-20261010T040000Z.tgz.age", target_names)
            self.assertNotIn("cinelight-selfhost-20261010T040000Z.tgz.age", target_names)
            self.assertGreater(len(target_names), 0)

    def test_stale_latest_archive_fails_closed(self):
        now = dt.datetime(2026, 10, 11, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            retention.ROOT = root.resolve()
            for day in range(1, 6):
                stamp = f"2026100{day}T040000Z"
                self.make_archive(root, f"awema-ai-{stamp}.tgz.age")
                self.make_archive(root, f"awema-{stamp}.tgz.age")
            with self.assertRaisesRegex(RuntimeError, "stale"):
                retention.build_plan(root, now)

    def test_corrupt_newest_checksum_fails_closed(self):
        now = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            retention.ROOT = root.resolve()
            for day in (9, 10, 11, 12):
                stamp = f"202610{day:02d}T040000Z"
                self.make_archive(root, f"awema-ai-{stamp}.tgz.age")
                self.make_archive(root, f"awema-runtime-{stamp}.tar.age")
                self.make_archive(root, f"awema-{stamp}.tgz.age")
            latest = root / "awema-ai-20261012T040000Z.tgz.age.sha256"
            latest.write_text("0" * 64 + "\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                retention.build_plan(root, now)


if __name__ == "__main__":
    unittest.main()

