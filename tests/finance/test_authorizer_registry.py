import ast
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

class FakeOS:
    def __init__(self, uid):
        self.uid = uid

    def __getattr__(self, name):
        if name == "geteuid":
            return lambda: self.uid
        if name == "O_NOFOLLOW":
            return getattr(os, name, 0)
        return getattr(os, name)


SOURCE = Path(os.environ.get("TEST_AUTHORIZE_SOURCE", str(Path(__file__).parents[1] / "awema-worker-authorize.current.py")))


class FakeLauncher:
    def __init__(self, base):
        self.BASE = base
        self.UIDS = {"pm": base.stat().st_uid, "dev": base.stat().st_uid + 1}


def policy(uid):
    return {
        "version": 2,
        "board": "awema-agency",
        "project": "awema-ai-team",
        "sensitive_actions_enabled": False,
        "roles": {
            "pm": {
                "enabled": True,
                "uid": uid,
                "route": "native-isolated",
                "toolsets": ["terminal", "file"],
                "actions": ["launch", "complete", "block", "cancel", "status"],
                "projects": ["awema-ai-team"],
            }
        },
    }


@unittest.skipUnless(os.name == "posix", "registry owner/mode checks require POSIX semantics")
class RegistryAuthorizationTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verified_registry")
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        registry_dir = self.base / "registry"
        registry_dir.mkdir()
        registry_dir.chmod(0o700)
        self.registry = registry_dir / "execution-v2.json"
        self.registry.write_text(json.dumps(policy(self.base.stat().st_uid)), encoding="utf-8")
        self.registry.chmod(0o600)
        uid = self.base.stat().st_uid
        namespace = {
            "m": FakeLauncher(self.base), "os": FakeOS(uid), "stat": stat,
            "json": json, "hashlib": hashlib,
        }
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), "exec"), namespace)
        self.verify = namespace["verified_registry"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_current_registry_contract_is_accepted_and_pinned(self):
        authorization = {}
        self.verify("pm", authorization, "launch", expected_uid=self.base.stat().st_uid)
        self.assertEqual(authorization["registry_sha256"], hashlib.sha256(self.registry.read_bytes()).hexdigest())

    def test_wrong_role_uid_or_route_is_rejected(self):
        self.assertRaises(ValueError, self.verify, "dev", {}, "launch", self.base.stat().st_uid)

    def test_mutated_registry_digest_is_rejected(self):
        self.assertRaises(ValueError, self.verify, "pm", {"registry_sha256": "0" * 64}, "launch", self.base.stat().st_uid)

    def test_sensitive_policy_is_rejected(self):
        data = policy(self.base.stat().st_uid)
        data["sensitive_actions_enabled"] = True
        self.registry.write_text(json.dumps(data), encoding="utf-8")
        self.assertRaises(ValueError, self.verify, "pm", {}, "launch", self.base.stat().st_uid)

    def test_group_or_world_writable_registry_is_rejected(self):
        self.registry.chmod(0o666)
        self.assertRaises(ValueError, self.verify, "pm", {}, "launch", self.base.stat().st_uid)


if __name__ == "__main__":
    unittest.main()
