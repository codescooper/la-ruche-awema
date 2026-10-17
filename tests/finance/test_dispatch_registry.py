import ast
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).parent / 'awema-worker-dispatch'


class FakeLauncher:
    def __init__(self, base):
        self.BASE = base
        self.UIDS = {'pm': os.geteuid()}


def policy(uid):
    return {'version': 2, 'board': 'awema-agency', 'project': 'awema-ai-team',
            'sensitive_actions_enabled': False,
            'roles': {'pm': {'enabled': True, 'uid': uid, 'route': 'native-isolated',
                             'toolsets': ['terminal', 'file'], 'actions': ['launch'],
                             'projects': ['awema-ai-team']}}}


@unittest.skipUnless(os.name == 'posix', 'registry owner/mode checks require POSIX semantics')
class DispatchRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        registry_dir = self.base / 'registry'
        registry_dir.mkdir()
        registry_dir.chmod(0o700)
        self.registry = registry_dir / 'execution-v2.json'
        self.registry.write_text(json.dumps(policy(os.geteuid())), encoding='utf-8')
        self.registry.chmod(0o600)
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'verified_registry')
        namespace = {'m': FakeLauncher(self.base), 'os': os, 'stat': stat, 'json': json, 'hashlib': hashlib}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), 'exec'), namespace)
        self.verify = namespace['verified_registry']

    def tearDown(self):
        self.tmp.cleanup()

    def test_matching_registry_grant_is_accepted(self):
        grant = {'registry_sha256': hashlib.sha256(self.registry.read_bytes()).hexdigest()}
        self.assertEqual(self.verify('pm', grant, 'launch')['route'], 'native-isolated')

    def test_registry_change_invalidates_existing_grant(self):
        self.assertRaises(ValueError, self.verify, 'pm', {'registry_sha256': '0' * 64}, 'launch')

    def test_sensitive_actions_are_rejected(self):
        value = policy(os.geteuid())
        value['sensitive_actions_enabled'] = True
        self.registry.write_text(json.dumps(value), encoding='utf-8')
        self.assertRaises(ValueError, self.verify, 'pm', {}, 'launch')

    def test_writable_registry_is_rejected(self):
        self.registry.chmod(0o666)
        self.assertRaises(ValueError, self.verify, 'pm', {}, 'launch')


if __name__ == '__main__':
    unittest.main()
