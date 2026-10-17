"""Synthetic provider only. Does not read credentials or make network requests."""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from portal import Store

try:
    import fcntl
except ImportError:
    # process() does not use the Linux lock; main() must not be invoked here.
    sys.modules.setdefault('fcntl', types.SimpleNamespace())

spec = importlib.util.spec_from_file_location('worker_fixture', Path(__file__).with_name('model_worker.py'))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'fixture.sqlite'
        self.store = Store(self.path)
        self.c = sqlite3.connect(self.path)
        self.c.row_factory = sqlite3.Row
        with self.c:
            self.c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',
                           ('fixture', 'Fixture', 'director', 1, 1, '', None, 0, 'agent-fixture', '{}'))
            self.c.execute('insert into projects(id,name,currency,opening,scope,created) values(?,?,?,?,?,?)',
                           ('p_fixture', 'Synthetic internal fixture', 'XOF', 0, 'internal-awema', 1))
        self.calls = []

    def tearDown(self):
        self.c.close()
        self.tmp.cleanup()

    def queue(self, state='queued'):
        with self.c:
            self.c.execute('insert into jobs values(?,?,?,?,?,?,?,?,?,?)',
                           ('j_fixture', 'fixture', 1, 'p_fixture', 'assistant',
                            'Synthetic question only', '{}', state, None, 1))

    def fake_provider(self, request):
        self.calls.append(request)
        return 'Synthetic answer'

    def job(self):
        return self.c.execute('select * from jobs where id=?', ('j_fixture',)).fetchone()

    def test_bounded_no_tool_request(self):
        self.queue()
        worker.process(self.c, self.fake_provider)
        self.assertEqual(len(self.calls), 1)
        request = self.calls[0]
        self.assertNotIn('tools', request)
        self.assertFalse(request['stream'])
        self.assertEqual(request['max_tokens'], 1200)
        self.assertEqual(request['thinking'], {'type': 'disabled'})
        self.assertEqual(len(request['messages']), 2)

    def test_completed_synthetic_answer(self):
        self.queue()
        self.assertEqual(worker.process(self.c, self.fake_provider)['state'], 'done')
        self.assertEqual(self.job()['response'], 'Synthetic answer')

    def test_revoke_during_provider_discards_answer(self):
        self.queue()
        def revoked(request):
            with self.store.connect() as other:
                other.execute('update users set active=0,generation=generation+1 where id=?', ('fixture',))
            return 'Must never be returned'
        self.assertEqual(worker.process(self.c, revoked)['state'], 'cancelled')
        self.assertIsNone(self.job()['response'])

    def test_revoke_before_provider_prevents_call(self):
        self.queue()
        with self.c:
            self.c.execute('update users set active=0,generation=generation+1 where id=?', ('fixture',))
        self.assertEqual(worker.process(self.c, self.fake_provider)['state'], 'cancelled')
        self.assertEqual(self.calls, [])

    def test_interrupted_processing_uncertain_without_retry(self):
        self.queue('processing')
        self.assertFalse(worker.process(self.c, self.fake_provider)['processed'])
        self.assertEqual(self.job()['state'], 'uncertain')
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
