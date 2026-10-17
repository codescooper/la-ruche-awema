"""Isolated regression checks for the worker model gateway fallback."""
import importlib.machinery
import importlib.util
import ipaddress
import socket
import sys
import threading
import time
import types
import urllib.error
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name('awema-model-gateway')
# The executable runs on Linux; this shim only lets the pure policy tests load
# on a Windows workstation where fcntl is unavailable.
try:
    import fcntl  # noqa: F401
except ImportError:
    sys.modules['fcntl'] = types.SimpleNamespace(LOCK_EX=0, flock=lambda *args: None)
loader = importlib.machinery.SourceFileLoader('awema_model_gateway_under_test', str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
gateway = importlib.util.module_from_spec(spec)
loader.exec_module(gateway)


class FallbackPolicyTests(unittest.TestCase):
    def test_provider_failures_are_bounded_and_classified(self):
        for status in (401, 403, 408, 425, 429, 500, 503, 599):
            error = urllib.error.HTTPError('https://provider.invalid', status, '', {}, None)
            self.assertEqual(gateway.fallback_reason(error), 'http_' + str(status))

    def test_bad_request_does_not_fallback(self):
        error = urllib.error.HTTPError('https://provider.invalid', 400, '', {}, None)
        self.assertIsNone(gateway.fallback_reason(error))

    def test_network_timeout_is_eligible(self):
        self.assertEqual(gateway.fallback_reason(TimeoutError()), 'network_timeout')
        self.assertEqual(gateway.fallback_reason(urllib.error.URLError(socket.timeout())), 'network_timeout')

    def test_payload_is_fixed_to_local_model_and_supported_fields(self):
        payload = gateway.ollama_request_payload({
            'model': 'deepseek-flash', 'messages': [], 'stream': True,
            'stream_options': {'include_usage': True}, 'max_completion_tokens': 32,
            'reasoning_effort': 'high', 'thinking': {'type': 'enabled'},
            'tools': [], 'provider_override': 'forbidden',
        })
        self.assertEqual(payload['model'], 'qwen3-4b-8k-test')
        self.assertEqual(payload['reasoning_effort'], 'none')
        self.assertEqual(payload['max_tokens'], 32)
        self.assertFalse(payload['stream'])
        self.assertNotIn('stream_options', payload)
        self.assertNotIn('thinking', payload)
        self.assertNotIn('provider_override', payload)

    def test_capacity_queue_is_bounded(self):
        server = types.SimpleNamespace(capacity=threading.BoundedSemaphore(1),
            capacity_waiters=0, capacity_waiters_lock=threading.Lock(), max_capacity_waiters=1)
        server.capacity.acquire()
        result = []
        waiter = threading.Thread(target=lambda: result.append(gateway.acquire_capacity(server, timeout=1)))
        waiter.start()
        deadline = time.monotonic() + .5
        while time.monotonic() < deadline:
            with server.capacity_waiters_lock:
                if server.capacity_waiters == 1: break
            time.sleep(.005)
        self.assertEqual(server.capacity_waiters, 1)
        self.assertEqual(gateway.acquire_capacity(server, timeout=.01)[1], 'queue_full')
        server.capacity.release()
        waiter.join(timeout=1)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(result[0][1], 'queued')
        server.capacity.release()

    def test_capacity_queue_timeout_cleans_waiter_count(self):
        server = types.SimpleNamespace(capacity=threading.BoundedSemaphore(1),
            capacity_waiters=0, capacity_waiters_lock=threading.Lock(), max_capacity_waiters=1)
        server.capacity.acquire()
        acquired, state, _ = gateway.acquire_capacity(server, timeout=.01)
        self.assertFalse(acquired)
        self.assertEqual(state, 'queue_timeout')
        self.assertEqual(server.capacity_waiters, 0)
        server.capacity.release()


if __name__ == '__main__':
    unittest.main(verbosity=2)
