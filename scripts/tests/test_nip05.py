import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location('verify_nip05', Path(__file__).parents[1] / 'verify-nip05.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
KEY = 'ab' * 32


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        self.send_response(self.server.status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', self.server.cors)
        self.send_header('Location', '/redirected')
        self.end_headers()
        self.wfile.write(self.server.body)

    def log_message(self, *args):
        pass


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.status = 200
        self.server.cors = '*'
        self.server.body = json.dumps({'names': {'alice': KEY}}).encode()
        self.server.paths = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_valid_binding_and_canonical_query(self):
        check.verify('Alice@Example.COM', KEY, self.base)
        self.assertEqual(self.server.paths, ['/.well-known/nostr.json?name=alice'])

    def test_wrong_key_and_missing_cors_fail(self):
        with self.assertRaisesRegex(ValueError, 'expected public key'):
            check.verify('alice@example.com', 'cd' * 32, self.base)
        self.server.cors = ''
        with self.assertRaisesRegex(ValueError, 'cross-origin'):
            check.verify('alice@example.com', KEY, self.base)

    def test_redirect_is_not_followed(self):
        self.server.status = 302
        with self.assertRaises(check.urllib.error.HTTPError):
            check.verify('alice@example.com', KEY, self.base)
        self.assertEqual(len(self.server.paths), 1)

    def test_missing_and_oversized_records_fail(self):
        for body in [b'[]', b'{"names":{}}', b' ' * (check.MAX_BYTES + 1)]:
            self.server.body = body
            with self.assertRaises(ValueError):
                check.verify('alice@example.com', KEY, self.base)

    def test_test_override_cannot_send_public_plaintext(self):
        for base in ['http://example.com', 'http://192.0.2.1', 'http://127.0.0.1@evil.example', 'http://127.0.0.1/?x=1']:
            with self.assertRaises(ValueError):
                check.endpoint('alice@example.com', base)
        for handle in ['alice@https://example.com', 'alice@example.com/path', 'alice@x:443', 'alice@example.com@evil.test']:
            with self.assertRaises(ValueError):
                check.endpoint(handle)


if __name__ == '__main__':
    unittest.main()
