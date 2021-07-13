# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import time

from webob import Request

from hawkauthlib import sign_request, get_id, get_signature, check_signature
from hawkauthlib.noncecache import NonceCache
from hawkauthlib.utils import parse_authz_header


class TestSignatures(unittest.TestCase):

    def test_get_id_works_on_valid_header(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"id": "user1", "ts": "1", "nonce": "2"})
        self.assertEqual(get_id(req), "user1")

    def test_get_id_returns_none_for_other_auth_schemes(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("OAuth", {"id": "user1", "ts": "1", "nonce": "2"})
        self.assertEqual(get_id(req), None)

    def test_get_id_returns_none_if_the_id_is_missing(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        self.assertEqual(get_id(req), None)

    def test_get_signature_against_example_from_spec(self):
        req = b"GET /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              b"Host: example.com:8000\r\n"\
              b"\r\n"
        params = {
            "id": "dh37fgj492je",
            "ts": "1353832234",
            "nonce": "j4h3g2",
            "ext": "some-app-ext-data"
        }
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        sig = "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
        req = Request.from_bytes(req)
        mysig = get_signature(req, key, algorithm, params=params)
        self.assertEqual(sig, mysig)

    def test_get_signature_by_parsing_authz_header(self):
        req = b"GET /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              b"Host: example.com:8000\r\n"\
              b"Content-Length: 11\r\n"\
              b"Authorization: Hawk "\
              b"    id=\"dh37fgj492je\","\
              b"    ts=\"1353832234\","\
              b"    nonce=\"j4h3g2\","\
              b"    ext=\"some-app-ext-data\""\
              b"\r\n\r\n"
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        sig = "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
        mysig = get_signature(req, key, algorithm)
        self.assertEqual(sig, mysig)

    def test_post_signature_by_parsing_authz_header(self):
        req = b"POST /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              b"Host: example.com:8000\r\n"\
              b"Content-Type: application/json; charset=utf-8\r\n"\
              b"Content-Length: 26\r\n"\
              b"Authorization: Hawk "\
              b"    id=\"dh37fgj492je\","\
              b"    ts=\"1353832234\","\
              b"    nonce=\"j4h3g2\","\
              b"    ext=\"some-app-ext-data\""\
              b"\r\n\r\n{\"test\": \"just some text\"}"
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        sig = "56wgBMHr4oIwA/dGZspMm6Zk4rnf3aiwwVeL0VtWoGo="
        mac = get_signature(req, key, algorithm)
        self.assertEqual(sig, mac)

    def test_post_with_payload_verification(self):
        req = b"POST /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              b"Host: example.com:8000\r\n"\
              b"Content-Type: application/json; charset=utf-8\r\n"\
              b"Content-Length: 26\r\n"\
              b"Authorization: Hawk "\
              b"    id=\"dh37fgj492je\","\
              b"    ts=\"1353832234\","\
              b"    nonce=\"j4h3g2\","\
              b"    hash=\"Lj826IMSgrm1vnCFQNxaXasE8zHBXSWq2pPtnHEmaO8=\","\
              b"    ext=\"some-app-ext-data\""\
              b"\r\n\r\n{\"test\": \"just some text\"}"
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        sig = "Tx7PoLWYtn3VJEc0GdkguHkEB281grYEtFycPhtln9w="
        mac = get_signature(req, key, algorithm)
        self.assertEqual(sig, mac)

    def test_version_2_0_0_post_signature_by_parsing_authz_header(self):
        req_template = '''POST /resource/1?b=1&a=2 HTTP/1.1\r
Host: example.com:8000\r
Content-Type: application/json; charset=utf-8\r
Content-Length: 26\r
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data"\r
\r
{"test": "%s"}'''
        client_req = req_template % "just some text"
        actual_req = req_template % "modify b4 send"
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        client_mac = "56wgBMHr4oIwA/dGZspMm6Zk4rnf3aiwwVeL0VtWoGo="
        client_mac_proof = get_signature(client_req.encode('utf8'), key, algorithm)
        self.assertEqual(client_mac_proof, client_mac)
        expected_mac = client_mac # hawkhashlib v2.0.0 adhered to client implementation only
        # Using payload modified by attacker and client signed MAC using secret for expected payload
        actual_mac = get_signature(actual_req.encode('utf8'), key, algorithm)
        self.assertEqual(expected_mac, client_mac)
        self.assertEqual(actual_mac, client_mac) # all 3 are identical

    def test_untrusted_no_hash_post_signature_by_parsing_authz_header(self):
        req_without_hash = b'''POST /resource/1?b=1&a=2 HTTP/1.1\r
Host: example.com:8000\r
Content-Type: application/json; charset=utf-8\r
Content-Length: 26\r
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data"\r
\r
{"test": "just some text"}'''
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        client_mac = "56wgBMHr4oIwA/dGZspMm6Zk4rnf3aiwwVeL0VtWoGo="
        client_mac_proof = get_signature(req_without_hash, key, algorithm)
        self.assertEqual(client_mac_proof, client_mac)
        params = {
            'id': "dh37fgj492je",
            'ts': "1353832234",
            'nonce': "j4h3g2",
            'ext': "some-app-ext-data"
        }
        expected_mac = get_signature(req_without_hash, key, algorithm, params, accept_untrusted_content=True)
        self.assertEqual(expected_mac, client_mac)

    def test_untrusted_with_hash_post_signature_by_parsing_authz_header(self):
        req_with_hash = b'''POST /resource/1?b=1&a=2 HTTP/1.1\r
Host: example.com:8000\r
Content-Type: application/json; charset=utf-8\r
Content-Length: 26\r
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", hash="Lj826IMSgrm1vnCFQNxaXasE8zHBXSWq2pPtnHEmaO8="\r
\r
{"test": "just some text"}'''
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        client_mac = "Tx7PoLWYtn3VJEc0GdkguHkEB281grYEtFycPhtln9w="
        actual_mac = get_signature(req_with_hash, key, algorithm, None, accept_untrusted_content=True)
        self.assertEqual(actual_mac, client_mac)

    def test_modified_req_with_original_hash_post_signature_by_parsing_authz_header(self):
        key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        algorithm = "sha256"
        client_mac = "Tx7PoLWYtn3VJEc0GdkguHkEB281grYEtFycPhtln9w="
        params = {
            'id': "dh37fgj492je",
            'ts': "1353832234",
            'nonce': "j4h3g2",
            'ext': "some-app-ext-data"
        }
        req_with_hash = '''POST /resource/1?b=1&a=2 HTTP/1.1\r
Host: example.com:8000\r
Content-Type: application/json; charset=utf-8\r
Content-Length: 26\r
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", hash="Lj826IMSgrm1vnCFQNxaXasE8zHBXSWq2pPtnHEmaO8="\r
\r
{"test": "%s"}'''
        req_with_hash_for_signing = req_with_hash % "just some text"
        modified_req_with_original_hash = req_with_hash % "modify b4 send"
        # client-side
        expected_mac = get_signature(req_with_hash_for_signing.encode('utf8'), key, algorithm, None, accept_untrusted_content=True)
        # server-side, i.e. get_signature will perform:
        # server_hash = hash_payload(modified_req_with_original_hash.encode('utf8'), algorithm)
        actual_mac = get_signature(modified_req_with_original_hash.encode('utf8'), key, algorithm)
        self.assertEqual(expected_mac, client_mac)
        self.assertNotEqual(actual_mac, client_mac)

    def test_sign_request_throws_away_other_auth_params(self):
        req = Request.blank("/")
        req.authorization = ("Digest", {"response": "helloworld"})
        sign_request(req, "id", "key")
        self.assertEqual(req.authorization[0], "Hawk")

    def test_check_signature_errors_when_missing_id(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        self.assertFalse(check_signature(req, "secretkeyohsecretkey"))

    def test_check_signature_fails_with_non_mac_scheme(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        sign_request(req, "myid", "mykey")
        req.authorization = ("OAuth", req.authorization[1])
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_expired_timestamp(self):
        req = Request.blank("/")
        ts = str(int(time.time() - 1000))
        req.authorization = ("Hawk", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_far_future_timestamp(self):
        req = Request.blank("/")
        ts = str(int(time.time() + 1000))
        req.authorization = ("Hawk", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_reused_nonce(self):
        # First request with that nonce should succeed.
        req = Request.blank("/")
        req.authorization = ("Hawk", {"nonce": "PEPPER"})
        sign_request(req, "myid", "mykey")
        self.assertTrue(check_signature(req, "mykey"))
        # Second request with that nonce should fail.
        req = Request.blank("/")
        req.authorization = ("Hawk", {"nonce": "PEPPER"})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))
        # But it will succeed if using a different nonce cache.
        self.assertTrue(check_signature(req, "mykey", nonces=NonceCache()))

    def test_check_signature_fails_with_busted_signature(self):
        req = Request.blank("/")
        sign_request(req, "myid", "mykey")
        signature = parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.assertFalse(check_signature(req, "mykey"))
