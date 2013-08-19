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
        self.assertEquals(get_id(req), "user1")

    def test_get_id_returns_none_for_other_auth_schemes(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("OAuth", {"id": "user1", "ts": "1", "nonce": "2"})
        self.assertEquals(get_id(req), None)

    def test_get_id_returns_none_if_the_id_is_missing(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        self.assertEquals(get_id(req), None)

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
        self.assertEquals(sig, mysig)

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
        self.assertEquals(sig, mysig)

    def test_sign_request_throws_away_other_auth_params(self):
        req = Request.blank("/")
        req.authorization = ("Digest", {"response": "helloworld"})
        sign_request(req, "id", "key")
        self.assertEquals(req.authorization[0], "Hawk")

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
