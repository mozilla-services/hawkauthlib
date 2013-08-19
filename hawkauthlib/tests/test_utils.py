# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from webob import Request

from hawkauthlib.utils import (strings_differ,
                               parse_authz_header,
                               get_normalized_request_string)


class TestUtils(unittest.TestCase):

    def test_strings_differ(self):
        # We can't really test the timing-invariance, but
        # we can test that we actually compute equality!
        self.assertTrue(strings_differ("", "a"))
        self.assertTrue(strings_differ("b", "a"))
        self.assertTrue(strings_differ("cc", "a"))
        self.assertTrue(strings_differ("cc", "aa"))
        self.assertFalse(strings_differ("", ""))
        self.assertFalse(strings_differ("D", "D"))
        self.assertFalse(strings_differ("EEE", "EEE"))

    def test_parse_authz_header(self):
        def req(authz):
            """Make a fake request with the given authz header."""
            class request:
                environ = {"HTTP_AUTHORIZATION": authz}
            return request

        # Test parsing of a single unquoted parameter.
        params = parse_authz_header(req('Digest realm=hello'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['realm'], 'hello')

        # Test parsing of multiple parameters with mixed quotes.
        params = parse_authz_header(req('Digest test=one, again="two"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], 'one')
        self.assertEquals(params['again'], 'two')

        # Test parsing of an escaped quote and empty string.
        params = parse_authz_header(req('Digest test="\\"",again=""'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], '"')
        self.assertEquals(params['again'], '')

        # Test parsing of embedded commas, escaped and non-escaped.
        params = parse_authz_header(req('Digest one="1\\,2", two="3,4"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['one'], '1,2')
        self.assertEquals(params['two'], '3,4')

        # Test parsing on various malformed inputs
        self.assertRaises(ValueError, parse_authz_header, req(None))
        self.assertRaises(ValueError, parse_authz_header, req(""))
        self.assertRaises(ValueError, parse_authz_header, req(" "))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken raw-token'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unclosed-quote'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm=unopened-quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unescaped"quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="escaped-end-quote\\"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="duplicated",,what=comma'))

        # Test all those again, but returning a default value
        self.assertEquals(None, parse_authz_header(req(None), None))
        self.assertEquals(None, parse_authz_header(req(""), None))
        self.assertEquals(None, parse_authz_header(req(" "), None))
        self.assertEquals(None,
                          parse_authz_header(req('Broken raw-token'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unclosed-quote'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm=unopened-quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unescaped"quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="escaped-end-quote\\"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="duplicated",,what=comma'), None))

    def test_normalized_request_string_against_example_from_spec(self):
        req = b"GET /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              b"Host: example.com:8000\r\n"\
              b"\r\n"
        params = {
            "ts": "1353832234",
            "nonce": "j4h3g2",
            "ext": "some-app-ext-data",
        }
        sigstr = "hawk.1.header\n"\
                 "1353832234\n"\
                 "j4h3g2\n"\
                 "GET\n"\
                 "/resource/1?b=1&a=2\n"\
                 "example.com\n"\
                 "8000\n"\
                 "\n"\
                 "some-app-ext-data\n"
        # IanB, *thank you* for Request.from_bytes!
        req = Request.from_bytes(req)
        mysigstr = get_normalized_request_string(req, params)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_with_custom_port(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com:88\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        sigstr = "hawk.1.header\n1\n2\nGET\n/\nexample.com\n88\n\n\n"
        mysigstr = get_normalized_request_string(req)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_with_https_scheme(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        req.scheme = "https"
        sigstr = "hawk.1.header\n1\n2\nGET\n/\nexample.com\n443\n\n\n"
        mysigstr = get_normalized_request_string(req)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_errors_when_no_default_port(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("Hawk", {"ts": "1", "nonce": "2"})
        req.scheme = "httptypo"
        self.assertRaises(ValueError, get_normalized_request_string, req)
