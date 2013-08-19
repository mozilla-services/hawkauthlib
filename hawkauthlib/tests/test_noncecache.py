# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import time
import unittest

from hawkauthlib.noncecache import NonceCache, Cache


class MockTime(object):
    """A mock time, for pretending to call time.time() and time.sleep()."""

    def __init__(self):
        self.now = time.time()

    def time(self):
        return self.now

    def sleep(self, secs):
        self.now += secs


class TestNonceCache(unittest.TestCase):

    def test_default_ttl_values(self):
        nc = NonceCache()
        self.assertEquals(nc.window,  60)

    def test_operation(self):
        window = 0.1
        mocktime = MockTime()
        nc = NonceCache(window, get_time=mocktime.time)
        # Initially nothing is cached, so all nonces as fresh.
        self.assertEquals(nc.window, window)
        self.assertEquals(len(nc), 0)
        self.assertTrue(nc.check_nonce(mocktime.time(), "abc"))
        # After adding a nonce, it should contain just that item.
        self.assertEquals(len(nc), 1)
        self.assertFalse(nc.check_nonce(mocktime.time(), "abc"))
        self.assertTrue(nc.check_nonce(mocktime.time(), "xyz"))
        # After the timeout passes, the nonce should be expired.
        mocktime.sleep(window)
        self.assertTrue(nc.check_nonce(mocktime.time(), "abc"))
        # Writing to the cache purges expired nonces but keeps valid ones.
        mocktime.sleep(window / 2)
        self.assertTrue(nc.check_nonce(mocktime.time(), "def"))
        self.assertFalse(nc.check_nonce(mocktime.time(), "abc"))
        self.assertFalse(nc.check_nonce(mocktime.time(), "def"))
        self.assertTrue(nc.check_nonce(mocktime.time(), "xyz"))
        mocktime.sleep(window / 2)
        self.assertTrue(nc.check_nonce(mocktime.time(), "abc"))
        self.assertFalse(nc.check_nonce(mocktime.time(), "def"))
        self.assertFalse(nc.check_nonce(mocktime.time(), "xyz"))
        # If the timestamp is outside the window,
        # even a fresh nonce will fail the check.
        self.assertFalse(nc.check_nonce(mocktime.time() - 2 * window, "ghi"))
        self.assertFalse(nc.check_nonce(mocktime.time() + 2 * window, "ghi"))
        self.assertTrue(nc.check_nonce(mocktime.time(), "ghi"))

    def test_that_cache_items_are_ungettable_once_expired(self):
        timeout = 1.0
        mocktime = MockTime()
        cache = Cache(timeout, get_time=mocktime.time)
        cache.set("hello", "world")
        self.assertEquals(cache.get("hello"), "world")
        mocktime.sleep(timeout / 2)
        self.assertEquals(cache.get("hello"), "world")
        mocktime.sleep(timeout / 2)
        self.assertRaises(KeyError, cache.get, "hello")

    def test_that_cache_respects_max_size(self):
        cache = Cache(1, max_size=2)
        cache.set("hello", "world")
        self.assertEquals(len(cache), 1)
        cache.set("how", "are")
        self.assertEquals(len(cache), 2)
        cache.set("you", "today?")
        self.assertEquals(len(cache), 2)
        self.assertEquals(cache.get("you"), "today?")
        self.assertEquals(cache.get("how"), "are")
        self.assertRaises(KeyError, cache.get, "hello")
