# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Class for managing a cache of nonces.

"""

import time
import heapq
import threading
import collections

DEFAULT_TIMESTAMP_WINDOW = 60


CacheItem = collections.namedtuple("CacheItem", "value timestamp")


class Cache(object):
    """A simple in-memory cache with automatic timestamp-based purging.

    This class provides a very simple in-memory cache.  Along with a dict
    for fast lookup of cached values, it maintains a queue of values and their
    timestamps so that they can be purged in order as they expire.
    """

    def __init__(self, ttl, max_size=None, get_time=None):
        assert not max_size or max_size > 0
        self.items = {}
        self.ttl = ttl
        self.max_size = max_size
        self.get_time = get_time or time.time
        self.purge_lock = threading.Lock()
        self.purge_queue = []

    def __len__(self):
        return len(self.items)

    def __contains__(self, key):
        try:
            item = self.items[key]
        except KeyError:
            return False
        if item.timestamp + self.ttl <= self.get_time():
            return False
        return True

    def get(self, key):
        item = self.items[key]
        if item.timestamp + self.ttl <= self.get_time():
            raise KeyError(key)
        return item.value

    def set(self, key, value, timestamp=None):
        now = self.get_time()
        if timestamp is None:
            timestamp = now
        purge_deadline = now - self.ttl
        item = CacheItem(value, timestamp)
        with self.purge_lock:
            # This try-except catches the case where we purge
            # all items from the queue, producing an IndexError.
            try:
                # Ensure we stay below max_size, if defined.
                if self.max_size:
                    while len(self.items) >= self.max_size:
                        self._purge_item()
                # Purge a few expired items to make room.
                # Don't purge *all* of them, so we don't pause for too long.
                for _ in range(5):
                    (old_timestamp, _old_key) = self.purge_queue[0]
                    if old_timestamp > purge_deadline:
                        break
                    self._purge_item()
            except IndexError:
                pass
            # Add the new item into both queue and map.
            self.items[key] = item
            heapq.heappush(self.purge_queue, (timestamp, key))

    def _purge_item(self):
        """Purge the topmost item in the queue."""
        # We have to take a little care here, because the entry in self.items
        # might have overwritten the entry which appears at head of queue.
        # Check that timestamps match before purging.
        (timestamp, key) = heapq.heappop(self.purge_queue)
        item = self.items.pop(key, None)
        if item is not None and item.timestamp != timestamp:
            self.items[key] = item  # pragma nocover


class NonceCache(object):
    """Object for managing a cache of used nonce values.

    This class allow easy timestamp-based management of client-generated
    nonces:

        * Reject nonces that have already been seen.
        * Reject nonces with a timestamp outside the configured window.
        * Purge remembered nonces when their timestamp becomes invalid.

    It supports an optional max_size argument to limit the total number of
    nonces stored.  If given then items may be removed from the cache even
    if they have not expired, possibly opening the server up to replay attacks
    but reducing the risk of resource exhaustion.
    """

    CACHE_CLASS = Cache

    def __init__(self, window=None, max_size=None, get_time=None):
        if window is None:
            window = DEFAULT_TIMESTAMP_WINDOW
        self.window = window
        self.max_size = max_size
        self.get_time = get_time or time.time
        self._seen = self.CACHE_CLASS(window, max_size, get_time)

    def __len__(self):
        return len(self._seen)

    def check_nonce(self, timestamp, nonce):
        """Check if the given timestamp+nonce is fresh.

        This method checks that the given timestamp is within the configured
        time window, and that the given nonce has not previously been seen
        within that window.  It returns True if the nonce is fresh and False
        if it is stale.

        Fresh nonces are added to an internal cache, so that subsequent checks
        of the same nonce will return False.
        """
        now = self.get_time()
        # Check if the timestamp is within the configured window.
        ts_min = now - self.window
        ts_max = now + self.window
        if not ts_min < timestamp < ts_max:
            return False
        # Check if the nonce has already been seen.
        if nonce in self._seen:
            return False
        # The nonce is fresh, add it into the cache.
        self._seen.set(nonce, True, timestamp)
        return True
