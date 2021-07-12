3.0.0 - 2021-06-10
==================

 * Introduced _optional_ payload verification method `verify_payload()`
 * Fixes [Issue #6](https://github.com/mozilla-services/hawkauthlib/issues/6) using server-side generated hash for Hawk signature calculation instead of trusting the request provided value
 * Backwards compatibility with old functionality is still possible when using `accept_untrusted_content` in `get_signature()` method

2.0.0 - 2016-01-16
==================

 * Py27, Py35 compatible

0.1.1 - 2013-11-12
==================

 * Let key be any binary string; id must still be ascii.


0.1.0 - 2013-08-19
==================

 * Initial release; this is essentially the macauthlib codebase, ported
   over to the new Hawk auth specification.
