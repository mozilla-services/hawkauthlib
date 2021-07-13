3.0.0 - 2021-06-10
==================

 * Adds the ability to verify payload hashes by calculating them on the server, and enables it by default.
   Fixes [Issue #6](https://github.com/mozilla-services/hawkauthlib/issues/6).
   * The `sign_request` and `get_signature` functions now have an optional `include_payload_hash` parameter
     which, if True, will calculate a payload hash based on the request body. They default to True.
   * The `check_signature` function now has an optional `require_payload_hash` parameter which, if True,
     will reject signatures that do not include a payload hash. It defaults to False.
   * The `check_signature` function now has an optional `verify_payload_hash` parameter which, if True,
     will check the payload hash provided by the client against the actual request body. It defaults to
     True.
   * For uses-cases where the default behaviour is not acceptable (e.g. the request body is not available
     when calculating or checking the signature) there are new functions `hash_payload` and `verify_payload`
     that can be used to perform payload verification manually.

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
