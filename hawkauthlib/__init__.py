# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""
A library for implementing the Hawk Access Authentication protocol:

    https://npmjs.org/package/hawk

Typical use for a client program would be to sign a request object like
this::

    hawkauthlib.sign_request(request, id, key)

Typical use for a server program would be to verify a signed request like
this::

    id = hawkauthlib.get_id(request)
    if id not None:
        key = somehow_lookup_the_hawk_secret_key(id)
        if hawkauthlib.check_signature(request, key):
            return True
    return False

"""

__version__      = "3.0.0"
__description__  = "Hawk Access Authentication protocol"
__url__          = "https://github.com/mozilla-services/hawkauthlib"
__license__      = "MPLv2.0"
__author__       = 'Mozilla Services'
__author_email__ = 'services-dev@mozilla.org'
__keywords__     = 'authentication Hawk HTTP request signing'


import os
import time
import hmac
import hashlib

from hawkauthlib import utils
from hawkauthlib.noncecache import NonceCache


# Global NonceCache instance used when a specific cache is not specified.
DEFAULT_NONCE_CACHE = None


ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}


@utils.normalize_request_object
def sign_request(request, id_, key, include_payload_hash=True, algorithm=None, params=None):
    """Sign the given request using Hawk access authentication.

    This function implements the client-side request signing algorithm as
    expected by the server, i.e. Hawk access authentication as divined from
    the node-js module documentation. It takes a WebOb Request object and
    inserts the appropriate signature into its Authorization header.

    If the "include_payload_hash" parameter is True (the default) then the request
    body will be hashed and included in the signature. Set it to False to omit
    the payload hash, e.g. if the body is not available at signing time (but see
    issue #6 for discussion on the security implications).

    If the "params" parameter is not None, it is assumed to be a pre-parsed
    dict of Hawk parameters as one might find in the Authorization header.  If
    it is missing or None then the Authorization header from the request will
    be parsed to determine the necessary parameters.
    """
    # Use explicitly-given parameters, or those from the request.
    if params is None:
        params = utils.parse_authz_header(request, {})
        if params and params.pop("scheme") != "Hawk":
            params.clear()
    # Give sensible values to any parameters that weren't specified.
    params["id"] = id_
    if "ts" not in params:
        params["ts"] = str(int(time.time()))
    if "nonce" not in params:
        params["nonce"] = utils.b64encode(os.urandom(5))
    if include_payload_hash:
        params["hash"] = hash_payload(request, algorithm)
    # Calculate the signature and add it to the parameters.
    params["mac"] = utils.get_signature(request, key, params, algorithm)
    # Serialize the parameters back into the authz header, and return it.
    # WebOb has logic to do this that's not perfect, but good enough for us.
    request.authorization = ("Hawk", params)
    return request.headers["Authorization"]


@utils.normalize_request_object
def get_id(request, params=None):
    """Get the Hawk id from the given request.

    This function extracts the claimed Hawk id from the authorization header of
    the given request.  It does not verify the signature, since that would
    require looking up the corresponding Hawk secret key.
    """
    if params is None:
        params = utils.parse_authz_header(request, {})
    if params.get("scheme") != "Hawk":
        return None
    return params.get("id", None)


@utils.normalize_request_object
def get_signature(request, key, include_payload_hash=True, algorithm=None, params=None):
    """Get the Hawk signature for the given request.

    This function calculates the Hawk signature for the given request and
    returns it as a string.

    If the "include_payload_hash" parameter is True (the default) then the request
    body will be hashed and included in the signature. Set it to False to omit
    the payload hash, e.g. if the body is not available at signing time (but see
    issue #6 for discussion on the security implications).

    If the "params" parameter is not None, it is assumed to be a pre-parsed
    dict of Hawk parameters as one might find in the Authorization header.  If
    it is missing or None then the Authorization header from the request will
    be parsed to determine the necessary parameters.
    """
    if algorithm is None:
        algorithm = "sha256"
    if params is None:
        params = utils.parse_authz_header(request, {})
    if include_payload_hash:
        params = params.copy()
        params["hash"] = hash_payload(request, algorithm)    
    return utils.get_signature(request, key, params, algorithm)


@utils.normalize_request_object
def hash_payload(request, algorithm=None):
    """Generate the payload hash for the given request.

    This function takes a WebOb Request object and generates the Hawk payload
    hash value for its request body.
    """
    payload_string = utils.get_normalized_payload_string(request)
    if payload_string is None:
        return None

    if algorithm is None:
        algorithm = "sha256"

    hashmod = ALGORITHMS[algorithm]()
    hashmod.update(payload_string.encode("utf8"))
    return utils.b64encode(hashmod.digest())


@utils.normalize_request_object
def verify_payload(request, params=None, algorithm=None):
    """Check that the request payload is correctly hashed.

    This function performs payload verification, which is an optional
    method call by implementers of Hawk Authentication, so it is not
    enabled by default and is not included in the access authentication
    check.

    This function retrieves a server-side generated hash of the actual
    content type header and raw body content being received by the server
    and compares to the requester supplied hash value. Returning True if
    they match and false otherwise.

    If the "params" parameter is not None, it is assumed to be a pre-parsed
    dict of Hawk parameters as one might find in the Authorization header.  If
    it is missing or None then the Authorization header from the request will
    be parsed to determine the necessary parameters.
    """
    if params is None:
        params = utils.parse_authz_header(request, {})

    return not utils.strings_differ(params["hash"], hash_payload(request, params, algorithm))


@utils.normalize_request_object
def check_signature(request, key, require_payload_hash=False, verify_payload_hash=True, algorithm=None, params=None, nonces=None):
    """Check that the request is correctly signed with the given Hawk key.

    This function checks the Hawk signature in the given request against its
    expected value, returning True if they match and false otherwise.

    If "require_payload_hash" is True then the signature parameters must include a
    payload hash. It defaults to False.

    If "verify_payload_hash" is True (the default) and the signature parameters
    include a payload hash,  then the request body will be hashed and compared against
    the provided value. Set it to False to skip payload hash verification, e.g. if the
    body is not available at the time of the signature check (but see issue #6 for
    discussion on the security implications, and consider calling "verify_payload" to
    check it yourself when the body is available).

    If the "params" parameter is not None, it is assumed to be a pre-parsed
    dict of Hawk parameters as one might find in the Authorization header.  If
    it is missing or None then the Authorization header from the request will
    be parsed to determine the necessary parameters.

    If the "nonces" parameter is not None, it must be a NonceCache object
    used to check validity of the signature nonce.  If not specified then a
    default global cache will be used.  To disable nonce checking (e.g. during
    testing) pass nonces=False.
    """
    global DEFAULT_NONCE_CACHE # pylint: disable=W0603
    if nonces is None:
        nonces = DEFAULT_NONCE_CACHE
        if nonces is None:
            nonces = DEFAULT_NONCE_CACHE = NonceCache()
    if params is None:
        params = utils.parse_authz_header(request, {})
    if params.get("scheme") != "Hawk":
        return False
    if require_payload_hash and "hash" not in params:
        return False
    # Any KeyError here indicates a missing parameter.
    # Any ValueError here indicates an invalid parameter.
    try:
        timestamp = int(params["ts"])
        nonce = params["nonce"]
        # Check validity of the signature first, optimistically assuming a valid payload hash.
        expected_sig = utils.get_signature(request, key, params, algorithm)
        if utils.strings_differ(params["mac"], expected_sig):
            return False
        # Now we can do the more expensive payload hashing, if required.
        if verify_payload_hash and "hash" in params:
            if not verify_payload(request, params, algorithm):
                return False
        # Check freshness of the nonce.
        # This caches it so future use of the nonce will fail.
        # We do this *after* successul sig check to avoid DOS attacks.
        if nonces is not False:
            if not nonces.check_nonce(timestamp, nonce):
                return False
    except (KeyError, ValueError):
        return False
    return True
