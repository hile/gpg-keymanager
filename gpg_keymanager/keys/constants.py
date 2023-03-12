#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Constants for PGP key file parsing

Based on documentation in
http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
"""
from enum import Enum

# Extensions of files parsed as public key files
PUBLIC_KEY_FILE_EXTENSIONS = (
    '.asc',
    '.pub',
)

# Required capabilities for keys
REQUIRED_CAPABILITIES = (
    'encrypt',
)


class KeyCapability(Enum):
    """
    Key capabilities
    """
    ENCRYPT = 'encrypt'
    SIGN = 'sign'
    CERTIFY = 'certify'
    AUTHENTICATION = 'authentication'
    UNKNOWN = 'unknown'


class KeyValidityStatus(Enum):
    """
    Expected values for key validity status field§
    """
    DISABLED = 'disabled'
    EXPIRED = 'expired'
    INVALID = 'invalid'
    REVOKED = 'revoked'
    SPECIAL = 'special'
    UNKNOWN = 'unknown'


class KeyValidityTrust(Enum):
    """
    Expected values for key validity trust values
    """
    MARGINAL = 'marginal'
    FULL = 'full'
    ULTIMATE = 'ultimate'
    WELL_KNOWN = 'well-known'


class KeyRecordType(Enum):
    """
    Types of data in key records
    """
    FINGERPRINT = 'fpr'
    PUBLIC_KEY = 'pub'
    SUB_KEY = 'sub'
    USER_ATTRIBUTE = 'uat'
    USER_ID = 'uid'


class KeyTrustDB(Enum):
    """
    Values in owner trust database exports / imports
    """
    UNKNOWN = 2
    UNTRUSTED = 3
    MARGINAL = 4
    FULL = 5
    ULTIMATE = 6


# Accepted PGP key validity states for password store encryption
ACCEPTED_VALIDITY_STATES = (
    KeyValidityTrust.FULL,
    KeyValidityTrust.ULTIMATE,
)

FIELD_KEY_CAPABILITIES = 'key_capabilities'
FIELD_CREATION_DATE = 'creation_date'
FIELD_EXPIRATION_DATE = 'expiration_date'
FIELD_KEY_ID = 'key_id'
FIELD_KEY_LENGTH = 'key_length'
FIELD_KEY_VALIDITY = 'validity'
FIELD_RECORD_TYPE = 'record_type'
FIELD_USER_ID = 'user_id'

# Key capability field values
KEY_CAPABILITIES = {
    'e': KeyCapability.ENCRYPT,
    's': KeyCapability.SIGN,
    'c': KeyCapability.CERTIFY,
    'a': KeyCapability.AUTHENTICATION,
    '?': KeyCapability.UNKNOWN,
}

# Validity flag values in gpg key details
KEY_VALIDITY_FLAGS = {
    'o': KeyValidityStatus.UNKNOWN,
    'i': KeyValidityStatus.INVALID,
    'd': KeyValidityStatus.DISABLED,
    'r': KeyValidityStatus.REVOKED,
    'e': KeyValidityStatus.EXPIRED,
    '-': KeyValidityStatus.UNKNOWN,
    'q': KeyValidityStatus.UNKNOWN,
    'n': KeyValidityStatus.INVALID,
    's': KeyValidityStatus.SPECIAL,
    'm': KeyValidityTrust.MARGINAL,
    'f': KeyValidityTrust.FULL,
    'u': KeyValidityTrust.ULTIMATE,
    'w': KeyValidityTrust.WELL_KNOWN,
}

# String representations of trust values
TRUSTDB_TRUST_LABELS = {
    KeyTrustDB.UNKNOWN: 'unknown',
    KeyTrustDB.UNTRUSTED: 'untrusted',
    KeyTrustDB.MARGINAL: 'marginal',
    KeyTrustDB.FULL: 'full',
    KeyTrustDB.ULTIMATE: 'ultimate'
}


KEY_FIELDS = (
    'record_type',
    'validity',
    'key_length',
    'public_key_algorithm',
    'key_id',
    'creation_date',
    'expiration_date',
    'key_hash',
    'owner_trust',
    'user_id',
    'signature_class',
    'key_capabilities',
    'issuer_certificate_signature',
    'flag',
    'token_serial_number',
    'hash_algorithm',
    'curve_name',
    'compliance_flags',
    'last_update',
    'origin',
    'comments',
)

KEY_DATE_FIELDS = (
    'creation_date',
    'expiration_date',
    'last_update',
)
