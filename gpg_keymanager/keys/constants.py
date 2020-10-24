"""
Constants for PGP key file parsing

Based on documentation in
http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
"""

# Extensions of files parsed as public key files
PUBLIC_KEY_FILE_EXTENSIONS = (
    '.asc',
    '.pub',
)

# Required capabilities for keys
REQUIRED_CAPABILITIES = (
    'encrypt',
)

# String mapping from key validity flag values
KEY_VALIDITY_STATUS_DISABLED = 'disabled'
KEY_VALIDITY_STATUS_EXPIRED = 'expired'
KEY_VALIDITY_STATUS_INVALID = 'invalid'
KEY_VALIDITY_STATUS_REVOKED = 'revoked'
KEY_VALIDITY_STATUS_SPECIAL = 'special'
KEY_VALIDITY_STATUS_UNKNOWN = 'unknown'
KEY_VALIDITY_TRUST_MARGINAL = 'marginal'
KEY_VALIDITY_TRUST_FULL = 'full'
KEY_VALIDITY_TRUST_ULTIMATE = 'ultimate'
KEY_VALIDITY_TRUST_WELL_KNOWN = 'well-known'

# Accepted PGP key validity states for password store encryption
ACCEPTED_VALIDITY_STATES = (
    'full',
    'ultimate'
)

FIELD_KEY_CAPABILITIES = 'key_capabilities'
FIELD_CREATION_DATE = 'creation_date'
FIELD_EXPIRATION_DATE = 'expiration_date'
FIELD_KEY_ID = 'key_id'
FIELD_KEY_LENGTH = 'key_length'
FIELD_KEY_VALIDITY = 'validity'
FIELD_RECORD_TYPE = 'record_type'
FIELD_USER_ID = 'user_id'

RECORD_TYPE_FINGERPRINT = 'fpr'
RECORD_TYPE_PUBLIC_KEY = 'pub'
RECORD_TYPE_SUB_KEY = 'sub'
RECORD_TYPE_USER_ATTRIBUTE = 'uat'
RECORD_TYPE_USER_ID = 'uid'

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

# Key capability field values
KEY_CAPABILITIES = {
    'e': 'encrypt',
    's': 'sign',
    'c': 'certify',
    'a': 'authentication',
    '?': 'unknown',
}

# Validity flag values in gpg key details
KEY_VALIDITY_FLAGS = {
    'o': KEY_VALIDITY_STATUS_UNKNOWN,
    'i': KEY_VALIDITY_STATUS_INVALID,
    'd': KEY_VALIDITY_STATUS_DISABLED,
    'r': KEY_VALIDITY_STATUS_REVOKED,
    'e': KEY_VALIDITY_STATUS_EXPIRED,
    '-': KEY_VALIDITY_STATUS_UNKNOWN,
    'q': KEY_VALIDITY_STATUS_UNKNOWN,
    'n': KEY_VALIDITY_STATUS_INVALID,
    'm': KEY_VALIDITY_TRUST_MARGINAL,
    'f': KEY_VALIDITY_TRUST_FULL,
    'u': KEY_VALIDITY_TRUST_ULTIMATE,
    'w': KEY_VALIDITY_TRUST_WELL_KNOWN,
    's': KEY_VALIDITY_STATUS_SPECIAL,
}

# Values in owner trust database exports / imports
TRUSTDB_UNKNOWN = 2
TRUSTDB_UNTRUSTED = 3
TRUSTDB_MARGINAL = 4
TRUSTDB_FULLY = 5
TRUSTDB_ULTIMATE = 6

# String representations of trust values
TRUSTDB_TRUST_LABELS = {
    TRUSTDB_UNKNOWN: 'unknown',
    TRUSTDB_UNTRUSTED: 'untrusted',
    TRUSTDB_MARGINAL: 'marginal',
    TRUSTDB_FULLY: 'full',
    TRUSTDB_ULTIMATE: 'ultimate'
}
