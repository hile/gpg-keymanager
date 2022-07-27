![Unit Tests](https://github.com/hile/gpg-keymanager/actions/workflows/unittest.yml/badge.svg)
![Style Checks](https://github.com/hile/gpg-keymanager/actions/workflows/lint.yml/badge.svg)

# GPG keyring and password store key management utilities

This python module contains utilities to manage user PGP keys and encryption keys
used for encryping items in GNU password store.

## PGP key filesystem directory

Loading PGP public keys from a filesystem directory can be used to allow teams to
publish member PGP keys without using key servers. This procedure is not secure by
itself but is reasonable enough when combined with access controls to the directory
and some external identity management tools like LDAP lookups.

Any PGP key imported from such access controlled filesystem directory or git
repository should still be checked with PGP fingerprint as usual.

## GNU password store encryption key management

This utility helps managing encryption keys used in *pass* password store, which can
encrypt items in the store to one or multiple PGP key IDs per folder.
