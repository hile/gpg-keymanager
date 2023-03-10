#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Constants for password store
"""
ENV_VAR = 'PASSWORD_STORE_DIR'
DEFAULT_PASSWORD_STORE_PATH = '~/.password-store'

PASSWORD_STORE_KEY_LIST_FILENAME = '.gpg-id'
PASSWORD_STORE_SECRET_EXTENSION = '.gpg'

PASSWORD_STORE_CONFIG_FILES = (
    PASSWORD_STORE_KEY_LIST_FILENAME,
)

PASSWORD_ENTRY_ENCODING = 'utf-8'
