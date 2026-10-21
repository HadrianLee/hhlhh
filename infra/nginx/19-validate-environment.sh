#!/bin/sh
set -eu

: "${DOMAIN:?Set DOMAIN}"
: "${BFF_SERVER_URL:?Set BFF_SERVER_URL to the BFF origin without a trailing slash}"
: "${SSL_CERT_PATH:?Set SSL_CERT_PATH}"
: "${SSL_KEY_PATH:?Set SSL_KEY_PATH}"
