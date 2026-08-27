#!/usr/bin/env bash
# Regenerates the self-signed key pairs used by the e2e IdP and SP.
# These are TEST credentials. Never use them anywhere else.
set -euo pipefail
cd "$(dirname "$0")"
# Output is prefixed e2e_ and consumed by spec/support/e2e.rb

gen() {
  local name=$1 cn=$2
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7300 \
    -keyout "${name}.key" -out "${name}.crt" \
    -subj "/C=US/ST=Test/L=Test/O=saml_idp e2e/CN=${cn}"
}

gen e2e_idp idp.e2e.test
gen e2e_sp  sp.e2e.test

# An encrypted key, to cover the pv_key_password code path.
openssl rsa -in e2e_idp.key -aes256 -passout pass:e2e-passphrase -out e2e_idp_encrypted.key
