#!/usr/bin/env sh
# Initialise Vault, unseal it, and configure the SSH CA secrets engine.
# This script is designed to run once against a fresh dev-mode Vault or
# a file-backend Vault that has never been initialised.
set -eu

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

echo "==> Waiting for Vault to be ready..."
until vault status -format=json 2>/dev/null | grep -q '"initialized"'; do
    sleep 1
done

# --- Initialise (only if not already done) -----------------------------------
if vault status -format=json | grep -q '"initialized": false'; then
    echo "==> Initialising Vault (1 key share, threshold 1)..."
    vault operator init -key-shares=1 -key-threshold=1 -format=json > /vault/data/init.json
    echo "==> Init payload written to /vault/data/init.json"
fi

UNSEAL_KEY=$(cat /vault/data/init.json | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')
ROOT_TOKEN=$(cat /vault/data/init.json | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
export VAULT_TOKEN="$ROOT_TOKEN"

# --- Unseal ------------------------------------------------------------------
if vault status -format=json | grep -q '"sealed": true'; then
    echo "==> Unsealing Vault..."
    vault operator unseal "$UNSEAL_KEY"
fi

echo "==> Vault is unsealed and ready."

# --- Enable SSH CA secrets engine --------------------------------------------
if ! vault secrets list -format=json | grep -q '"ssh/"'; then
    echo "==> Enabling SSH secrets engine at ssh/..."
    vault secrets enable -path=ssh ssh
fi

# --- Generate or import the CA keypair ---------------------------------------
if ! vault read ssh/config/ca 2>/dev/null | grep -q 'public_key'; then
    echo "==> Generating SSH CA keypair..."
    vault write ssh/config/ca generate_signing_key=true
fi

echo "==> Fetching SSH CA public key..."
vault read -field=public_key ssh/config/ca > /vault/data/trusted-user-ca-keys.pub
echo "    Written to /vault/data/trusted-user-ca-keys.pub"

# --- Create a signing role for autopatch JIT certs ---------------------------
echo "==> Configuring SSH signing role 'autopatch-executor'..."
vault write ssh/roles/autopatch-executor -<<"EOF"
{
  "key_type": "ca",
  "default_user": "autopatch",
  "allowed_users": "autopatch",
  "allow_user_certificates": true,
  "default_extensions": {
    "permit-pty": ""
  },
  "ttl": "5m",
  "max_ttl": "30m",
  "algorithm_signer": "rsa-sha2-256"
}
EOF

# --- Create a policy for the autopatch application ---------------------------
echo "==> Writing autopatch policy..."
vault policy write autopatch -<<"EOF"
path "ssh/sign/autopatch-executor" {
  capabilities = ["create", "update"]
}
path "ssh/config/ca" {
  capabilities = ["read"]
}
path "auth/approle/login" {
  capabilities = ["create", "update"]
}
EOF

# --- Create an AppRole for the autopatch service -----------------------------
if ! vault auth list -format=json | grep -q '"approle/"'; then
    echo "==> Enabling AppRole auth..."
    vault auth enable approle
fi

vault write auth/approle/role/autopatch \
    token_policies="autopatch" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=0

ROLE_ID=$(vault read -field=role_id auth/approle/role/autopatch/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/autopatch/secret-id)

echo ""
echo "============================================"
echo "  Vault initialisation complete!"
echo "  Root token : $ROOT_TOKEN"
echo "  Role ID    : $ROLE_ID"
echo "  Secret ID  : $SECRET_ID"
echo "============================================"
echo ""
echo "Set these in your .env:"
echo "  VAULT_ADDR=http://vault:8200"
echo "  VAULT_ROLE_ID=$ROLE_ID"
echo "  VAULT_SECRET_ID=$SECRET_ID"

# Write them to a file the app can read in dev
cat > /vault/data/approle-creds.json <<ENDJSON
{
  "role_id": "$ROLE_ID",
  "secret_id": "$SECRET_ID",
  "root_token": "$ROOT_TOKEN"
}
ENDJSON

echo "==> Credentials written to /vault/data/approle-creds.json"
