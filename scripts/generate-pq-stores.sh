#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../local/pq-shp-stores"
PASSWORD="changeit"
VALIDITY_DAYS="3650"
FORCE="false"

usage() {
    cat <<EOF
Usage: bash scripts/generate-pq-stores.sh [options]

Options:
  -o, --output-dir <dir>     Output directory for generated stores
  -p, --password <password>  Store/key password
  -d, --days <days>          Certificate validity in days
  -f, --force                Replace existing generated files
  -h, --help                 Show this help

Defaults:
  output-dir: local/pq-shp-stores
  password:   changeit
  days:       3650
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        -p|--password)   PASSWORD="$2";   shift 2 ;;
        -d|--days)       VALIDITY_DAYS="$2"; shift 2 ;;
        -f|--force)      FORCE="true"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

resolve_keytool() {
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/keytool" ]]; then
        printf '%s\n' "$JAVA_HOME/bin/keytool"
        return
    fi
    if command -v keytool >/dev/null 2>&1; then
        command -v keytool
        return
    fi
    echo "keytool not found. Install a JDK or set JAVA_HOME." >&2
    exit 1
}

KEYTOOL="$(resolve_keytool)"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

SERVER_KEYSTORE="$OUTPUT_DIR/server-keystore.p12"
SERVER_TRUSTSTORE="$OUTPUT_DIR/server-truststore.p12"
SERVER_CERTIFICATE="$OUTPUT_DIR/server.crt"
CLIENT_KEYSTORE="$OUTPUT_DIR/client-keystore.p12"
CLIENT_TRUSTSTORE="$OUTPUT_DIR/client-truststore.p12"
CLIENT_CERTIFICATE="$OUTPUT_DIR/client.crt"

GENERATED_FILES=(
    "$SERVER_KEYSTORE"
    "$SERVER_TRUSTSTORE"
    "$SERVER_CERTIFICATE"
    "$CLIENT_KEYSTORE"
    "$CLIENT_TRUSTSTORE"
    "$CLIENT_CERTIFICATE"
)

if [[ "$FORCE" != "true" ]]; then
    EXISTING_FILES=()
    for file in "${GENERATED_FILES[@]}"; do
        if [[ -e "$file" ]]; then EXISTING_FILES+=("$file"); fi
    done
    if [[ ${#EXISTING_FILES[@]} -gt 0 ]]; then
        echo "Some store files already exist. Re-run with --force to replace them:" >&2
        printf '  %s\n' "${EXISTING_FILES[@]}" >&2
        exit 1
    fi
fi

rm -f "${GENERATED_FILES[@]}"

"$KEYTOOL" -genkeypair \
    -alias server \
    -keyalg ML-DSA \
    -sigalg ML-DSA-65 \
    -validity "$VALIDITY_DAYS" \
    -storetype PKCS12 \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$PASSWORD" \
    -keypass "$PASSWORD" \
    -dname "CN=secure-rts-server, OU=PA1, O=FCT NOVA, L=Lisbon, C=PT" \
    -noprompt

"$KEYTOOL" -genkeypair \
    -alias client \
    -keyalg ML-DSA \
    -sigalg ML-DSA-65 \
    -validity "$VALIDITY_DAYS" \
    -storetype PKCS12 \
    -keystore "$CLIENT_KEYSTORE" \
    -storepass "$PASSWORD" \
    -keypass "$PASSWORD" \
    -dname "CN=secure-rts-client, OU=PA1, O=FCT NOVA, L=Lisbon, C=PT" \
    -noprompt

"$KEYTOOL" -exportcert \
    -rfc \
    -alias server \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$PASSWORD" \
    -file "$SERVER_CERTIFICATE"

"$KEYTOOL" -exportcert \
    -rfc \
    -alias client \
    -keystore "$CLIENT_KEYSTORE" \
    -storepass "$PASSWORD" \
    -file "$CLIENT_CERTIFICATE"

"$KEYTOOL" -importcert \
    -noprompt \
    -alias client \
    -file "$CLIENT_CERTIFICATE" \
    -storetype PKCS12 \
    -keystore "$SERVER_TRUSTSTORE" \
    -storepass "$PASSWORD"

"$KEYTOOL" -importcert \
    -noprompt \
    -alias server \
    -file "$SERVER_CERTIFICATE" \
    -storetype PKCS12 \
    -keystore "$CLIENT_TRUSTSTORE" \
    -storepass "$PASSWORD"

echo
echo "Generated PQ SHP stores in: $OUTPUT_DIR"
echo "Password: $PASSWORD"
echo
echo "Server keystore:   $SERVER_KEYSTORE"
echo "Server truststore: $SERVER_TRUSTSTORE"
echo "Client keystore:   $CLIENT_KEYSTORE"
echo "Client truststore: $CLIENT_TRUSTSTORE"
