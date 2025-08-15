#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Secure File Verifier - Portable, Strict, Multi-Platform
# ============================================================

VERSION="1.0.0"

# --- Color Support (Safe) ---
if command -v tput >/dev/null && [ -n "${TERM:-}" ] && [ "$TERM" != "dumb" ]; then
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    YELLOW=$(tput setaf 3)
    RESET=$(tput sgr0)
else
    GREEN=""; RED=""; YELLOW=""; RESET=""
fi

# --- Usage Banner ---
show_usage() {
cat <<'EOF'
============================================================
 SECURE FILE VERIFIER — USAGE & EXAMPLES
============================================================
Basic Command Structure:
  ./verifier.sh --file <file_to_verify> \
                --sig <signature_file> \
                --expected-fpr "FULL_40_CHAR_FINGERPRINT" \
                [--key-file <pubkey.asc> | --key-id <KEY_ID>] \
                [--sha256 <checksum_file> | --sha512 <checksum_file>] \
                [--allow-network] \
                [--non-interactive] \
                [--json]

Example 1: With Local Key File
  ./verifier.sh --file downloaded-package.tar.gz \
                --sig downloaded-package.tar.gz.asc \
                --expected-fpr "1234567890ABCDEF1234567890ABCDEF12345678" \
                --key-file developer-pubkey.asc \
                --sha256 checksums.txt

Example 2: With Key ID (requires network)
  ./verifier.sh --file app-image.bin \
                --sig app-image.bin.sig \
                --expected-fpr "1234567890ABCDEF1234567890ABCDEF12345678" \
                --key-id 0x12345678 \
                --allow-network

Notes:
  - Uses an ISOLATED keyring: ./trustedkeys.gpg
  - FULL 40-hex fingerprint match enforced
  - Default: NO network, revocation & expiry enforced
  - Produces plaintext & optional JSON audit logs
============================================================
EOF
}

# --- Defaults ---
ALLOW_NETWORK=false
NON_INTERACTIVE=false
JSON_OUTPUT=false
KEYRING="./trustedkeys.gpg"

# --- Parse Args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) FILE="$2"; shift 2 ;;
        --sig) SIG="$2"; shift 2 ;;
        --expected-fpr) EXPECTED_FPR="$2"; shift 2 ;;
        --key-file) KEY_FILE="$2"; shift 2 ;;
        --key-id) KEY_ID="$2"; shift 2 ;;
        --sha256) SHA256_FILE="$2"; shift 2 ;;
        --sha512) SHA512_FILE="$2"; shift 2 ;;
        --allow-network) ALLOW_NETWORK=true; shift ;;
        --non-interactive) NON_INTERACTIVE=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        *) echo "${RED}Unknown option: $1${RESET}"; exit 1 ;;
    esac
done

# --- Always Show Usage ---
show_usage
if ! $NON_INTERACTIVE; then
    read -rp "${YELLOW}Proceed with verification? (y/N): ${RESET}" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi

# --- Input Validation ---
[[ -f "$FILE" ]] || { echo "${RED}ERROR: File not found: $FILE${RESET}"; exit 1; }
[[ -f "$SIG" ]] || { echo "${RED}ERROR: Signature file not found: $SIG${RESET}"; exit 1; }
[[ "${EXPECTED_FPR:-}" =~ ^[A-Fa-f0-9]{40}$ ]] || { echo "${RED}ERROR: Invalid fingerprint format${RESET}"; exit 1; }

# --- Setup GPG ---
GPG_OPTS=(--no-default-keyring --keyring "$KEYRING" --status-fd 1 --with-colons)
if ! $ALLOW_NETWORK; then
    GPG_OPTS+=(--keyserver-options no-auto-key-retrieve)
fi

# --- Import Key ---
if [[ -n "${KEY_FILE:-}" ]]; then
    gpg "${GPG_OPTS[@]}" --import "$KEY_FILE" >/dev/null
elif [[ -n "${KEY_ID:-}" ]]; then
    $ALLOW_NETWORK || { echo "${RED}ERROR: Network fetch not allowed${RESET}"; exit 1; }
    gpg "${GPG_OPTS[@]}" --keyserver hkps://keys.openpgp.org --recv-keys "$KEY_ID"
else
    echo "${RED}ERROR: Must provide --key-file or --key-id${RESET}"; exit 1;
fi

# --- Verify Fingerprint (Machine Readable) ---
IMPORTED_FPR=$(gpg --no-default-keyring --keyring "$KEYRING" \
                   --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')
if [[ "$IMPORTED_FPR" != "$EXPECTED_FPR" ]]; then
    echo "${RED}ERROR: Fingerprint mismatch! Imported: $IMPORTED_FPR${RESET}"
    exit 1
fi
echo "${GREEN}Fingerprint OK${RESET}"

# --- Checksum Verification ---
verify_checksum() {
    local file="$1" algo="$2" checksum_file="$3"
    local sum_cmd

    case "$algo" in
        sha256) sum_cmd=$(command -v sha256sum || echo "shasum -a 256") ;;
        sha512) sum_cmd=$(command -v sha512sum || echo "shasum -a 512") ;;
        *) echo "${RED}Unsupported checksum algo${RESET}"; exit 1 ;;
    esac

    local expected_hash
    expected_hash=$(awk -v f="$file" '{if ($2==f) print $1}' "$checksum_file" | tr -d '\r\n')

    if [[ -z "$expected_hash" ]]; then
        echo "${RED}ERROR: No checksum entry for $file${RESET}"; exit 1
    fi

    local actual_hash
    actual_hash=$($sum_cmd "$file" | awk '{print $1}')

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        echo "${RED}ERROR: Checksum mismatch for $file${RESET}"; exit 1
    fi
    echo "${GREEN}Checksum OK ($algo)${RESET}"
}

if [[ -n "${SHA256_FILE:-}" ]]; then verify_checksum "$FILE" sha256 "$SHA256_FILE"; fi
if [[ -n "${SHA512_FILE:-}" ]]; then verify_checksum "$FILE" sha512 "$SHA512_FILE"; fi

# --- Signature Verification ---
if gpg "${GPG_OPTS[@]}" --verify "$SIG" "$FILE" 2>&1 | grep -q "GOODSIG"; then
    echo "${GREEN}Signature OK${RESET}"
else
    echo "${RED}ERROR: Signature verification failed${RESET}"; exit 1
fi

# --- JSON Output ---
if $JSON_OUTPUT; then
    jq -n \
       --arg file "$FILE" \
       --arg sig "$SIG" \
       --arg fpr "$EXPECTED_FPR" \
       '{file:$file, sig:$sig, fingerprint:$fpr, status:"OK"}'
fi

echo "${GREEN}VERIFICATION COMPLETE (STRICT)${RESET}"
