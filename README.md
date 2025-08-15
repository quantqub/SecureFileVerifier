# Secure File Verifier

**Trust & Transparency First**

A robust, security-focused script for verifying file integrity and authenticity through checksums and GPG signatures. This is a **plain Bash script** — no compiled binaries, no hidden processes, no network activity unless *you* explicitly enable it.

You can open `verifier.sh` in any text editor and see exactly what it does, line by line.

## 🛡 Why Verification Matters

When you download software, even from official sites, risks include:
- **Corruption** — from network or storage errors
- **Tampering** — a malicious actor replacing the file
- **Fake/outdated releases** — from third-party mirrors

**Verification ensures**:
- **Checksum** — file hasn't changed since release
- **Digital signature** — signed by the real developer
- **Fingerprint match** — key belongs to who you trust

If any step fails — **stop immediately**.

## 🚀 Quick Start

1. **Get the script**
   ```bash
   git clone https://github.com/quantqub/SecureFileVerifier.git
   cd SecureFileVerifier
   chmod +x verifier.sh
   ```

2. **Download what you need**
   - The file you want to verify
   - Its detached signature (`.sig` or `.asc`)
   - The public key (or key ID) of the developer
   - The checksum file (`.sha256` or `.sha512`)

3. **Run verification**
   ```bash
   ./verifier.sh \
     --file myapp.tar.gz \
     --sig myapp.tar.gz.sig \
     --expected-fpr "1234567890ABCDEF1234567890ABCDEF12345678" \
     --key-file developer.asc \
     --sha256 myapp.tar.gz.sha256
   ```

## ⚙ Features

- **Dual Verification** — Confirms both checksum and GPG signature
- **Multiple Algorithms** — SHA-256 & SHA-512 support
- **Strict Security** — Full 40-character fingerprint matching
- **Isolated Keyring** — Keeps your system keyring clean
- **Flexible Key Sources** — Local key file or keyserver lookup
- **JSON Output** — For automation and CI/CD pipelines
- **Zero Hidden Logic** — Fully auditable shell script

## 📋 Command-Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--file` | File to verify | Yes |
| `--sig` | Signature file | Yes |
| `--expected-fpr` | Expected 40-char GPG fingerprint | Yes |
| `--key-file` | Path to public key file | Yes* |
| `--key-id` | Key ID for keyserver lookup | Yes* |
| `--sha256` | Path to SHA-256 checksum file | No |
| `--sha512` | Path to SHA-512 checksum file | No |
| `--allow-network` | Enable network access for key fetching | No |
| `--non-interactive` | Disable interactive prompts | No |
| `--json` | Output results in JSON format | No |

*Either `--key-file` or `--key-id` is required

## 🔒 Security Tips

- Always verify fingerprints through a trusted channel
- Avoid `--allow-network` unless absolutely necessary
- Review the script before running (it's short and plain Bash)
- Use `--non-interactive` and `--json` for automation
- The script uses an isolated keyring (`./trustedkeys.gpg`)

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Verification successful |
| `1`  | General error |
| `2`  | Invalid arguments |
| `3`  | Checksum verification failed |
| `4`  | Signature verification failed |
| `5`  | Fingerprint mismatch |

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

*Created by [quantqub](https://github.com/quantqub)*
