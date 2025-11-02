# Browser Autofill Extractor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Issues](https://img.shields.io/github/issues/numsalam/browser-autofill-extractor.svg)](https://github.com/numsalam/browser-autofill-extractor/issues)
[![Stars](https://img.shields.io/github/stars/numsalam/browser-autofill-extractor.svg?style=social)](https://github.com/numsalam/browser-autofill-extractor/stargazers)

A production-ready Python tool for securely extracting autofill data (addresses, phone numbers, payment methods) from browser profiles during enterprise migrations. Supports Chrome, Firefox, and Edge with on-device decryption, PCI-compliant payment handling, and error-resilient operations.

This tool is designed for authorized enterprise use, ensuring data privacy (GDPR/CCPA compliant) and minimal downtime in large-scale deployments.

## Features

- **Multi-Browser Support**: Extracts from Chrome, Firefox, and Edge profiles.
- **Secure Decryption**: On-device only; uses OS-native APIs (DPAPI, Keychain, NSS) for Chromium/Firefox encryption.
- **PCI-Compliant Payments**: Masks full card numbers (last 4 only), SHA-256 hashes for audits (no storage/transit of PANs).
- **Profile Detection**: Automatically enumerates multi-profile setups across Windows, macOS, and Linux.
- **Error Handling**: Graceful failures per profile; logging for audits (non-sensitive).
- **Encrypted Exports**: Optional Fernet encryption for output JSON.
- **Type-Hinted & Modular**: Clean, extensible code with dataclasses and exceptions.

## Requirements

- Python 3.10+
- Dependencies (install via pip):
  ```
  pip install cryptography pywin32 keyring
  ```
  - `pywin32`: Windows DPAPI (optional, falls back gracefully).
  - `keyring`: macOS/Linux key storage.
- Run with elevated privileges (e.g., via MDM like Intune) for file access.
- Browser must be closed (tool can integrate with shutdown scripts).

**Note**: No internet access required; all operations are local.

## Installation

1. Clone the repo:
   ```
   git clone https://github.com/numsalam/browser-autofill-extractor.git
   cd browser-autofill-extractor
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
   (Create `requirements.txt` with: `cryptography`, `pywin32`, `keyring`.)

3. (Optional) Bundle for distribution:
   ```
   pip install pyinstaller
   pyinstaller --onefile browser_autofill_extractor.py
   ```

## Usage

Run the script via CLI. Basic example:

```bash
python browser_autofill_extractor.py --browser chrome --output autofill_data.json
```

### Arguments

| Flag | Description | Required | Example |
|------|-------------|----------|---------|
| `--browser` | Browser to extract: `chrome`, `firefox`, or `edge` | Yes | `--browser chrome` |
| `--output, -o` | Output JSON file path | Yes | `--output extracted.json` |
| `--encrypt-key` | Base64-encoded Fernet key for encrypted export (optional) | No | `--encrypt-key b'...' ` |

### Example Outputs

- Plain JSON (unencrypted):
  ```json
  {
    "browser": "chrome",
    "profiles": {
      "Default": {
        "addresses": {
          "name_first": "John",
          "address_home_street_address": "123 Main St"
        },
        "payments": {
          "guid1": {
            "name": "Visa ****1234"
          }
        }
      }
    }
  }
  ```

- Encrypted: Base64-wrapped Fernet payload (decrypt with matching key).

For batch migrations, integrate with orchestration tools (e.g., Ansible, SCCM) to run per-device.

### Security & Compliance

- **Decryption**: Keys never leave the device; supports master passwords (prompts if set).
- **Payments**: 
  - Full PANs decrypted in-memory only, then masked/hashed.
  - Audit logs: SHA-256 of sensitive fields (separate `audit.log`).
  - No CVV storage (ephemeral per browser).
- **Privacy**: PII (e.g., addresses) exported as-is but can be filtered via custom policies.
- **Best Practices**:
  - Use `--encrypt-key` from a KMS (e.g., Azure Key Vault).
  - Run in ephemeral environments (e.g., Docker with volume mounts).
  - Pilot on test profiles; validate with synthetic data.

**Warnings**:
- Authorized use only: Complies with GDPR/CCPA/PCI DSS when used correctly.
- Do not run on production without legal review.
- Logs exclude sensitive data; rotate `extraction.log` and `audit.log` regularly.

## Architecture

- **ProfileDetector**: OS-aware path scanning.
- **Decryptor**: Handles Chromium AES-GCM and Firefox PBKDF2/NSS.
- **Extractors**: Browser-specific SQLite/JSON parsers (ChromiumExtractor, FirefoxExtractor).
- **SecureHandler**: PCI masking, hashing, and Fernet export.

See `browser_autofill_extractor.py` for full implementation (type-hinted, ~500 LOC).

## Testing

- Unit tests: Run `python -m pytest` (add pytest to dev deps).
- Integration: Test on sample profiles (create via browser export tools).
- Coverage: Aim for 90%+ (use `pytest-cov`).

Sample test profile setup:
1. Create a test Chrome profile with dummy autofill.
2. Run: `python browser_autofill_extractor.py --browser chrome --output test.json`.
3. Verify masking: `jq '.profiles.Default.payments' test.json`.

## Contributing

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/secure-export`).
3. Commit changes (`git commit -m 'Add: Enhanced masking'`).
4. Push (`git push origin feature/secure-export`).
5. Open a Pull Request.

Focus on security enhancements, new browsers (e.g., Safari), or ETL integrations.

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- Built on open-source libs: [Cryptography](https://cryptography.io/), [Keyring](https://keyring.readthedocs.io/).
- Inspired by tools like HackBrowserData (for reference only).

---

*For enterprise support: Contact numsalamsecurit@gmail.com. Last updated: November 02, 2025.*