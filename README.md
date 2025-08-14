# cryptolib

Educational cryptography library for learning:
- Classical ciphers (A–Z only): Caesar, Vigenère, Playfair, Hill(2×2), OTP
- Math utils (my own implementations): `egcd`, `modinv`, `modexp`
- Attacks: Caesar χ², Vigenère (Kasiski/IOC), Hill known-plaintext, OTP two-time, ECB pattern, CTR nonce-reuse
- Modern (safe wrappers): AES-GCM, SHA-256, X25519 (ECDH), RSA-OAEP, Ed25519

> **Disclaimer:** For education only. Do not use in production.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -U pip
pip install -e .
pytest -q
