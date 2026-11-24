# 🦉 OTOTP

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Password%20/%20Auth-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OTOTP** — TOTP/HOTP 2FA code generator & validator ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OTOTP — TOTP/HOTP 2FA code generator & validator. TOTP / HOTP 2FA Code Generator & Validator TOTP (RFC 6238) and HOTP (RFC 4226) implemented from scratch on crypto/hmac and the SHA-1/SHA-256/SHA-512 families. Generate live codes, validate with a drift window, mint new secrets with an otpauth:// provisioning URI, and inspect existing otpauth URIs.

---

## ✨ Features

- Generate and validate TOTP/HOTP 2FA codes
- Support common parameters (digits, period, algorithms)
- Useful for lab MFA workflows and offline verification
- Safe local operation with no third-party services
- CLI-friendly scripting interface
- Export validation results when needed

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OTOTP OTOTP.go
./OTOTP --help
./OTOTP --secret JBSWY3DPEHPK3PXP
./OTOTP --secret JBSWY3DPEHPK3PXP --validate 123456
./OTOTP --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
