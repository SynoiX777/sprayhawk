# 🦅 SprayHawk — Active Directory Multi-Mode Attack Engine

[🇦🇿 Azərbaycanca](README.az.md) | [🇹🇷 Türkçe](README.tr.md)

A multi-mode Active Directory attack toolkit: Password Spray, classic Brute Force, and Hydra integration, with a live terminal UI.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚠️ Legal Use Notice

This tool is intended **ONLY** for:
- Authorized penetration testing engagements (written permission required)
- CTF / lab environments (HackTheBox, TryHackMe, etc.)
- Your own lab / test network

Using this against systems without authorization is **illegal**. The author assumes no liability for misuse.

## ✨ Features

- 🎯 **3 attack modes:**
  - `--ps` Password Spray — many users, 1-2 passwords (lockout-safe)
  - `--bf` Classic Brute Force — 1 user, full wordlist, automatic lockout protection
  - `--hbf` Hydra Brute Force — wraps the system `hydra` binary, wide protocol support
- 🔀 **Two protocols** — SMB (445) and LDAP
- 📊 **Live terminal UI** — real-time stats, progress bar, findings panel (`rich` library)
- 🔒 **Smart status detection** — distinguishes "wrong password" from "account locked/disabled"
- 📤 **Result export** — CSV and JSON formats

## 📦 Installation

```bash
git clone https://github.com/SynoiX777/sprayhawk.git
cd sprayhawk
pip install -r requirements.txt --break-system-packages
```

For Hydra mode, also install:
```bash
sudo apt install hydra
```

## 🚀 Usage

```bash
# Password Spray (SMB)
python3 sprayhawk.py --ps --smb -d corp.local -U users.txt -p "Summer2026!" --dc 10.10.10.10

# Classic Brute Force (1 user, protected by lockout threshold)
python3 sprayhawk.py --bf --smb -d corp.local -u admin -P rockyou.txt --dc 10.10.10.10 --lockout-threshold 5

# Hydra Brute Force
python3 sprayhawk.py --hbf -d corp.local -U users.txt -P passwords.txt --dc 10.10.10.10 --service smb
```

## 🔧 Parameters

| Parameter | Description |
|---|---|
| `--ps` / `--bf` / `--hbf` | Attack mode selection |
| `-d, --domain` | Domain name |
| `--dc` | Domain Controller IP address |
| `-U, --userlist` | Username list file |
| `-u, --username` | Single target user (for --bf) |
| `-P, --passwordlist` | Password list file |
| `-p, --password` | Single password |
| `--smb` / `--ldap` | Protocol selection |
| `--delay` / `--jitter` | Delay between attempts |
| `--lockout-threshold` | AD lockout threshold (for --bf) |
| `-o, --output` | Export results (.csv/.json) |

## 🧠 Why is Password Spray different from Brute Force?

Password spraying uses **many users + few passwords** — each account gets only 1-2 attempts, minimizing lockout risk. Brute-force instead tries many passwords against a single account, usually triggering a lockout quickly.

## 📄 License

MIT License
