# 🦅 SprayHawk — Active Directory Multi-Rejimli Hücum Aləti

[🇬🇧 English](README.md) | [🇹🇷 Türkçe](README.tr.md)

Active Directory mühitləri üçün, üç fərqli rejimdə işləyən hücum aləti: Password Spray, klassik Brute Force və Hydra inteqrasiyası, canlı terminal UI ilə.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚠️ Qanuni İstifadə Bildirişi

Bu alət **YALNIZ** aşağıdakı hallarda istifadə üçün nəzərdə tutulub:
- Yazılı icazəniz olan pentest əlaqələndirmələri
- CTF / lab mühitləri (HackTheBox, TryHackMe və s.)
- Öz laboratoriya/test şəbəkəniz

İcazəsiz sistemlərə qarşı istifadə **qanunsuzdur**. Müəllif, bu alətin sui-istifadəsinə görə məsuliyyət daşımır.

## ✨ Xüsusiyyətlər

- 🎯 **3 hücum rejimi:**
  - `--ps` Password Spray — çoxlu istifadəçi, 1-2 parol (lockout-safe)
  - `--bf` Klassik Brute Force — 1 istifadəçi, tam wordlist, avtomatik lockout qorunması
  - `--hbf` Hydra Brute Force — sistem hydra alətini wrap edir, geniş protokol dəstəyi
- 🔀 **İki protokol dəstəyi** — SMB (445) və LDAP
- 📊 **Canlı terminal UI** — real-vaxt statistika, progress bar, tapıntı paneli (`rich` kitabxanası)
- 🔒 **Ağıllı status ayırdı** — "yanlış parol" ilə "hesab kilidli/deaktiv"i ayırır
- 📤 **Nəticə ixracı** — CSV və JSON formatında

## 📦 Quraşdırma

```bash
git clone https://github.com/SynoiX777/sprayhawk.git
cd SprayHawk
pip install -r requirements.txt --break-system-packages
```

Hydra rejimi üçün əlavə olaraq:
```bash
sudo apt install hydra
```

## 🚀 İstifadə

```bash
# Password Spray (SMB)
python3 sprayhawk.py --ps --smb -d corp.local -U users.txt -p "Summer2026!" --dc 10.10.10.10

# Klassik Brute Force (1 istifadəçi, lockout threshold ilə qorunmuş)
python3 sprayhawk.py --bf --smb -d corp.local -u admin -P rockyou.txt --dc 10.10.10.10 --lockout-threshold 5

# Hydra Brute Force
python3 sprayhawk.py --hbf -d corp.local -U users.txt -P passwords.txt --dc 10.10.10.10 --service smb
```

## 🔧 Parametrlər

| Parametr | Təsvir |
|---|---|
| `--ps` / `--bf` / `--hbf` | Hücum rejimi seçimi |
| `-d, --domain` | Domain adı |
| `--dc` | Domain Controller IP ünvanı |
| `-U, --userlist` | İstifadəçi adları faylı |
| `-u, --username` | Tək hədəf istifadəçi (--bf üçün) |
| `-P, --passwordlist` | Parol siyahısı faylı |
| `-p, --password` | Tək parol |
| `--smb` / `--ldap` | Protokol seçimi |
| `--delay` / `--jitter` | Cəhdlər arası gecikmə |
| `--lockout-threshold` | AD lockout threshold (--bf üçün) |
| `-o, --output` | Nəticə fayla yazma (.csv/.json) |

## 🧠 Niyə Password Spray, Brute Force-dan fərqlidir?

Password spraying, **çoxlu istifadəçi + az sayda parol** məntiqi ilə işləyir — hər hesab üçün cəmi 1-2 cəhd edilir, bu da lockout riskini minimuma endirir. Brute-force isə tək bir hesaba qarşı çoxlu parol sınayır, adətən sürətlə kilidlənməyə səbəb olur.

## 📄 Lisenziya

MIT License
