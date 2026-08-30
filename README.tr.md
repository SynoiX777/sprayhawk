# 🦅 SprayHawk — Active Directory Çok Modlu Saldırı Aracı

[🇬🇧 English](README.md) | [🇦🇿 Azərbaycanca](README.az.md)

Active Directory ortamları için üç farklı modda çalışan saldırı aracı: Password Spray, klasik Brute Force ve Hydra entegrasyonu, canlı terminal arayüzü ile.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚠️ Yasal Kullanım Bildirimi

Bu araç **YALNIZCA** aşağıdaki durumlarda kullanılmak üzere tasarlanmıştır:
- Yazılı izniniz olan pentest çalışmaları
- CTF / lab ortamları (HackTheBox, TryHackMe vb.)
- Kendi laboratuvar/test ağınız

İzinsiz sistemlere karşı kullanım **yasa dışıdır**. Yazar, bu aracın kötüye kullanılmasından sorumlu değildir.

## ✨ Özellikler

- 🎯 **3 saldırı modu:**
  - `--ps` Password Spray — çok kullanıcı, 1-2 şifre (lockout-safe)
  - `--bf` Klasik Brute Force — 1 kullanıcı, tam wordlist, otomatik lockout koruması
  - `--hbf` Hydra Brute Force — sistem hydra aracını sarmalar, geniş protokol desteği
- 🔀 **İki protokol desteği** — SMB (445) ve LDAP
- 📊 **Canlı terminal arayüzü** — gerçek zamanlı istatistik, ilerleme çubuğu, bulgu paneli (`rich` kütüphanesi)
- 🔒 **Akıllı durum tespiti** — "yanlış şifre" ile "hesap kilitli/devre dışı"nı ayırt eder
- 📤 **Sonuç dışa aktarımı** — CSV ve JSON formatında

## 📦 Kurulum

```bash
git clone https://github.com/SynoiX777/sprayhawk.git
cd sprayhawk
pip install -r requirements.txt --break-system-packages
```

Hydra modu için ayrıca kurulum:
```bash
sudo apt install hydra
```

## 🚀 Kullanım

```bash
# Password Spray (SMB)
python3 sprayhawk.py --ps --smb -d corp.local -U users.txt -p "Summer2026!" --dc 10.10.10.10

# Klasik Brute Force (1 kullanıcı, lockout threshold ile korumalı)
python3 sprayhawk.py --bf --smb -d corp.local -u admin -P rockyou.txt --dc 10.10.10.10 --lockout-threshold 5

# Hydra Brute Force
python3 sprayhawk.py --hbf -d corp.local -U users.txt -P passwords.txt --dc 10.10.10.10 --service smb
```

## 🔧 Parametreler

| Parametre | Açıklama |
|---|---|
| `--ps` / `--bf` / `--hbf` | Saldırı modu seçimi |
| `-d, --domain` | Domain adı |
| `--dc` | Domain Controller IP adresi |
| `-U, --userlist` | Kullanıcı adları dosyası |
| `-u, --username` | Tek hedef kullanıcı (--bf için) |
| `-P, --passwordlist` | Şifre listesi dosyası |
| `-p, --password` | Tek şifre |
| `--smb` / `--ldap` | Protokol seçimi |
| `--delay` / `--jitter` | Denemeler arası gecikme |
| `--lockout-threshold` | AD lockout threshold (--bf için) |
| `-o, --output` | Sonuçları dosyaya yaz (.csv/.json) |

## 🧠 Password Spray, Brute Force'tan Nasıl Farklıdır?

Password spraying, **çok kullanıcı + az şifre** mantığıyla çalışır — her hesaba yalnızca 1-2 deneme yapılır, bu da lockout riskini minimuma indirir. Brute-force ise tek bir hesaba karşı çok sayıda şifre dener, genellikle hızla kilitlenmeye neden olur.

## 📄 Lisans

MIT License
