import json
import os
import shutil
import sys
import urllib.request

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm, Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), ".quarantine")

# Allowed/Ignored Apps at Paths (Case-insensitive)
WHITELIST_APPS = [
    "firefox", "chrome", "rufus", "xampp", "android-studio", "tor",
    "counter-strike", "red alert", "command & conquer", "python", "adb",
    "discord", "spotify", "vscode", "steam", "onedrive"
]

WHITELIST_PATHS = [
    r"\desktop\games",
    r"\desktop\mypersonal data\paddleocr"
]

# CRITICAL WINDOWS FOLDERS (SAFETY EXCLUSIONS)
# Ino-overlook para hindi masira ang Windows OS sa Full Scan Mode
SYSTEM_EXCLUSIONS = [
    r"c:\windows\system32",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\windows\assembly",
    r"c:\$recycle.bin",
    r"c:\system volume information"
]

QUICK_TARGET_FOLDERS = [
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
]

STRICT_EXTS = ['.exe', '.bat', '.vbs', '.ps1', '.cmd', '.scr']

FILE_SIGNATURES = {
    '.png': [b'\x89PNG\r\n\x1a\n'],
    '.jpg': [b'\xFF\xD8'],
    '.jpeg': [b'\xFF\xD8'],
    '.exe': [b'MZ'],
    '.dll': [b'MZ']
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(scan_mode_name):
    console.print(Panel.fit(
        f"[bold cyan]🛡️  ADVANCED AI SECURITY AUDITOR[/bold cyan]\n"
        f"[dim white]Engine: Gemma 3 (1B) Local Engine  |  Mode: [bold yellow]{scan_mode_name}[/bold yellow][/dim white]",
        border_style="cyan",
        subtitle="[bold dim]PC Threat Detection System[/bold dim]"
    ))

def is_system_excluded(filepath):
    check_str = filepath.lower()
    return any(sys_path in check_str for sys_path in SYSTEM_EXCLUSIONS)

def is_safe_path_or_app(filepath):
    check_str = filepath.lower()
    
    for w_path in WHITELIST_PATHS:
        if w_path in check_str:
            return True
            
    return any(app in check_str for app in WHITELIST_APPS)

def check_magic_byte_anomaly(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext not in FILE_SIGNATURES:
        return False, ""

    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)
            expected_headers = FILE_SIGNATURES[ext]
            
            if ext in ['.png', '.jpg', '.jpeg'] and header.startswith(b'MZ'):
                return True, "DISGUISED_EXE (Executable disguised as Image)"
            
            matches = any(header.startswith(sig) for sig in expected_headers)
            if not matches and len(header) > 0:
                return True, f"HEADER_MISMATCH (Fake {ext.upper()} File)"
    except Exception:
        pass

    return False, ""

def scan_files(scan_mode):
    suspicious = []
    
    if scan_mode == "1":
        target_dirs = QUICK_TARGET_FOLDERS
        description = "🔍 Sinusuri ang Quick Target Folders (Downloads, Temp, Desktop)..."
    else:
        target_dirs = ["C:\\"]
        description = "🔍 Sinusuri ang Buong C:\\ Drive (Lalaktawan ang System32 para sa kaligtasan)..."

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold green]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(description=description, total=None)
        
        for folder in target_dirs:
            if not os.path.exists(folder):
                continue
            for root, _, files in os.walk(folder):
                # Laktawan agad ang buong protected system directory tree
                if is_system_excluded(root):
                    continue

                for file in files:
                    filepath = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    
                    if is_system_excluded(filepath) or is_safe_path_or_app(filepath):
                        continue

                    # 1. MAGIC BYTE AUDIT
                    is_anomaly, reason = check_magic_byte_anomaly(filepath)
                    if is_anomaly:
                        suspicious.append({
                            "filename": file, 
                            "path": filepath, 
                            "threat_type": f"🚨 {reason}"
                        })
                        continue

                    # 2. STRICT EXECUTABLE & TEMP SCRIPT AUDIT
                    if ext in STRICT_EXTS:
                        is_double_ext = file.count('.') > 1
                        is_temp_script = ("temp" in filepath.lower()) and (ext in ['.ps1', '.bat', '.cmd', '.vbs'])
                        contains_suspicious_word = any(w in filepath.lower() for w in ["hack", "keylogger", "exploit", "trojan"])

                        if is_double_ext or is_temp_script or contains_suspicious_word:
                            suspicious.append({
                                "filename": file, 
                                "path": filepath, 
                                "threat_type": "SUSPICIOUS_SCRIPT/EXEC"
                            })
                        
                    # Max 10 items ang ipapakita para hindi mabara si Gemma at ang Terminal table
                    if len(suspicious) >= 10:
                        break
                if len(suspicious) >= 10:
                    break

    return suspicious

def ask_gemma3_1b(scan_data):
    url = "http://localhost:11434/api/generate"
    # Kukunin ang unang 5 items para manatiling mabilis si Gemma 3
    summary_items = [f"{item['filename']} ({item['threat_type']})" for item in scan_data[:5]]
    
    prompt = (
        f"Security audit for detected items: {summary_items}. "
        "Briefly summarize the threat in 2 sentences. State Overall Risk Level (LOW, MEDIUM, or HIGH)."
    )

    data = {
        "model": "gemma3:1b",
        "prompt": prompt,
        "stream": False,
        "keep_alive": "15m",
        "options": {
            "num_predict": 320,
            "temperature": 0.0
        }
    }

    req = urllib.request.Request(
        url, 
        data=json.dumps(data).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}
    )

    try:
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[bold yellow]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description="⚡ Isinusulat ni Gemma 3 (1B) ang Security Audit...", total=None)
            with urllib.request.urlopen(req) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res.get('response', '').strip()
    except Exception as e:
        return f"Risk Level: UNKNOWN\n[dim](Ollama connection issue: {e})[/dim]"

def display_detected_files(files):
    table = Table(
        title="[bold red]⚠️  DETECTED SUSPICIOUS FILES & ANOMALIES[/bold red]", 
        border_style="red", 
        header_style="bold magenta"
    )
    table.add_column("File Name", style="bold yellow", width=22)
    table.add_column("Detection Threat Type", style="bold red", width=30)
    table.add_column("Location Path", style="dim white")

    for item in files:
        table.add_row(item["filename"], item["threat_type"], item["path"])

    console.print("")
    console.print(table)

def quarantine_file(filepath):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
            
        filename = os.path.basename(filepath)
        safe_filename = filename + ".quarantined"
        destination = os.path.join(QUARANTINE_DIR, safe_filename)
        
        shutil.move(filepath, destination)
        
        console.print(Panel(
            f"[bold green]🔒 FILE QUARANTINE SUCCESSFUL[/bold green]\n\n"
            f"📄 [bold white]File Name:[/bold white] {filename}\n"
            f"📍 [bold yellow]Isolated Path:[/bold yellow] [u]{destination}[/u]",
            border_style="green",
            expand=False
        ))
    except Exception as e:
        console.print(f"[bold red]❌ Error isolating '{os.path.basename(filepath)}':[/bold red] {e}")

def show_menu():
    clear_screen()
    console.print(Panel.fit(
        "[bold cyan]🛡️  ADVANCED AI SECURITY AUDITOR[/bold cyan]\n"
        "[dim white]Pumili ng uri ng Threat Scan na gustong patakbuhin:[/dim white]",
        border_style="cyan"
    ))
    console.print("\n[bold yellow][1][/bold yellow] 🚀 [bold white]Quick Scan[/bold white] (Downloads, Desktop, Temp folders - [green]Mabilis[/green])")
    console.print("[bold yellow][2][/bold yellow] 🐢 [bold white]Full System Drive Scan[/bold white] (Buong C:\\ Drive with OS Protections - [red]Mas matagal[/red])")
    console.print("[bold yellow][3][/bold yellow] ❌ [bold white]Exit[/bold white]\n")

    choice = Prompt.ask("👉 [bold magenta]I-enter ang numero ng iyong pinili[/bold magenta]", choices=["1", "2", "3"], default="1")
    return choice

if __name__ == "__main__":
    scan_choice = show_menu()

    if scan_choice == "3":
        console.print("\n[bold yellow]👋 Paalam! Naka-exit na ang Security Auditor.[/bold yellow]\n")
        sys.exit()

    mode_name = "QUICK SCAN" if scan_choice == "1" else "FULL C:\\ DRIVE SCAN"
    
    clear_screen()
    print_header(mode_name)
    
    files = scan_files(scan_choice)
    
    if not files:
        console.print("")
        console.print(Panel(
            "[bold green]✅ SYSTEM SECURE[/bold green]\nWalang nakitang fake image, disguised executable, o kaduda-dudang script sa na-scan na lugar.",
            border_style="green"
        ))
    else:
        display_detected_files(files)
        
        audit_res = ask_gemma3_1b(files)
        console.print("")
        console.print(Panel(
            audit_res,
            title="[bold yellow]🤖 GEMMA 3 (1B) AI SECURITY REPORT[/bold yellow]",
            border_style="yellow"
        ))
        
        console.print("")
        console.print("─"*60, style="dim white")
        console.print("")
        
        should_quarantine = Confirm.ask("👉 [bold magenta]Gusto mo bang i-QUARANTINE ang mga file na ito?[/bold magenta]")
        
        if should_quarantine:
            console.print("\n[bold cyan]🚀 Simula ng Isolation Process...[/bold cyan]\n")
            for item in files:
                quarantine_file(item['path'])
            
            console.print("")
            console.print(Panel.fit(
                f"[bold green]✅ NAPROSESO NA ANG LAHAT NG FILES![/bold green]\n\n"
                f"Ang mga na-quarantine na file ay secure na nakatago sa:\n"
                f"[bold yellow]{QUARANTINE_DIR}[/bold yellow]",
                border_style="cyan"
            ))
        else:
            console.print("\n[bold red]❌ Kinansela ng user. Walang binago sa system.[/bold red]\n")