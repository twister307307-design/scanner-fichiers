#!/usr/bin/env python3
"""
Scanner de Fichiers Avancé v4.3 - Interface Graphique
Scan complet • Fichiers corrompus • Doublons • Erreurs en temps réel
Nouveautés v4.3 :
  - Option doublons stricts : vérification du chemin relatif en plus du contenu
    (évite les faux doublons entre dossiers frères, ex: profils Bambu Studio)
Nouveautés v4.0 :
  - Scan planifié / automatique (toutes les X heures)
  - Filtre par taille minimale/maximale de fichier
  - Vérification VirusTotal API (hash MD5)
  - Score de dangerosité (1-10) par fichier suspect
  - Quarantaine : déplacer les suspects dans un dossier isolé
  - Détection fichiers chiffrés suspects (ransomware)
  - Graphique camembert par type de fichier
  - Recherche/filtre dans les onglets
  - Tri des colonnes dans les onglets Suspects & Doublons (Treeview)
  - Miniature aperçu au survol des fichiers image
"""

import os
import sys
import hashlib
import time
import stat
import threading
import platform
import shutil
import json
import csv
import math
import urllib.request
import urllib.error
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import queue
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ─── Config persistante ───────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".scanner_config.json")

def load_config():
    defaults = {
        "theme": "dark",
        "ram_pct": 25,
        "geometry": "1100x760",
        "sound_enabled": True,
        "var_corruption": True,
        "var_duplicates": True,
        "var_copy_corrupted": True,
        "var_delete_dupes": False,
        "var_save_report": True,
        # v3.0
        "virustotal_api_key": "",
        "var_virustotal": False,
        "var_quarantine": False,
        "var_detect_encrypted": True,
        "schedule_hours": 0,
        "var_schedule_enabled": False,
        "var_strict_dupes": True,
    }
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            defaults.update(data)
    except Exception:
        pass
    return defaults

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

# ─── Historique ───────────────────────────────────────────────────────────────

HISTORY_PATH = os.path.join(os.path.expanduser("~"), ".scanner_history.json")

def load_history():
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:20]  # garder les 20 derniers
    try:
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

# ─── Thèmes ───────────────────────────────────────────────────────────────────

THEMES = {
    "dark": {
        "BG": "#0f1117", "BG2": "#1a1d27", "BG3": "#252836",
        "ACCENT": "#00d4ff", "GREEN": "#00e676", "RED": "#ff5252",
        "YELLOW": "#ffd740", "PURPLE": "#ce93d8", "ORANGE": "#ff9800",
        "FG": "#e8eaf6", "DIMFG": "#7986cb", "TAB_SEL": "#3a3f52",
        "HEADER": "#0d1526",
    },
    "dracula": {
        "BG": "#282a36", "BG2": "#1e1f29", "BG3": "#44475a",
        "ACCENT": "#8be9fd", "GREEN": "#50fa7b", "RED": "#ff5555",
        "YELLOW": "#f1fa8c", "PURPLE": "#bd93f9", "ORANGE": "#ffb86c",
        "FG": "#f8f8f2", "DIMFG": "#6272a4", "TAB_SEL": "#44475a",
        "HEADER": "#1e1f29",
    },
    "nord": {
        "BG": "#2e3440", "BG2": "#3b4252", "BG3": "#434c5e",
        "ACCENT": "#88c0d0", "GREEN": "#a3be8c", "RED": "#bf616a",
        "YELLOW": "#ebcb8b", "PURPLE": "#b48ead", "ORANGE": "#d08770",
        "FG": "#eceff4", "DIMFG": "#81a1c1", "TAB_SEL": "#4c566a",
        "HEADER": "#242933",
    },
    "light": {
        "BG": "#f5f5f5", "BG2": "#ffffff", "BG3": "#e0e0e0",
        "ACCENT": "#0277bd", "GREEN": "#2e7d32", "RED": "#c62828",
        "YELLOW": "#f57f17", "PURPLE": "#6a1b9a", "ORANGE": "#e65100",
        "FG": "#212121", "DIMFG": "#546e7a", "TAB_SEL": "#bbdefb",
        "HEADER": "#e3f2fd",
    },
}

# ─── Détection corruption ─────────────────────────────────────────────────────

def is_recycle_meta(filepath):
    name = os.path.basename(filepath)
    return name.startswith("$I") and "$Recycle.Bin" in filepath

def is_file_corrupted(filepath, size):
    SHOULD_HAVE_CONTENT = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov",
        ".pdf", ".docx", ".xlsx", ".pptx",
        ".zip", ".tar", ".gz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib",
    }
    ext = Path(filepath).suffix.lower()
    if size == 0 and ext in SHOULD_HAVE_CONTENT:
        return True, "taille 0 (fichier vide suspect)"
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        MAGIC = {
            ".jpg":  [b"\xff\xd8\xff"],
            ".jpeg": [b"\xff\xd8\xff"],
            ".png":  [b"\x89PNG"],
            ".gif":  [b"GIF87a", b"GIF89a"],
            ".pdf":  [b"%PDF"],
            ".zip":  [b"PK\x03\x04"],
            ".gz":   [b"\x1f\x8b"],
            ".7z":   [b"7z\xbc\xaf"],
            ".rar":  [b"Rar!"],
            ".mp3":  [b"\xff\xfb", b"\xff\xf3", b"ID3"],
        }
        if ext in MAGIC and size > 0:
            if is_recycle_meta(filepath):
                return True, "indispo:métadonnée corbeille"
            valid = any(header.startswith(m) for m in MAGIC[ext])
            if not valid:
                return True, f"en-tête invalide pour {ext}"
    except PermissionError:
        return True, "indispo:accès refusé"
    except OSError as e:
        return True, f"indispo:erreur OS: {str(e)[:40]}"
    except Exception as e:
        return True, f"erreur lecture: {str(e)[:40]}"
    return False, ""


# ─── Détection fichiers suspects (virus/malware) ──────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    # Exécutables & scripts dangereux
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps2", ".psc1", ".psc2",
    ".msi", ".msp", ".msc", ".hta", ".cpl", ".jar", ".reg",
    # Macros Office
    ".xlsm", ".xltm", ".xlam", ".docm", ".dotm", ".pptm", ".potm", ".ppam",
    # Archives auto-extractibles ou déguisées
    ".cab", ".iso", ".img",
    # Fichiers réseaux / shell
    ".lnk", ".url",
}

SUSPICIOUS_NAME_PATTERNS = [
    "crack", "keygen", "patch", "hack", "trojan", "virus", "malware",
    "ransomware", "rootkit", "worm", "backdoor", "exploit", "payload",
    "invoice", "facture", "free", "win", "prize", "reward",
    "update_adobe", "update_flash", "setup_free",
]

def is_file_suspicious(filepath, size):
    """Retourne (True, raison) si le fichier est suspect."""
    name = os.path.basename(filepath).lower()
    ext  = Path(filepath).suffix.lower()
    stem = Path(filepath).stem.lower()

    # Double extension (ex: photo.jpg.exe)
    double_ext_exts = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta"}
    if ext in double_ext_exts:
        inner_ext = Path(stem).suffix.lower()
        if inner_ext in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc",
                         ".txt", ".mp3", ".mp4", ".zip"}:
            return True, f"double extension suspecte ({inner_ext}{ext})"

    # Extension dangereuse connue
    if ext in SUSPICIOUS_EXTENSIONS:
        return True, f"extension à risque ({ext})"

    # Nom contenant des mots-clés suspects
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in name:
            return True, f"nom suspect (contient « {pattern} »)"

    # Fichier caché avec extension exécutable (commence par un point sur Unix)
    if name.startswith(".") and ext in {".sh", ".py", ".pl", ".rb", ".exe", ".bin"}:
        return True, f"fichier caché exécutable ({ext})"

    # Fichier très petit se faisant passer pour un média (< 5 Ko)
    media_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".avi", ".mkv", ".mp3"}
    if ext in media_exts and 0 < size < 5120:
        return True, f"fichier média anormalement petit ({format_size(size)})"

    return False, ""


# ─── Détection fichiers chiffrés suspects (ransomware) ───────────────────────

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".enc", ".crypted", ".locked", ".crypt", ".crypto",
    ".vault", ".zzzzz", ".micro", ".zepto", ".cerber", ".locky",
    ".wncry", ".wcry", ".wnry", ".wncrypt", ".wncryptt",
    ".dharma", ".globe", ".globe2", ".globe3",
    ".osiris", ".shit", ".thor", ".aesir",
    ".id-", ".r5a", ".r4a",
}

def is_file_encrypted_suspect(filepath, size):
    """Détecte les fichiers potentiellement chiffrés par ransomware."""
    ext  = Path(filepath).suffix.lower()
    name = os.path.basename(filepath).lower()

    # Extension typique ransomware
    for rext in RANSOMWARE_EXTENSIONS:
        if ext == rext or name.endswith(rext):
            return True, f"extension ransomware connue ({ext})"

    # Entropie élevée sur les premiers octets (> 7.5 bits/octet → probablement chiffré)
    if size > 512:
        try:
            with open(filepath, "rb") as f:
                data = f.read(4096)
            if len(data) > 0:
                freq = [0] * 256
                for b in data:
                    freq[b] += 1
                entropy = 0.0
                n = len(data)
                for c in freq:
                    if c > 0:
                        p = c / n
                        entropy -= p * math.log2(p)
                if entropy > 7.5:
                    safe_high_entropy = {
                        # Archives
                        ".zip", ".gz", ".7z", ".rar", ".tar", ".bz2", ".xz", ".zst",
                        # Médias
                        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".flac", ".aac", ".ogg",
                        # Images
                        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico",
                        # Exécutables / libs (compressés/signés par nature)
                        ".exe", ".dll", ".so", ".dylib",
                        # Paquets applicatifs Microsoft / AppX
                        ".msix", ".msixbundle", ".appx", ".appxbundle",
                        ".cab", ".msi", ".msm", ".msp",
                        # Paquets données apps (Chrome, Edge, Copilot…)
                        ".pak", ".data", ".dat", ".bin",
                        # Signatures numériques
                        ".sig", ".p7s", ".p7b", ".p12", ".pfx",
                        # Polices
                        ".ttf", ".otf", ".woff", ".woff2",
                        # PDF / docs compressés
                        ".pdf", ".docx", ".xlsx", ".pptx", ".odt",
                        # Bases de données / caches
                        ".db", ".sqlite", ".ldb", ".pak",
                    }
                    if ext not in safe_high_entropy:
                        return True, f"entropie élevée ({entropy:.2f}/8.0) — possible chiffrement"
        except Exception:
            pass

    return False, ""


# ─── Fichiers système Windows (à analyser mais exclure des résultats suspects/doublons) ──

WINDOWS_SYSTEM_PATHS = {
    # Dossiers système Windows core
    "windows", "system32", "syswow64", "winsxs", "winside",
    "drivers", "driverstore", "inf", "prefetch",
    "assembly", "microsoft.net", "windowsapps",
    "$windows.~bt", "$windows.~ws",
    # Dossiers applicatifs Microsoft (Edge, Copilot, Office, VS…)
    "program files", "program files (x86)",
    "microsoft", "microsoft shared", "microsoft office",
    "windowsapps", "programdata",
    # Installeurs / dépôts
    "installshield installation information", "installer",
    "resiliencylinks",
    # Dossiers cache / temp système
    "appdata", "localappdata", "temp", "tmp",
}

WINDOWS_SYSTEM_EXTENSIONS = {
    # Drivers / système bas niveau
    ".sys", ".drv", ".mui", ".mun", ".cat", ".nls", ".etl",
    # Paquets Microsoft Store
    ".msix", ".msixbundle", ".appx", ".appxbundle",
    # Installeurs Windows
    ".cab", ".msi", ".msm", ".msp",
    # Signatures / certificats
    ".sig", ".p7s", ".p7b", ".p12", ".pfx",
    # Paquets données apps (Chrome, Edge, Copilot…)
    ".pak",
}

def is_windows_system_file(filepath):
    """Retourne True si le fichier appartient au système Windows.
    Ces fichiers sont analysés normalement mais ne sont PAS marqués comme
    suspects/doublons/corrompus bizarres — leur chiffrement ou haute entropie
    est normale (ex: fichiers WinSxS compressés, MUI localisés, etc.).
    """
    parts = [p.lower() for p in Path(filepath).parts]
    for part in parts:
        if part in WINDOWS_SYSTEM_PATHS:
            return True
    ext = Path(filepath).suffix.lower()
    if ext in WINDOWS_SYSTEM_EXTENSIONS:
        return True
    # Préfixes typiques fichiers système
    name = os.path.basename(filepath).lower()
    if name.startswith(("ntoskrnl", "hal.", "win32k", "ntdll", "kernel32", "user32")):
        return True
    return False


def compute_danger_score(reason):
    """Calcule un score de dangerosité 1-10 selon la raison détectée."""
    score = 1
    r_low = reason.lower()
    kw_scores = {
        "double extension": 5,
        "ransomware": 9,
        "entropie élevée": 6,
        "extension à risque": 3,
        "nom suspect": 4,
        "fichier caché exécutable": 5,
        "fichier média anormalement": 3,
        "virustotal": 10,
    }
    for kw, pts in kw_scores.items():
        if kw in r_low:
            score = max(score, pts)
    return min(score, 10)


# ─── VirusTotal API ──────────────────────────────────────────────────────────

def check_virustotal(md5_hash, api_key):
    """
    Interroge l'API VirusTotal v3 avec un hash MD5.
    Retourne (is_malicious, detections, total, permalink).
    """
    if not api_key or not md5_hash:
        return False, 0, 0, ""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        permalink = f"https://www.virustotal.com/gui/file/{md5_hash}"
        return (malicious + suspicious) > 0, malicious + suspicious, total, permalink
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, 0, 0, ""
        return False, 0, 0, ""
    except Exception:
        return False, 0, 0, ""


def format_size(size_bytes):
    if size_bytes < 0:
        return "?"
    for unit in ["o", "Ko", "Mo", "Go", "To"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} Po"


def format_duration(seconds):
    if seconds < 0 or seconds != seconds:
        return "--:--"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds//60}m {seconds%60:02d}s"
    else:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f"{h}h {m:02d}m {s:02d}s"


def get_desktop():
    system = platform.system()
    if system == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
            desktop, _ = winreg.QueryValueEx(key, "Desktop")
            return desktop
        except Exception:
            pass
    for name in ("Desktop", "Bureau"):
        p = os.path.join(os.path.expanduser("~"), name)
        if os.path.isdir(p):
            return p
    return os.path.expanduser("~")


# ─── Barres ───────────────────────────────────────────────────────────────────

def make_bounce_bar(pos, direction, bar_w=50, block=8):
    pos += direction
    if pos >= bar_w - block:
        pos = bar_w - block
        direction = -1
    elif pos <= 0:
        pos = 0
        direction = 1
    inner = " " * pos + "█" * block + " " * (bar_w - pos - block)
    return f"[{inner}]", pos, direction


def make_progress_bar(pct, bar_w=50):
    filled = int(bar_w * pct / 100)
    empty  = bar_w - filled
    return f"[{'█' * filled}{'░' * empty}]"


# ─── Notification Windows ─────────────────────────────────────────────────────

def win_toast(title, msg):
    pass  # plus utilisé

def play_done_sound():
    """Joue une mélodie cristalline douce en fin de scan (arpège ascendant + résolution)."""
    try:
        if platform.system() == "Windows":
            import winsound
            # Mélodie : Do-Mi-Sol-Do (arpège majeur ascendant) puis Mi résolutif
            notes = [
                (1046, 120),   # Do6
                (1318, 120),   # Mi6
                (1568, 120),   # Sol6
                (2093, 200),   # Do7 (note haute, tenue)
                (1760, 280),   # La6 (résolution douce, longue)
            ]
            for freq, dur in notes:
                winsound.Beep(freq, dur)
        elif platform.system() == "Darwin":
            os.system("afplay /System/Library/Sounds/Glass.aiff &")
        else:
            sounds = [
                "paplay /usr/share/sounds/freedesktop/stereo/complete.oga",
                "aplay /usr/share/sounds/freedesktop/stereo/complete.oga",
                "paplay /usr/share/sounds/ubuntu/notifications/Xylo.ogg",
            ]
            for cmd in sounds:
                if os.system(f"{cmd} 2>/dev/null") == 0:
                    break
            else:
                print("\a", end="", flush=True)
    except Exception:
        pass


# ─── Interface Graphique ──────────────────────────────────────────────────────

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tip    = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, event=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, font=("Consolas", 7),
                       bg="#2a2d3e", fg="#e8eaf6", relief="flat", padx=6, pady=3)
        lbl.pack()

    def _hide(self, event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.cfg  = load_config()

        self.root.title("Scanner de Fichiers Avancé v4.3")
        self.root.geometry(self.cfg.get("geometry", "1100x760"))
        self.root.minsize(900, 620)

        self._apply_theme(self.cfg.get("theme", "dark"), init=True)

        self.scan_thread   = None
        self.stop_event    = threading.Event()
        self.msg_queue     = queue.Queue()
        self.scan_roots    = []
        self.results       = {}
        self.report_path   = None
        self._bounce_pos   = 0
        self._bounce_dir   = 1
        self._bar_line     = None
        self._file_line    = None
        self._speed_history = []
        self._ext_stats    = defaultdict(lambda: {"count": 0, "size": 0})
        # v3.0
        self._schedule_timer = None
        self._suspects_data  = []   # liste de (path, reason, score, vt_detections)

        self._build_ui()
        self._set_default_roots()
        self._poll_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.cfg["geometry"] = self.root.geometry()
        self.cfg["last_scan_roots"] = list(self.roots_list.get(0, tk.END))
        save_config(self.cfg)
        if self._schedule_timer is not None:
            self._schedule_timer.cancel()
        self.root.destroy()

    # ── Thème ──────────────────────────────────────────────────────────────────

    def _apply_theme(self, name, init=False):
        t = THEMES.get(name, THEMES["dark"])
        self.BG      = t["BG"]
        self.BG2     = t["BG2"]
        self.BG3     = t["BG3"]
        self.ACCENT  = t["ACCENT"]
        self.GREEN   = t["GREEN"]
        self.RED     = t["RED"]
        self.YELLOW  = t["YELLOW"]
        self.PURPLE  = t["PURPLE"]
        self.ORANGE  = t["ORANGE"]
        self.FG      = t["FG"]
        self.DIMFG   = t["DIMFG"]
        self.TAB_SEL = t["TAB_SEL"]
        self.HEADER  = t["HEADER"]
        self.cfg["theme"] = name
        if not init:
            messagebox.showinfo("Thème", f"Thème « {name} » appliqué.\nRelancez l'application pour l'effet complet.")

    # ── UI ─────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.configure(bg=self.BG)

        # ── Header ──
        header = tk.Frame(self.root, bg=self.HEADER, pady=12)
        header.pack(fill=tk.X)
        tk.Label(header, text="🔍  SCANNER DE FICHIERS AVANCÉ  v4.3",
                 font=("Consolas", 16, "bold"), fg=self.ACCENT, bg=self.HEADER).pack()
        tk.Label(header, text="Doublons  •  Corrompus  •  Suspects  •  Quarantaine  •  VirusTotal  •  Erreurs en temps réel",
                 font=("Consolas", 9), fg=self.DIMFG, bg=self.HEADER).pack()

        # Sélecteur de thème dans le header
        theme_frame = tk.Frame(header, bg=self.HEADER)
        theme_frame.pack(pady=(4, 0))
        tk.Label(theme_frame, text="Thème :", font=("Consolas", 7),
                 fg=self.DIMFG, bg=self.HEADER).pack(side=tk.LEFT, padx=(0, 6))
        for tname in THEMES:
            btn = tk.Button(theme_frame, text=tname,
                            font=("Consolas", 7), bg=self.BG3, fg=self.FG,
                            activebackground=self.BG2, activeforeground=self.ACCENT,
                            borderwidth=0, padx=8, pady=2, cursor="hand2", relief=tk.FLAT,
                            command=lambda n=tname: self._apply_theme(n))
            btn.pack(side=tk.LEFT, padx=2)

        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)

        # ── Panel gauche ──
        left = tk.Frame(body, bg=self.BG, width=300)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left.pack_propagate(False)

        self._section(left, "📁  DOSSIERS À SCANNER")
        self.roots_list = tk.Listbox(left, bg=self.BG3, fg=self.FG,
                                     selectbackground=self.ACCENT, selectforeground="#000",
                                     font=("Consolas", 8), height=5, borderwidth=0,
                                     highlightthickness=1, highlightcolor=self.ACCENT,
                                     highlightbackground=self.BG3)
        self.roots_list.pack(fill=tk.X, pady=(0, 4))
        btn_row = tk.Frame(left, bg=self.BG)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        self._btn(btn_row, "＋ Ajouter", self._add_folder, self.ACCENT).pack(side=tk.LEFT, padx=(0, 4))
        self._btn(btn_row, "✕ Retirer",  self._remove_folder, self.RED).pack(side=tk.LEFT)

        # ── Accordéon OPTIONS ──
        opt_header = tk.Frame(left, bg=self.BG, cursor="hand2")
        opt_header.pack(fill=tk.X, pady=(8, 0))
        self._opt_arrow = tk.Label(opt_header, text="▶", font=("Consolas", 8, "bold"),
                                   fg=self.DIMFG, bg=self.BG, cursor="hand2")
        self._opt_arrow.pack(side=tk.LEFT)
        opt_label = tk.Label(opt_header, text="  ⚙️  OPTIONS", font=("Consolas", 8, "bold"),
                             fg=self.DIMFG, bg=self.BG, cursor="hand2")
        opt_label.pack(side=tk.LEFT)
        self._opt_collapsed = True

        self._opt_frame = tk.Frame(left, bg=self.BG)

        self.var_corruption     = tk.BooleanVar(value=self.cfg.get("var_corruption", True))
        self.var_duplicates     = tk.BooleanVar(value=self.cfg.get("var_duplicates", True))
        self.var_copy_corrupted = tk.BooleanVar(value=self.cfg.get("var_copy_corrupted", True))
        self.var_delete_dupes   = tk.BooleanVar(value=self.cfg.get("var_delete_dupes", False))
        self.var_save_report    = tk.BooleanVar(value=self.cfg.get("var_save_report", True))
        self.var_sound          = tk.BooleanVar(value=self.cfg.get("sound_enabled", True))
        # v3.0
        self.var_virustotal     = tk.BooleanVar(value=self.cfg.get("var_virustotal", False))
        self.var_quarantine     = tk.BooleanVar(value=self.cfg.get("var_quarantine", False))
        self.var_detect_encrypted = tk.BooleanVar(value=self.cfg.get("var_detect_encrypted", True))
        self.var_schedule_enabled = tk.BooleanVar(value=self.cfg.get("var_schedule_enabled", False))
        self.var_strict_dupes   = tk.BooleanVar(value=self.cfg.get("var_strict_dupes", True))

        for text, var, color, tip in [
            # ── Analyse ──
            ("Détecter fichiers corrompus",  self.var_corruption,     self.RED,    "Analyse les en-têtes de fichiers"),
            ("🔐 Détecter chiffrement (ransomware)", self.var_detect_encrypted, self.YELLOW, "Détecte entropie élevée + extensions ransomware"),
            ("Trouver les doublons",          self.var_duplicates,     self.PURPLE, "Hash MD5 partiel pour détecter les copies"),
        ]:
            row = tk.Frame(self._opt_frame, bg=self.BG)
            row.pack(fill=tk.X, pady=2)
            cb = tk.Checkbutton(row, text=text, variable=var,
                                bg=self.BG, fg=color, selectcolor=self.BG3,
                                activebackground=self.BG, activeforeground=color,
                                font=("Consolas", 8))
            cb.pack(anchor="w")
            Tooltip(cb, tip)

        # Option doublons stricts (sous-option indentée)
        row_strict = tk.Frame(self._opt_frame, bg=self.BG)
        row_strict.pack(fill=tk.X, pady=(0, 2))
        cb_strict = tk.Checkbutton(row_strict,
                                   text="  ↳ Strict : même chemin relatif",
                                   variable=self.var_strict_dupes,
                                   bg=self.BG, fg=self.DIMFG, selectcolor=self.BG3,
                                   activebackground=self.BG, activeforeground=self.FG,
                                   font=("Consolas", 7))
        cb_strict.pack(anchor="w")
        Tooltip(cb_strict,
                "Évite les faux doublons entre dossiers frères\n"
                "(ex: profils Anycubic/ vs Elegoo/ dans Bambu Studio).\n"
                "Coché = doublon seulement si même chemin relatif identique.\n"
                "Décoché = doublon dès que contenu identique (comportement original).")

        tk.Label(self._opt_frame, text="  — Actions —",
                 font=("Consolas", 7, "italic"), fg=self.DIMFG, bg=self.BG).pack(anchor="w", pady=(4, 0))

        for text, var, color, tip in [
            # ── Actions ──
            ("Copier corrompus → Bureau",     self.var_copy_corrupted, self.YELLOW, "Copie les fichiers suspects sur le Bureau"),
            ("Supprimer les doublons",        self.var_delete_dupes,   self.RED,    "Garde l'original, supprime les copies"),
        ]:
            row = tk.Frame(self._opt_frame, bg=self.BG)
            row.pack(fill=tk.X, pady=2)
            cb = tk.Checkbutton(row, text=text, variable=var,
                                bg=self.BG, fg=color, selectcolor=self.BG3,
                                activebackground=self.BG, activeforeground=color,
                                font=("Consolas", 8))
            cb.pack(anchor="w")
            Tooltip(cb, tip)

        tk.Label(self._opt_frame, text="  — Rapport & son —",
                 font=("Consolas", 7, "italic"), fg=self.DIMFG, bg=self.BG).pack(anchor="w", pady=(4, 0))

        for text, var, color, tip in [
            # ── Rapports / divers ──
            ("Sauvegarder rapport .txt",      self.var_save_report,    self.GREEN,  "Rapport complet dans votre dossier utilisateur"),
            ("🔔 Son en fin de scan",         self.var_sound,          self.ACCENT, "Mélodie cristalline quand le scan est terminé"),
        ]:
            row = tk.Frame(self._opt_frame, bg=self.BG)
            row.pack(fill=tk.X, pady=2)
            cb = tk.Checkbutton(row, text=text, variable=var,
                                bg=self.BG, fg=color, selectcolor=self.BG3,
                                activebackground=self.BG, activeforeground=color,
                                font=("Consolas", 8))
            cb.pack(anchor="w")
            Tooltip(cb, tip)

        # ── VirusTotal ──
        tk.Frame(self._opt_frame, bg=self.DIMFG, height=1).pack(fill=tk.X, pady=(6, 4))
        vt_cb_row = tk.Frame(self._opt_frame, bg=self.BG)
        vt_cb_row.pack(fill=tk.X)
        cb_vt = tk.Checkbutton(vt_cb_row, text="🦠 Vérifier VirusTotal (API)",
                               variable=self.var_virustotal,
                               bg=self.BG, fg="#ff6d00", selectcolor=self.BG3,
                               activebackground=self.BG, activeforeground="#ff6d00",
                               font=("Consolas", 8),
                               command=self._toggle_vt_key_row)
        cb_vt.pack(side=tk.LEFT)
        Tooltip(cb_vt, "Envoie le hash MD5 des suspects à VirusTotal")

        # Bloc clé API VT — affiché SOUS la case, masqué si décochée
        self._vt_key_row = tk.Frame(self._opt_frame, bg=self.BG2,
                                    padx=8, pady=6, relief=tk.FLAT, bd=1)
        # Ligne titre + bouton aide
        vt_key_header = tk.Frame(self._vt_key_row, bg=self.BG2)
        vt_key_header.pack(fill=tk.X)
        tk.Label(vt_key_header, text="🔑  Clé API VirusTotal",
                 font=("Consolas", 7, "bold"), fg="#ff6d00", bg=self.BG2).pack(side=tk.LEFT)
        btn_vt_help = tk.Button(vt_key_header, text="? Aide",
                                font=("Consolas", 7), bg=self.BG3, fg=self.ACCENT,
                                activebackground=self.BG, borderwidth=0,
                                cursor="hand2", relief=tk.FLAT, padx=5, pady=1,
                                command=self._open_vt_help)
        btn_vt_help.pack(side=tk.RIGHT, padx=2)
        Tooltip(btn_vt_help, "Comment obtenir une clé API VirusTotal gratuite")
        # Champ clé + œil
        vt_entry_row = tk.Frame(self._vt_key_row, bg=self.BG2)
        vt_entry_row.pack(fill=tk.X, pady=(4, 0))
        self.vt_key_var = tk.StringVar(value=self.cfg.get("virustotal_api_key", ""))
        self._vt_entry = tk.Entry(vt_entry_row, textvariable=self.vt_key_var,
                                  font=("Consolas", 7), bg=self.BG3, fg=self.FG,
                                  insertbackground=self.FG, borderwidth=0,
                                  show="*", width=26)
        self._vt_entry.pack(side=tk.LEFT, padx=(0, 4))
        self._vt_show = False
        def _toggle_vt_show():
            self._vt_show = not self._vt_show
            self._vt_entry.config(show="" if self._vt_show else "*")
            btn_eye.config(text="🙈" if self._vt_show else "👁")
        btn_eye = tk.Button(vt_entry_row, text="👁",
                            font=("Consolas", 8), bg=self.BG3, fg=self.DIMFG,
                            activebackground=self.BG2, borderwidth=0,
                            cursor="hand2", relief=tk.FLAT, padx=4,
                            command=_toggle_vt_show)
        btn_eye.pack(side=tk.LEFT)
        Tooltip(btn_eye, "Afficher / masquer la clé API")
        # Afficher ou non selon l'état initial de la case
        if self.var_virustotal.get():
            self._vt_key_row.pack(fill=tk.X, pady=(4, 4))

        # ── Scan planifié ──
        tk.Frame(self._opt_frame, bg=self.DIMFG, height=1).pack(fill=tk.X, pady=(4, 4))
        sch_cb_row = tk.Frame(self._opt_frame, bg=self.BG)
        sch_cb_row.pack(fill=tk.X)
        cb_sch = tk.Checkbutton(sch_cb_row, text="⏱ Scan planifié automatique",
                                variable=self.var_schedule_enabled,
                                bg=self.BG, fg=self.ACCENT, selectcolor=self.BG3,
                                activebackground=self.BG, activeforeground=self.ACCENT,
                                font=("Consolas", 8),
                                command=self._toggle_schedule_row)
        cb_sch.pack(side=tk.LEFT)
        Tooltip(cb_sch, "Lance le scan automatiquement toutes les X heures")

        # Ligne durée (masquée si case décochée)
        self._sch_dur_row = tk.Frame(self._opt_frame, bg=self.BG)
        tk.Label(self._sch_dur_row, text="  Toutes les", font=("Consolas", 7),
                 fg=self.DIMFG, bg=self.BG).pack(side=tk.LEFT)
        self.var_schedule = tk.StringVar(value=str(self.cfg.get("schedule_hours", 1)))
        tk.Entry(self._sch_dur_row, textvariable=self.var_schedule, width=4,
                 font=("Consolas", 7), bg=self.BG3, fg=self.FG,
                 insertbackground=self.FG, borderwidth=0).pack(side=tk.LEFT, padx=4)
        tk.Label(self._sch_dur_row, text="heure(s)", font=("Consolas", 7),
                 fg=self.DIMFG, bg=self.BG).pack(side=tk.LEFT)
        self.btn_schedule = tk.Button(self._sch_dur_row, text="Activer",
                                      font=("Consolas", 7), bg=self.BG3, fg=self.GREEN,
                                      activebackground=self.BG2, borderwidth=0,
                                      cursor="hand2", relief=tk.FLAT, padx=6,
                                      command=self._toggle_schedule)
        self.btn_schedule.pack(side=tk.LEFT, padx=4)
        self.lbl_schedule_status = tk.Label(self._opt_frame, text="",
                                            font=("Consolas", 7), fg=self.GREEN, bg=self.BG)
        if self.var_schedule_enabled.get():
            self._sch_dur_row.pack(fill=tk.X, pady=(2, 0))
            self.lbl_schedule_status.pack(anchor="w")

        for widget in (opt_header, self._opt_arrow, opt_label):
            widget.bind("<Button-1>", lambda e: self._toggle_options())

        # ── Limite RAM ──
        self._section(left, "🧠  LIMITE RAM")
        ram_row = tk.Frame(left, bg=self.BG)
        ram_row.pack(fill=tk.X, pady=(0, 2))
        self.var_ram = tk.IntVar(value=self.cfg.get("ram_pct", 25))
        for pct in [5, 15, 25, 50, 75, 90]:
            tk.Radiobutton(ram_row, text=f"{pct}%", variable=self.var_ram, value=pct,
                           command=self._on_ram_change,
                           bg=self.BG, fg=self.DIMFG, selectcolor=self.BG3,
                           activebackground=self.BG, activeforeground=self.ACCENT,
                           font=("Consolas", 8)).pack(side=tk.LEFT, padx=2)
        self.lbl_ram_info = tk.Label(left, text="", font=("Consolas", 7),
                                     fg=self.YELLOW, bg=self.BG, wraplength=270, justify="left")
        self.lbl_ram_info.pack(anchor="w", pady=(0, 6))

        tk.Frame(left, bg=self.BG, height=8).pack()
        self.btn_start = self._btn(left, "▶  LANCER LE SCAN", self._start_scan, self.GREEN, big=True)
        self.btn_start.pack(fill=tk.X, pady=(0, 6))
        Tooltip(self.btn_start, "Lance le scan sur les dossiers sélectionnés")
        self.btn_stop = self._btn(left, "■  ARRÊTER", self._stop_scan, self.RED, big=True)
        self.btn_stop.pack(fill=tk.X)
        self.btn_stop.config(state=tk.DISABLED)
        tk.Frame(left, bg=self.BG, height=8).pack()
        self.btn_report = self._btn(left, "📄  Ouvrir rapport .txt", self._open_report, self.DIMFG)
        self.btn_report.pack(fill=tk.X, pady=(0, 3))
        self.btn_report.config(state=tk.DISABLED)
        self.btn_export_csv = self._btn(left, "📊  Exporter CSV", self._export_csv, self.DIMFG)
        self.btn_export_csv.pack(fill=tk.X, pady=(0, 3))
        self.btn_export_csv.config(state=tk.DISABLED)
        Tooltip(self.btn_export_csv, "Exporte corrompus + doublons + chiffrés en CSV")
        self.btn_history = self._btn(left, "🕓  Historique scans", self._show_history, self.DIMFG)
        self.btn_history.pack(fill=tk.X)
        Tooltip(self.btn_history, "Affiche les 20 derniers scans")

        # ── Panel droit ──
        right = tk.Frame(body, bg=self.BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Cards
        cards = tk.Frame(right, bg=self.BG)
        cards.pack(fill=tk.X, pady=(0, 8))
        self.card_scanned   = self._card(cards, "Scannés",       "0",     self.ACCENT)
        self.card_size      = self._card(cards, "Taille",        "0 o",   self.GREEN)
        self.card_corrupted = self._card(cards, "Corrompus",     "0",     self.RED)
        self.card_suspects  = self._card(cards, "Suspects",      "0",     "#ff6d00")
        self.card_dupes     = self._card(cards, "Doublons",      "0",     self.PURPLE)
        self.card_errors    = self._card(cards, "Chiffrés",      "0",     self.ORANGE)
        self.card_speed     = self._card(cards, "Vitesse",       "0 f/s", self.DIMFG)
        for c in (self.card_scanned, self.card_size, self.card_corrupted,
                  self.card_suspects, self.card_dupes,
                  self.card_errors, self.card_speed):
            c.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            Tooltip(c, c._val_label.cget("text"))

        # Notebook
        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True)
        self._style_notebook(notebook)
        self.log_all       = self._log_tab(notebook, "📋 Journal")
        self.log_clean, self.tree_clean = self._clean_tab(notebook)
        self.log_corrupted = self._log_tab(notebook, "🔴 Corrompus")
        self.log_suspects, self.btn_open_suspects, self.btn_quarantine = \
            self._suspects_tab(notebook)
        self.log_dupes, self.btn_del_dupes = self._log_tab_with_action(
            notebook, "🟣 Doublons", "🗑  Supprimer les doublons", self._manual_delete_dupes, self.PURPLE)
        self.log_errors    = self._log_tab(notebook, "🟠 Chiffrés")
        self.tab_stats     = self._build_stats_tab(notebook)

        # Compteurs sous-catégories indispo

        # ── Barre de recherche globale ──
        search_frame = tk.Frame(right, bg=self.BG2, pady=3)
        search_frame.pack(fill=tk.X, before=notebook)
        tk.Label(search_frame, text="🔍", font=("Consolas", 9), fg=self.DIMFG, bg=self.BG2).pack(side=tk.LEFT, padx=(6, 2))
        self.var_search = tk.StringVar()
        self.var_search.trace_add("write", lambda *a: self._filter_suspects())
        self._search_entry = tk.Entry(search_frame, textvariable=self.var_search,
                                      font=("Consolas", 8), bg=self.BG3, fg=self.FG,
                                      insertbackground=self.FG, borderwidth=0, width=28)
        self._search_entry.pack(side=tk.LEFT, padx=4)
        tk.Label(search_frame, text="(filtre l'onglet Suspects)", font=("Consolas", 7),
                 fg=self.DIMFG, bg=self.BG2).pack(side=tk.LEFT)

        # Status bar
        self.status_bar = tk.Label(self.root, text="Prêt.", font=("Consolas", 8),
                                   fg=self.DIMFG, bg=self.HEADER, anchor="w", padx=10, pady=4)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # ── Onglet Stats ───────────────────────────────────────────────────────────

    def _build_stats_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.BG)
        notebook.add(frame, text="📈 Stats")

        top = tk.Frame(frame, bg=self.BG)
        top.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(top, text="TOP EXTENSIONS — taille & nombre de fichiers",
                 font=("Consolas", 8, "bold"), fg=self.DIMFG, bg=self.BG).pack(anchor="w")

        # Canvas barres
        self.stats_canvas = tk.Canvas(frame, bg=self.BG2, highlightthickness=0, height=230)
        self.stats_canvas.pack(fill=tk.X, padx=10, pady=(0, 6))

        # Camembert
        tk.Label(frame, text="RÉPARTITION PAR TYPE (camembert)",
                 font=("Consolas", 8, "bold"), fg=self.DIMFG, bg=self.BG).pack(anchor="w", padx=10)
        self.pie_canvas = tk.Canvas(frame, bg=self.BG2, highlightthickness=0, height=200)
        self.pie_canvas.pack(fill=tk.X, padx=10, pady=(0, 6))

        # Courbe de vitesse
        tk.Label(frame, text="COURBE DE VITESSE (f/s en temps réel)",
                 font=("Consolas", 8, "bold"), fg=self.DIMFG, bg=self.BG).pack(anchor="w", padx=10)
        self.speed_canvas = tk.Canvas(frame, bg=self.BG2, highlightthickness=0, height=100)
        self.speed_canvas.pack(fill=tk.X, padx=10, pady=(0, 6))

        return frame

    def _update_stats_canvas(self):
        c = self.stats_canvas
        c.delete("all")
        w = c.winfo_width() or 600
        h = c.winfo_height() or 280

        if not self._ext_stats:
            c.create_text(w//2, h//2, text="Aucune donnée", fill=self.DIMFG,
                          font=("Consolas", 9))
            return

        # Top 12 par taille
        top = sorted(self._ext_stats.items(), key=lambda x: x[1]["size"], reverse=True)[:12]
        if not top:
            return

        max_size  = max(v["size"]  for _, v in top) or 1
        max_count = max(v["count"] for _, v in top) or 1

        bar_h  = 18
        gap    = 8
        left_m = 70
        right_m = 14
        colors = [self.ACCENT, self.GREEN, self.PURPLE, self.YELLOW,
                  self.ORANGE, self.RED, self.DIMFG, "#4dd0e1",
                  "#a5d6a7", "#ef9a9a", "#ffe082", "#ce93d8"]

        for i, (ext, vals) in enumerate(top):
            y = 16 + i * (bar_h * 2 + gap)
            col = colors[i % len(colors)]
            # barre taille
            bw = int((w - left_m - right_m) * vals["size"] / max_size)
            c.create_rectangle(left_m, y, left_m + bw, y + bar_h,
                               fill=col, outline="")
            # barre count (plus fine, superposée semi-transparente)
            bw2 = int((w - left_m - right_m) * vals["count"] / max_count)
            c.create_rectangle(left_m, y + bar_h - 4, left_m + bw2, y + bar_h,
                               fill=self.FG, outline="")
            # labels
            lbl = ext if ext else "(sans ext)"
            c.create_text(left_m - 4, y + bar_h // 2, text=lbl,
                          anchor="e", fill=self.FG, font=("Consolas", 7))
            info = f"{format_size(vals['size'])}  {vals['count']:,} f"
            c.create_text(left_m + bw + 4, y + bar_h // 2, text=info,
                          anchor="w", fill=self.DIMFG, font=("Consolas", 7))

    def _update_speed_canvas(self):
        c = self.speed_canvas
        c.delete("all")
        w = c.winfo_width() or 600
        h = c.winfo_height() or 120
        data = self._speed_history[-200:]
        if len(data) < 2:
            return
        max_v = max(data) or 1
        pts = []
        for i, v in enumerate(data):
            x = int(i / (len(data) - 1) * (w - 20)) + 10
            y = int(h - 10 - (v / max_v) * (h - 20))
            pts.append((x, y))
        c.create_line(10, h - 10, w - 10, h - 10, fill=self.BG3, width=1)
        for i in range(len(pts) - 1):
            c.create_line(pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1],
                          fill=self.ACCENT, width=2)
        c.create_text(w - 10, 10, text=f"max {max_v:.0f} f/s",
                      anchor="ne", fill=self.DIMFG, font=("Consolas", 7))

    def _update_pie_canvas(self):
        """Dessine un camembert de répartition des types de fichiers par taille."""
        c = self.pie_canvas
        c.delete("all")
        w = c.winfo_width() or 600
        h = c.winfo_height() or 200

        if not self._ext_stats:
            c.create_text(w//2, h//2, text="Aucune donnée", fill=self.DIMFG,
                          font=("Consolas", 9))
            return

        # Regrouper les petites catégories en "Autres"
        top = sorted(self._ext_stats.items(), key=lambda x: x[1]["size"], reverse=True)[:9]
        total_size = sum(v["size"] for v in self._ext_stats.values())
        top_size   = sum(v["size"] for _, v in top)
        other_size = total_size - top_size

        slices = [(ext if ext else "(sans ext)", vals["size"]) for ext, vals in top]
        if other_size > 0:
            slices.append(("Autres", other_size))

        total = sum(s for _, s in slices) or 1
        colors_pie = [self.ACCENT, self.GREEN, self.PURPLE, self.YELLOW,
                      self.ORANGE, self.RED, "#4dd0e1", "#a5d6a7",
                      "#ef9a9a", self.DIMFG]

        cx = h // 2 + 10
        cy = h // 2
        r  = h // 2 - 14
        start = -90.0

        for i, (label, size) in enumerate(slices):
            extent = 360.0 * size / total
            col = colors_pie[i % len(colors_pie)]
            c.create_arc(cx - r, cy - r, cx + r, cy + r,
                         start=start, extent=extent,
                         fill=col, outline=self.BG2, width=1)
            start += extent

        # Légende
        lx = cx + r + 24
        ly = 16
        for i, (label, size) in enumerate(slices):
            col = colors_pie[i % len(colors_pie)]
            c.create_rectangle(lx, ly + i * 18, lx + 10, ly + i * 18 + 10, fill=col, outline="")
            pct = 100.0 * size / total
            c.create_text(lx + 14, ly + i * 18 + 5, anchor="w",
                          text=f"{label}  {format_size(size)}  ({pct:.1f}%)",
                          fill=self.FG, font=("Consolas", 7))

    def _toggle_vt_key_row(self):
        if self.var_virustotal.get():
            self._vt_key_row.pack(fill=tk.X, pady=(4, 4))
        else:
            self._vt_key_row.pack_forget()


    def _toggle_schedule_row(self):
        if self.var_schedule_enabled.get():
            self._sch_dur_row.pack(fill=tk.X, pady=(2, 0))
            self.lbl_schedule_status.pack(anchor="w")
        else:
            # Annuler le timer si actif
            if self._schedule_timer is not None:
                self._schedule_timer.cancel()
                self._schedule_timer = None
                self.btn_schedule.config(text="Activer", fg=self.GREEN)
            self._sch_dur_row.pack_forget()
            self.lbl_schedule_status.pack_forget()

    def _open_vt_help(self):
        """Crée et ouvre un fichier .txt d'aide pour VirusTotal."""
        help_path = os.path.join(os.path.expanduser("~"), "aide_virustotal.txt")
        content = """\
╔══════════════════════════════════════════════════════════════╗
║         AIDE — Clé API VirusTotal                           ║
╚══════════════════════════════════════════════════════════════╝

VirusTotal est un service GRATUIT qui analyse les fichiers avec
plus de 70 antivirus à la fois.

════════════════════════════════════════════════════════════════
 COMMENT OBTENIR VOTRE CLÉ API (gratuit) :
════════════════════════════════════════════════════════════════

1. Ouvrez ce lien dans votre navigateur :
   https://www.virustotal.com/gui/home/upload
2. Créez un compte (email + mot de passe).

3. Une fois connecté, cliquez sur votre nom d'utilisateur
   en haut à droite → "API key".

4. Copiez la clé affichée.

5. Collez-la dans le champ "Clé API" du Scanner.

════════════════════════════════════════════════════════════════
 LIMITES DU COMPTE GRATUIT :
════════════════════════════════════════════════════════════════

  • 4 requêtes par minute
  • 500 requêtes par jour
  → Largement suffisant pour un scan occasionnel.

════════════════════════════════════════════════════════════════
 COMMENT ÇA FONCTIONNE DANS LE SCANNER :
════════════════════════════════════════════════════════════════

Pour chaque fichier détecté comme SUSPECT, le scanner calcule
son empreinte MD5 et l'envoie à VirusTotal.
Si un ou plusieurs antivirus le reconnaissent comme malveillant,
le score de dangerosité passe à 10/10 et la colonne VirusTotal
affiche le nombre de détections (ex: "🦠 5").

Lien officiel VirusTotal :
   https://www.virustotal.com

Lien documentation API :
   https://docs.virustotal.com/reference/overview
"""
        try:
            with open(help_path, "w", encoding="utf-8") as f:
                f.write(content)
            if platform.system() == "Windows":
                os.startfile(help_path)
            elif platform.system() == "Darwin":
                os.system(f"open '{help_path}'")
            else:
                os.system(f"xdg-open '{help_path}'")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir l'aide :\n{e}")

    # ── Scan planifié ──────────────────────────────────────────────────────────

    def _toggle_schedule(self):
        if self._schedule_timer is not None:
            self._schedule_timer.cancel()
            self._schedule_timer = None
            self.btn_schedule.config(text="Activer", fg=self.GREEN)
            self.lbl_schedule_status.config(text="")
            return
        try:
            hours = float(self.var_schedule.get())
        except ValueError:
            messagebox.showerror("Scan planifié", "Entrez un nombre d'heures valide.")
            return
        if hours <= 0:
            messagebox.showinfo("Scan planifié", "Entrez un nombre d'heures > 0.")
            return
        self.btn_schedule.config(text="Désactiver", fg=self.RED)
        self._schedule_next(hours)

    def _schedule_next(self, hours):
        delay_s = int(hours * 3600)
        next_dt = datetime.now()
        from datetime import timedelta
        next_dt += timedelta(seconds=delay_s)
        self.lbl_schedule_status.config(
            text=f"⏱ Prochain scan : {next_dt.strftime('%H:%M:%S')}")
        self._schedule_timer = threading.Timer(delay_s, self._scheduled_scan, args=(hours,))
        self._schedule_timer.daemon = True
        self._schedule_timer.start()

    def _scheduled_scan(self, hours):
        self.root.after(0, self._start_scan)
        self._schedule_next(hours)

    # ── Accordéon ──────────────────────────────────────────────────────────────

    def _toggle_options(self):
        if self._opt_collapsed:
            self._opt_frame.pack(fill=tk.X, after=self._opt_arrow.master)
            self._opt_arrow.config(text="▼")
            self._opt_collapsed = False
        else:
            self._opt_frame.pack_forget()
            self._opt_arrow.config(text="▶")
            self._opt_collapsed = True

    # ── Helpers UI ─────────────────────────────────────────────────────────────

    def _section(self, parent, title):
        tk.Label(parent, text=title, font=("Consolas", 8, "bold"),
                 fg=self.DIMFG, bg=self.BG).pack(anchor="w", pady=(8, 2))

    def _btn(self, parent, text, cmd, color, big=False):
        font = ("Consolas", 10, "bold") if big else ("Consolas", 8)
        return tk.Button(parent, text=text, command=cmd,
                         bg=self.BG3, fg=color, activebackground=self.BG2,
                         activeforeground=color, font=font, borderwidth=0,
                         cursor="hand2", pady=6 if big else 4, relief=tk.FLAT)

    def _card(self, parent, label, value, color):
        frame = tk.Frame(parent, bg=self.BG3, padx=8, pady=6)
        tk.Label(frame, text=label, font=("Consolas", 7), fg=self.DIMFG, bg=self.BG3).pack()
        val_lbl = tk.Label(frame, text=value, font=("Consolas", 11, "bold"), fg=color, bg=self.BG3)
        val_lbl.pack()
        frame._val_label  = val_lbl
        frame._base_color = color
        return frame

    def _card_set(self, card, value, flash=False):
        card._val_label.config(text=value)
        if flash:
            self._flash_card(card)

    def _flash_card(self, card, steps=6, step=0):
        """Flash la card en blanc puis revient à la couleur de base."""
        colors = [self.FG, self.FG, card._base_color, card._base_color,
                  card._base_color, card._base_color]
        if step < len(colors):
            card._val_label.config(fg=colors[step])
            self.root.after(60, lambda: self._flash_card(card, steps, step + 1))

    def _clean_tab(self, notebook):
        """Onglet listant tous les fichiers scannés sans anomalie détectée."""
        frame = tk.Frame(notebook, bg=self.BG)
        notebook.add(frame, text="✅ Fichiers sains")

        # Barre info
        info = tk.Frame(frame, bg=self.BG2, pady=4)
        info.pack(fill=tk.X)
        tk.Label(info, text="Double-clic → ouvre le dossier  |  Clic droit → copier le chemin",
                 font=("Consolas", 7), fg=self.DIMFG, bg=self.BG2).pack(side=tk.LEFT, padx=8)
        self._clean_count_lbl = tk.Label(info, text="0 fichier(s) sain(s)",
                                          font=("Consolas", 7, "bold"), fg=self.GREEN, bg=self.BG2)
        self._clean_count_lbl.pack(side=tk.RIGHT, padx=8)

        # Treeview
        style = ttk.Style()
        style.configure("Clean.Treeview",
                        background=self.BG2, foreground=self.FG,
                        fieldbackground=self.BG2, rowheight=20,
                        font=("Consolas", 8))
        style.configure("Clean.Treeview.Heading",
                        background=self.BG3, foreground=self.GREEN,
                        font=("Consolas", 8, "bold"))
        style.map("Clean.Treeview",
                  background=[("selected", self.GREEN)],
                  foreground=[("selected", "#000")])

        cols = ("chemin", "taille")
        tv_frame = tk.Frame(frame, bg=self.BG)
        tv_frame.pack(fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(tv_frame, orient=tk.VERTICAL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tree = ttk.Treeview(tv_frame, columns=cols, show="headings",
                            style="Clean.Treeview", yscrollcommand=sb.set)
        sb.config(command=tree.yview)
        tree.pack(fill=tk.BOTH, expand=True)

        tree.heading("chemin", text="Chemin du fichier")
        tree.heading("taille", text="Taille")
        tree.column("chemin", width=700, stretch=True)
        tree.column("taille", width=80,  stretch=False, anchor="e")

        tree.bind("<Double-1>", self._on_clean_double_click)
        tree.bind("<Button-3>", self._on_clean_right_click)

        # Scrollbar horizontale
        sbx = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        sbx.pack(fill=tk.X)
        tree.configure(xscrollcommand=sbx.set)

        return frame, tree

    def _on_clean_double_click(self, event):
        item = self.tree_clean.focus()
        if not item:
            return
        vals = self.tree_clean.item(item, "values")
        if vals:
            self._open_parent(vals[0])

    def _on_clean_right_click(self, event):
        item = self.tree_clean.identify_row(event.y)
        if not item:
            return
        self.tree_clean.selection_set(item)
        vals = self.tree_clean.item(item, "values")
        if not vals:
            return
        path = vals[0]
        menu = tk.Menu(self.root, tearoff=0, bg=self.BG3, fg=self.FG,
                       activebackground=self.GREEN, activeforeground="#000",
                       font=("Consolas", 8), borderwidth=0, relief=tk.FLAT)
        menu.add_command(label="📁  Ouvrir le dossier parent",
                         command=lambda: self._open_parent(path))
        menu.add_command(label="📋  Copier le chemin",
                         command=lambda: self._copy_to_clipboard(path))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _log_tab(self, notebook, title):
        frame = tk.Frame(notebook, bg=self.BG)
        notebook.add(frame, text=title)
        txt = scrolledtext.ScrolledText(frame, bg=self.BG2, fg=self.FG,
                                        font=("Consolas", 8), wrap=tk.WORD,
                                        borderwidth=0, insertbackground=self.FG,
                                        state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True)
        self._setup_tags(txt)
        self._bind_right_click(txt)
        return txt

    def _log_tab_with_action(self, notebook, title, btn_text, btn_cmd, btn_color):
        frame = tk.Frame(notebook, bg=self.BG)
        notebook.add(frame, text=title)
        toolbar = tk.Frame(frame, bg=self.BG2, pady=4)
        toolbar.pack(fill=tk.X)
        btn = tk.Button(toolbar, text=btn_text, command=btn_cmd,
                        bg=self.BG3, fg=btn_color, activebackground=self.BG,
                        activeforeground=btn_color, font=("Consolas", 8, "bold"),
                        borderwidth=0, cursor="hand2", pady=3, padx=10, relief=tk.FLAT,
                        state=tk.DISABLED)
        btn.pack(side=tk.LEFT, padx=8)
        txt = scrolledtext.ScrolledText(frame, bg=self.BG2, fg=self.FG,
                                        font=("Consolas", 8), wrap=tk.WORD,
                                        borderwidth=0, insertbackground=self.FG,
                                        state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True)
        self._setup_tags(txt)
        self._bind_right_click(txt)
        return txt, btn

    def _suspects_tab(self, notebook):
        """Onglet Suspects avec Treeview triable, boutons Accéder + Quarantaine."""
        frame = tk.Frame(notebook, bg=self.BG)
        notebook.add(frame, text="🦠 Suspects")

        toolbar = tk.Frame(frame, bg=self.BG2, pady=4)
        toolbar.pack(fill=tk.X)

        btn_open = tk.Button(toolbar, text="📂 Accéder aux chemins",
                             command=self._open_suspect_paths,
                             bg=self.BG3, fg="#ff6d00", activebackground=self.BG,
                             font=("Consolas", 8, "bold"), borderwidth=0,
                             cursor="hand2", pady=3, padx=10, relief=tk.FLAT,
                             state=tk.DISABLED)
        btn_open.pack(side=tk.LEFT, padx=8)

        btn_quar = tk.Button(toolbar, text="🔒 Quarantaine",
                             command=self._quarantine_suspects,
                             bg=self.BG3, fg=self.RED, activebackground=self.BG,
                             font=("Consolas", 8, "bold"), borderwidth=0,
                             cursor="hand2", pady=3, padx=10, relief=tk.FLAT,
                             state=tk.DISABLED)
        btn_quar.pack(side=tk.LEFT, padx=4)

        # Treeview triable
        cols = ("score", "chemin", "raison", "vt")
        style = ttk.Style()
        style.configure("Suspects.Treeview",
                        background=self.BG2, foreground=self.FG,
                        fieldbackground=self.BG2, rowheight=22,
                        font=("Consolas", 8))
        style.configure("Suspects.Treeview.Heading",
                        background=self.BG3, foreground=self.ACCENT,
                        font=("Consolas", 8, "bold"))
        style.map("Suspects.Treeview",
                  background=[("selected", self.ACCENT)],
                  foreground=[("selected", "#000")])

        tv_frame = tk.Frame(frame, bg=self.BG)
        tv_frame.pack(fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(tv_frame, orient=tk.VERTICAL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_suspects = ttk.Treeview(tv_frame, columns=cols, show="headings",
                                          style="Suspects.Treeview",
                                          yscrollcommand=sb.set)
        sb.config(command=self.tree_suspects.yview)
        self.tree_suspects.pack(fill=tk.BOTH, expand=True)

        self.tree_suspects.heading("score",  text="⚠ Score",
                                   command=lambda: self._sort_tree(self.tree_suspects, "score", False))
        self.tree_suspects.heading("chemin", text="Chemin",
                                   command=lambda: self._sort_tree(self.tree_suspects, "chemin", False))
        self.tree_suspects.heading("raison", text="Raison",
                                   command=lambda: self._sort_tree(self.tree_suspects, "raison", False))
        self.tree_suspects.heading("vt",     text="VirusTotal",
                                   command=lambda: self._sort_tree(self.tree_suspects, "vt", False))
        self.tree_suspects.column("score",  width=70,  anchor="center")
        self.tree_suspects.column("chemin", width=400, anchor="w")
        self.tree_suspects.column("raison", width=260, anchor="w")
        self.tree_suspects.column("vt",     width=100, anchor="center")

        # Couleurs par score
        for score in range(1, 11):
            if score >= 8:
                fg = self.RED
            elif score >= 5:
                fg = "#ff6d00"
            else:
                fg = self.YELLOW
            self.tree_suspects.tag_configure(f"score_{score}", foreground=fg)

        # Miniature image au survol
        self._thumb_tip = None
        self._thumb_img = None
        self.tree_suspects.bind("<Motion>",  self._on_tree_motion)
        self.tree_suspects.bind("<Leave>",   self._hide_thumb)
        self.tree_suspects.bind("<Double-1>", self._on_suspect_double_click)
        self.tree_suspects.bind("<Button-3>", self._on_suspect_right_click)

        return frame, btn_open, btn_quar

    def _sort_tree(self, tree, col, reverse):
        data = [(tree.set(k, col), k) for k in tree.get_children("")]
        try:
            data.sort(key=lambda x: float(x[0]) if x[0].replace(".", "").isdigit() else x[0].lower(),
                      reverse=reverse)
        except Exception:
            data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for i, (_, k) in enumerate(data):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    def _filter_suspects(self):
        """Filtre l'onglet Suspects selon la barre de recherche."""
        term = self.var_search.get().lower()
        for item in self.tree_suspects.get_children():
            self.tree_suspects.delete(item)
        for path, reason, score, vt_det in self._suspects_data:
            if term and term not in path.lower() and term not in reason.lower():
                continue
            vt_txt = f"🦠 {vt_det}" if vt_det > 0 else "—"
            score_tag = f"score_{min(score, 10)}"
            self.tree_suspects.insert("", tk.END, values=(score, path, reason, vt_txt),
                                      tags=(score_tag,))

    def _on_tree_motion(self, event):
        """Affiche miniature image au survol dans le Treeview suspects."""
        item = self.tree_suspects.identify_row(event.y)
        if not item:
            self._hide_thumb()
            return
        values = self.tree_suspects.item(item, "values")
        if not values or len(values) < 2:
            return
        path = values[1]
        img_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
        ext = Path(path).suffix.lower() if path else ""
        if ext not in img_exts or not os.path.isfile(path):
            self._hide_thumb()
            return
        if HAS_PIL:
            try:
                img = Image.open(path)
                img.thumbnail((160, 160))
                photo = ImageTk.PhotoImage(img)
                self._show_thumb(event, photo)
            except Exception:
                self._hide_thumb()
        else:
            # Fallback sans PIL : affiche juste le nom
            self._hide_thumb()

    def _show_thumb(self, event, photo):
        self._hide_thumb()
        x = self.tree_suspects.winfo_rootx() + event.x + 16
        y = self.tree_suspects.winfo_rooty() + event.y - 80
        self._thumb_tip = tk.Toplevel(self.root)
        self._thumb_tip.wm_overrideredirect(True)
        self._thumb_tip.wm_geometry(f"+{x}+{y}")
        self._thumb_tip.configure(bg=self.BG3)
        lbl = tk.Label(self._thumb_tip, image=photo, bg=self.BG3, relief=tk.FLAT, bd=1)
        lbl.pack()
        self._thumb_img = photo  # keep reference

    def _hide_thumb(self, event=None):
        if self._thumb_tip:
            self._thumb_tip.destroy()
            self._thumb_tip = None

    def _on_suspect_double_click(self, event):
        item = self.tree_suspects.focus()
        if not item:
            return
        vals = self.tree_suspects.item(item, "values")
        if vals and len(vals) >= 2:
            path = vals[1]
            if os.path.exists(path):
                # Ouvre le dossier PARENT — ne jamais exécuter un fichier suspect
                self._open_parent(path)

    def _on_suspect_right_click(self, event):
        """Menu clic droit sur un fichier suspect dans le Treeview."""
        # Sélectionner la ligne sous le curseur
        item = self.tree_suspects.identify_row(event.y)
        if not item:
            return
        self.tree_suspects.selection_set(item)
        self.tree_suspects.focus(item)

        vals = self.tree_suspects.item(item, "values")
        if not vals or len(vals) < 2:
            return
        path = vals[1]

        menu = tk.Menu(self.root, tearoff=0, bg=self.BG3, fg=self.FG,
                       activebackground=self.ACCENT, activeforeground="#000",
                       font=("Consolas", 8), borderwidth=0, relief=tk.FLAT)

        if os.path.exists(path):
            menu.add_command(
                label="📁  Ouvrir le dossier parent",
                command=lambda: self._open_parent(path))
            menu.add_command(
                label="📋  Copier le chemin",
                command=lambda: self._copy_to_clipboard(path))
            menu.add_separator()
            menu.add_command(
                label="🗑  Déplacer vers la corbeille",
                command=lambda: self._trash_suspect(item, path))
        else:
            menu.add_command(label="⚠  Fichier introuvable", state=tk.DISABLED)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _trash_suspect(self, item, path):
        """Demande confirmation puis envoie le fichier suspect à la corbeille (UAC si besoin)."""
        filename = os.path.basename(path)
        ok = messagebox.askyesno(
            "🗑  Déplacer vers la corbeille",
            f"Voulez-vous déplacer ce fichier vers la corbeille ?\n\n"
            f"  {filename}\n\n"
            f"  {path}\n\n"
            "Le fichier pourra être restauré depuis la corbeille si besoin.",
            icon="warning")
        if not ok:
            return

        try:
            if platform.system() == "Windows":
                # Commande PowerShell Shell.Application → corbeille Windows native
                ps = (
                    f'$shell = New-Object -ComObject Shell.Application; '
                    f'$item = $shell.Namespace(0).ParseName("{path}"); '
                    f'if ($item) {{ $item.InvokeVerb("delete") }} '
                    f'else {{ throw "Fichier introuvable : {path}" }}'
                )
                # Essai sans admin d'abord
                import subprocess
                ret = subprocess.run(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                    capture_output=True)
                if ret.returncode != 0:
                    # Échec → relancer avec UAC (vraie fenêtre Windows Oui/Non)
                    ok2 = messagebox.askyesno(
                        "🔒 Droits insuffisants",
                        f"Le fichier n'a pas pu être déplacé vers la corbeille\n"
                        f"(droits insuffisants).\n\n"
                        f"  {filename}\n\n"
                        "Relancer en tant qu'Administrateur ?\n"
                        "(La fenêtre UAC Windows va s'ouvrir)",
                        icon="warning")
                    if not ok2:
                        return
                    success, err = elevate_and_run_ps(ps)
                    if not success:
                        raise OSError(err or "Opération annulée ou refusée.")
                    # Avec UAC + ShellExecute on ne peut pas attendre la fin,
                    # on retire quand même la ligne (le fichier sera en corbeille)
            else:
                # Linux / macOS : déplacer dans ~/.Trash
                trash_dir = os.path.join(os.path.expanduser("~"), ".Trash")
                os.makedirs(trash_dir, exist_ok=True)
                dest = os.path.join(trash_dir, filename)
                n = 1
                while os.path.exists(dest):
                    name_p, ext_p = os.path.splitext(filename)
                    dest = os.path.join(trash_dir, f"{name_p}_{n}{ext_p}")
                    n += 1
                shutil.move(path, dest)

            # Retirer la ligne du Treeview
            self.tree_suspects.delete(item)
            # Retirer des données internes
            self._suspects_data = [(p, r, s, v) for p, r, s, v in self._suspects_data if p != path]
            self._log(self.log_all, f"🗑  Mis à la corbeille : {path}", "yellow")

        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de déplacer vers la corbeille :\n{e}")



    def _setup_tags(self, txt):
        txt.tag_config("red",    foreground=self.RED)
        txt.tag_config("green",  foreground=self.GREEN)
        txt.tag_config("yellow", foreground=self.YELLOW)
        txt.tag_config("purple", foreground=self.PURPLE)
        txt.tag_config("cyan",   foreground=self.ACCENT)
        txt.tag_config("dim",    foreground=self.DIMFG)
        txt.tag_config("orange",  foreground=self.ORANGE)
        txt.tag_config("suspect", foreground="#ff6d00")
        txt.tag_config("bold",   font=("Consolas", 8, "bold"))

    def _style_notebook(self, nb):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",     background=self.BG,  borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab", background=self.BG3, foreground=self.DIMFG,
                        font=("Consolas", 8), padding=[8, 4],
                        focuscolor=self.BG3, bordercolor=self.BG)
        style.map("TNotebook.Tab",
                  background=[("selected", self.TAB_SEL), ("active", self.BG2)],
                  foreground=[("selected", self.FG),      ("active", self.FG)],
                  focuscolor=[("selected", self.TAB_SEL)])

    # ── Clic droit sur les logs ────────────────────────────────────────────────

    def _bind_right_click(self, txt):
        txt.bind("<Button-3>", lambda e, w=txt: self._show_context_menu(e, w))

    def _show_context_menu(self, event, widget):
        # Récupérer la ligne cliquée
        idx   = widget.index(f"@{event.x},{event.y}")
        line  = int(str(idx).split(".")[0])
        # Chercher un chemin dans les 3 lignes autour
        path  = None
        for dl in range(-2, 3):
            ln = line + dl
            if ln < 1:
                continue
            try:
                content = widget.get(f"{ln}.0", f"{ln}.end").strip()
                # Détecter chemin Windows ou Unix
                if (len(content) > 3 and
                    (content[1:3] in (":\\", ":/") or content.startswith("/"))):
                    path = content.lstrip("▶✓✗ ")
                    break
            except Exception:
                pass

        menu = tk.Menu(self.root, tearoff=0, bg=self.BG3, fg=self.FG,
                       activebackground=self.ACCENT, activeforeground="#000",
                       font=("Consolas", 8), borderwidth=0, relief=tk.FLAT)

        if path and os.path.exists(path):
            menu.add_command(label="📂  Ouvrir le fichier",
                             command=lambda: self._open_path(path))
            menu.add_command(label="📁  Ouvrir le dossier parent",
                             command=lambda: self._open_parent(path))
            menu.add_command(label="📋  Copier le chemin",
                             command=lambda: self._copy_to_clipboard(path))
            menu.add_separator()
        menu.add_command(label="📋  Tout copier",
                         command=lambda: self._copy_to_clipboard(
                             widget.get("1.0", tk.END)))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _open_path(self, path):
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _open_parent(self, path):
        parent = os.path.dirname(path)
        self._open_path(parent)

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text.strip())

    # ── RAM ────────────────────────────────────────────────────────────────────

    def _on_ram_change(self):
        pct = self.var_ram.get()
        self.cfg["ram_pct"] = pct
        if pct == 90:
            ok = messagebox.askyesno(
                "Confirmation — 90% RAM",
                "⚠️  Êtes-vous sûr de vouloir allouer 90% de votre RAM ?\n\n"
                "Cela peut rendre votre système très lent pendant le scan\n"
                "et bloquer d'autres applications.",
                icon="warning")
            if not ok:
                self.var_ram.set(25)
                self.lbl_ram_info.config(text="")
                return
            self.lbl_ram_info.config(text="⚠ 90% — risque de ralentissement système !")
        elif pct >= 50:
            self.lbl_ram_info.config(text=f"ℹ {pct}% de la RAM alloués au scan.")
        else:
            self.lbl_ram_info.config(text="")

    # ── Dossiers ───────────────────────────────────────────────────────────────

    def _set_default_roots(self):
        """Charge les derniers dossiers scannés depuis la config, sinon met les disques/racine."""
        saved = self.cfg.get("last_scan_roots", [])
        # Garder uniquement les chemins qui existent encore
        valid = [r for r in saved if os.path.isdir(r)]
        if valid:
            for r in valid:
                self.roots_list.insert(tk.END, r)
        else:
            # Aucun précédent → valeurs par défaut
            if platform.system() == "Windows":
                import string
                drives = [f"{l}:\\" for l in string.ascii_uppercase if os.path.exists(f"{l}:\\")]
                roots = drives if drives else ["C:\\"]
            else:
                roots = ["/"]
            for r in roots:
                self.roots_list.insert(tk.END, r)

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Choisir un dossier à scanner")
        if folder:
            self.roots_list.insert(tk.END, folder)

    def _remove_folder(self):
        for i in reversed(self.roots_list.curselection()):
            self.roots_list.delete(i)

    # ── Scan ───────────────────────────────────────────────────────────────────

    def _start_scan(self):
        roots = list(self.roots_list.get(0, tk.END))
        if not roots:
            messagebox.showwarning("Aucun dossier", "Ajoutez au moins un dossier à scanner.")
            return
        valid = [r for r in roots if os.path.isdir(r)]
        if not valid:
            messagebox.showerror("Dossiers invalides", "Aucun des dossiers n'est accessible.")
            return
        self.scan_roots = valid
        self.stop_event.clear()
        # Vérification clé API VirusTotal si activé
        if self.var_virustotal.get() and not self.vt_key_var.get().strip():
            messagebox.showwarning(
                "🦠 VirusTotal — Clé API manquante",
                "Vous avez activé la vérification VirusTotal\n"
                "mais la clé API est vide.\n\n"
                "Merci de remplir la clé API avant le lancement.\n\n"
                "💡 Cliquez sur « ? Aide » pour savoir comment en obtenir une gratuitement.")
            return

        self._clear_logs()
        self.results = {}
        self.report_path = None
        self._suspects_list = []
        self._suspects_data  = []
        self.results_dupes_count = 0
        self._dupes_pairs = []
        self._clean_file_count = 0
        for row in self.tree_clean.get_children():
            self.tree_clean.delete(row)
        self._clean_count_lbl.config(text="0 fichier(s) sain(s)")
        self._speed_history = []
        self._ext_stats = defaultdict(lambda: {"count": 0, "size": 0})
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_report.config(state=tk.DISABLED)
        self.btn_export_csv.config(state=tk.DISABLED)
        self.btn_del_dupes.config(state=tk.DISABLED)
        self.btn_open_suspects.config(state=tk.DISABLED)
        self.btn_quarantine.config(state=tk.DISABLED)
        for item in self.tree_suspects.get_children():
            self.tree_suspects.delete(item)
        self._set_status("Comptage en cours…", self.ACCENT)
        self._terminal_write_header(valid)
        self._count_start = time.time()
        # Sauvegarder les options
        self.cfg.update({
            "var_corruption":     self.var_corruption.get(),
            "var_duplicates":     self.var_duplicates.get(),
            "var_copy_corrupted": self.var_copy_corrupted.get(),
            "var_delete_dupes":   self.var_delete_dupes.get(),
            "var_save_report":    self.var_save_report.get(),
            "sound_enabled":      self.var_sound.get(),
            "var_virustotal":     self.var_virustotal.get(),
            "var_quarantine":     self.var_quarantine.get(),
            "var_detect_encrypted": self.var_detect_encrypted.get(),
            "var_schedule_enabled": self.var_schedule_enabled.get(),
            "virustotal_api_key": self.vt_key_var.get(),
            "schedule_hours":     self.var_schedule.get(),
            "var_strict_dupes":   self.var_strict_dupes.get(),
        })
        save_config(self.cfg)
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.stop_event.set()
        self._set_status("Arrêt demandé…", self.YELLOW)

    def _get_ram_limit_bytes(self):
        if HAS_PSUTIL:
            total_ram = psutil.virtual_memory().total
        else:
            total_ram = 4 * 1024 ** 3
        return int(total_ram * self.var_ram.get() / 100)

    def _scan_worker(self):
        q                = self.msg_queue
        roots            = self.scan_roots
        check_corruption = self.var_corruption.get()
        find_duplicates  = self.var_duplicates.get()
        strict_dupes     = self.var_strict_dupes.get()
        detect_encrypted = self.var_detect_encrypted.get()
        use_virustotal   = self.var_virustotal.get()
        vt_api_key       = self.vt_key_var.get().strip()
        ram_limit        = self._get_ram_limit_bytes()

        def send(type_, **kw):
            q.put({"type": type_, **kw})

        # Comptage
        send("status", text="Comptage des fichiers…")
        total = 0
        _frame = 0
        for root in roots:
            for _, _, files in os.walk(root, followlinks=False):
                total += len(files)
                _frame += 1
                if _frame % 40 == 0:
                    send("counting", count=total)
                if self.stop_event.is_set():
                    send("stopped"); return
        send("count_done", total=total)

        # Scan
        name_index = {}  # (fname_lower, size, hash_partiel) → premier chemin trouvé
        corrupted  = []
        suspects   = []
        errors     = []
        stats = {"total_size": 0, "corrupted": 0,
                 "suspects": 0, "duplicates": 0, "encrypted": 0, "errors": 0, "scanned": 0}

        start_time     = time.time()
        last_refresh   = time.time()
        scanned        = 0
        REFRESH        = 0.12
        last_ram_check = time.time()

        for root in roots:
            for dirpath, dirs, filenames in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not d.startswith(".") or root == dirpath]
                for filename in filenames:
                    if self.stop_event.is_set():
                        send("stopped"); return

                    filepath = os.path.join(dirpath, filename)
                    scanned += 1
                    stats["scanned"] = scanned
                    ext = Path(filepath).suffix.lower()

                    try:
                        st = os.stat(filepath, follow_symlinks=False)
                        if stat.S_ISLNK(st.st_mode):
                            continue
                        size = st.st_size
                        stats["total_size"] += size
                        send("ext_stat", ext=ext, size=size)

                        # Détecter si fichier système Windows
                        is_sys = is_windows_system_file(filepath)

                        # ── ÉTAPE 1 : score de suspicion de base ─────────────────
                        susp_flag, susp_reason = is_file_suspicious(filepath, size)
                        base_score = compute_danger_score(susp_reason) if susp_flag else 0

                        # Fichier système → score de base plafonné à 3
                        if is_sys:
                            base_score = min(base_score, 3)

                        # ── ÉTAPE 2 : si score >= 5 → analyse approfondie ────────
                        if base_score >= 5:
                            vt_detections = 0
                            vt_score_bonus = 0

                            # VT : hash MD5 + interrogation API
                            if use_virustotal and vt_api_key:
                                try:
                                    h = hashlib.md5()
                                    with open(filepath, "rb") as f:
                                        for chunk_data in iter(lambda: f.read(65536), b""):
                                            h.update(chunk_data)
                                    md5 = h.hexdigest()
                                    is_mal, detections, total_vt, permalink = \
                                        check_virustotal(md5, vt_api_key)
                                    vt_detections = detections
                                    if is_mal:
                                        vt_score_bonus = 10
                                        susp_reason += f" | VT: {detections}/{total_vt} détections"
                                except Exception:
                                    pass

                            # Analyse chiffrement approfondie (entropie)
                            enc_bonus = 0
                            if detect_encrypted and not is_sys:
                                enc_flag, enc_reason = is_file_encrypted_suspect(filepath, size)
                                if enc_flag:
                                    enc_bonus = 3  # +3 pts si chiffré en plus d'être suspect
                                    susp_reason += f" | chiffré: {enc_reason}"
                                    stats["encrypted"] += 1
                                    send("encrypted", path=filepath, reason=enc_reason)

                            score = max(base_score + enc_bonus, vt_score_bonus)

                            # Fichier système : seuil relevé à 7 même avec bonus
                            if is_sys and score < 7:
                                pass
                            else:
                                suspects.append((filepath, susp_reason))
                                stats["suspects"] += 1
                                send("suspect", path=filepath, reason=susp_reason,
                                     score=score, vt=vt_detections)

                            # Corruption uniquement si déjà suspect (score >= 5)
                            if check_corruption and not is_sys:
                                flag, reason = is_file_corrupted(filepath, size)
                                if flag and not reason.startswith("indispo:"):
                                    corrupted.append((filepath, reason))
                                    stats["corrupted"] += 1
                                    send("corrupted", path=filepath, reason=reason)

                        # ── ÉTAPE 3 : chiffrement seul sur fichiers non-suspects ──
                        # Un fichier pas suspect mais avec entropie TRÈS élevée (>7.8)
                        # et une extension vraiment inhabituelle peut quand même être signalé
                        elif detect_encrypted and not is_sys:
                            enc_flag, enc_reason = is_file_encrypted_suspect(filepath, size)
                            if enc_flag:
                                # Vérifier que l'extension n'est pas dans les formats compressés normaux
                                safe_exts = {
                                    ".zip", ".gz", ".7z", ".rar", ".tar", ".bz2", ".xz",
                                    ".mp3", ".mp4", ".avi", ".mkv", ".jpg", ".jpeg", ".png",
                                    ".exe", ".dll", ".msix", ".cab", ".pak", ".sig", ".dat",
                                    ".pdf", ".docx", ".xlsx", ".db", ".sqlite",
                                }
                                # Extraire l'entropie du message pour vérifier si > 7.8
                                import re as _re
                                m = _re.search(r"\((\d+\.\d+)/8", enc_reason)
                                entropy_val = float(m.group(1)) if m else 0.0
                                if ext not in safe_exts and entropy_val >= 7.8:
                                    stats["encrypted"] += 1
                                    send("encrypted", path=filepath, reason=enc_reason)

                        # Doublons = même nom + même taille + même hash partiel
                        if find_duplicates and not is_sys and size > 0:
                            fname = os.path.basename(filepath).lower()
                            try:
                                h = hashlib.md5()
                                with open(filepath, "rb") as f:
                                    h.update(f.read(65536))
                                    if size > 131072:
                                        f.seek(-65536, 2)
                                        h.update(f.read(65536))
                                h.update(str(size).encode())
                                content_key = (fname, size, h.hexdigest())

                                if strict_dupes:
                                    # Mode strict : on regroupe par contenu,
                                    # puis on ne signale doublon QUE si le chemin
                                    # relatif (depuis la racine de scan) est identique.
                                    # Cela évite les faux doublons entre dossiers frères
                                    # (ex: profiles/Anycubic/ vs profiles/Elegoo/).
                                    if content_key not in name_index:
                                        name_index[content_key] = []
                                    # Calcul du chemin relatif depuis la racine de scan la plus proche
                                    rel_path = None
                                    for scan_root in roots:
                                        try:
                                            rel_path = os.path.relpath(filepath, scan_root)
                                            break
                                        except ValueError:
                                            pass
                                    # On stocke (chemin_absolu, chemin_relatif) pour chaque contenu
                                    existing = name_index[content_key]
                                    matched = False
                                    for orig_abs, orig_rel in existing:
                                        if rel_path and orig_rel and rel_path == orig_rel:
                                            # Même chemin relatif = vrai doublon
                                            send("duplicate", original=orig_abs, duplicate=filepath)
                                            matched = True
                                            break
                                    if not matched:
                                        existing.append((filepath, rel_path))
                                else:
                                    # Mode original : tout contenu identique = doublon
                                    if content_key in name_index:
                                        original = name_index[content_key]
                                        send("duplicate", original=original, duplicate=filepath)
                                    else:
                                        name_index[content_key] = filepath
                            except (PermissionError, OSError):
                                pass

                        # Fichier sain : aucune anomalie détectée → onglet Fichiers sains
                        if base_score < 5:
                            send("clean", path=filepath, size=size)

                    except PermissionError:
                        errors.append((filepath, "Permission refusée"))
                        stats["errors"] += 1
                        send("error", path=filepath, err="Permission refusée")
                    except OSError as e:
                        errors.append((filepath, str(e)[:60]))
                        stats["errors"] += 1
                        send("error", path=filepath, err=str(e)[:60])
                    except Exception as e:
                        errors.append((filepath, str(e)[:60]))
                        stats["errors"] += 1
                        send("error", path=filepath, err=str(e)[:60])

                    now = time.time()
                    if now - last_refresh >= REFRESH:
                        elapsed = now - start_time
                        speed   = scanned / elapsed if elapsed > 0 else 0
                        remaining = (total - scanned) / speed if speed > 0 and total > 0 else 0
                        stats["duplicates"] = getattr(self, "results_dupes_count", 0)
                        send("progress", scanned=scanned, total=total,
                             current_file=filepath, stats=dict(stats),
                             elapsed=elapsed, speed=speed, eta=remaining)
                        last_refresh = now

        elapsed = time.time() - start_time
        send("done", corrupted=corrupted, suspects=suspects,
             errors=errors, stats=stats, elapsed=elapsed)

    # ── Polling ────────────────────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                self._handle_msg(self.msg_queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _handle_msg(self, msg):
        t = msg["type"]
        if t == "status":
            self._set_status(msg["text"], self.ACCENT)
        elif t == "counting":
            self._terminal_update_bounce(msg["count"])
        elif t == "count_done":
            self.total_files = msg["total"]
            self._terminal_replace_line(self.log_all, self._bar_line,
                f"  {make_progress_bar(0)}  0%   0/{self.total_files:,}   ETA : --   Écoulé : 0m00s   0 f/s", "cyan")
            self._log(self.log_all, f"  ✓ Comptage terminé — {self.total_files:,} fichiers", "green")
            self._set_status("Scan en cours…", self.ACCENT)
        elif t == "ext_stat":
            ext  = msg["ext"]
            size = msg["size"]
            self._ext_stats[ext]["count"] += 1
            self._ext_stats[ext]["size"]  += size
        elif t == "progress":
            s, total = msg["scanned"], msg["total"]
            stats = msg["stats"]
            pct   = (s / max(total, 1)) * 100
            spd   = msg["speed"]
            self._speed_history.append(spd)
            self._terminal_update_progress(pct, msg["eta"], spd, s, total, msg.get("elapsed", 0))
            self._terminal_update_file(msg["current_file"])
            prev_scanned = int(self.card_scanned._val_label.cget("text").replace(",", "") or "0")
            self._card_set(self.card_scanned,   f"{s:,}",                  flash=(s > prev_scanned + 500))
            self._card_set(self.card_size,       format_size(stats["total_size"]))
            self._card_set(self.card_corrupted,  str(stats["corrupted"]),  flash=(stats["corrupted"] > 0))
            self._card_set(self.card_suspects,   str(stats.get("suspects", 0)), flash=(stats.get("suspects", 0) > 0))
            self._card_set(self.card_dupes,      str(stats["duplicates"]), flash=(stats["duplicates"] > 0))
            self._card_set(self.card_errors,     str(stats.get("encrypted", 0)), flash=(stats.get("encrypted", 0) > 0))
            self._card_set(self.card_speed,      f"{spd:.0f} f/s")
            if len(self._speed_history) % 5 == 0:
                self._update_speed_canvas()
        elif t == "corrupted":
            self._log(self.log_corrupted, f"[{msg['reason']}]\n  {msg['path']}", "red")
        elif t == "encrypted":
            self._log(self.log_errors,
                      f"🔐 [{msg['reason']}]\n  {msg['path']}", "orange")
        elif t == "suspect":
            score   = msg.get("score", 1)
            vt_det  = msg.get("vt", 0)
            path    = msg["path"]
            reason  = msg["reason"]
            self._suspects_list.append(path)
            self._suspects_data.append((path, reason, score, vt_det))
            vt_txt   = f"🦠 {vt_det}" if vt_det > 0 else "—"
            score_tag = f"score_{min(score, 10)}"
            term = self.var_search.get().lower()
            if not term or term in path.lower() or term in reason.lower():
                self.tree_suspects.insert("", tk.END,
                    values=(score, path, reason, vt_txt), tags=(score_tag,))
        elif t == "clean":
            path = msg["path"]
            size = msg["size"]
            self.tree_clean.insert("", tk.END, values=(path, format_size(size)))
            self._clean_file_count = getattr(self, "_clean_file_count", 0) + 1
            self._clean_count_lbl.config(text=f"{self._clean_file_count:,} fichier(s) sain(s)")
        elif t == "duplicate":
            self._log(self.log_dupes,
                      f"  ✓ ORIGINAL  {msg['original']}\n  ✗ DOUBLON   {msg['duplicate']}", "purple")
            if not hasattr(self, "_dupes_pairs"):
                self._dupes_pairs = []
            self._dupes_pairs.append((msg["original"], msg["duplicate"]))
            self.results_dupes_count = getattr(self, "results_dupes_count", 0) + 1
            self._card_set(self.card_dupes, str(self.results_dupes_count), flash=True)
        elif t == "error":
            self._log(self.log_errors, f"[{msg['err']}]\n  {msg['path']}", "yellow")
        elif t == "stopped":
            self._scan_finished(stopped=True)
        elif t == "done":
            self.results = msg
            self._scan_finished()

    def _scan_finished(self, stopped=False):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        if stopped:
            self._terminal_freeze_bars()
            self._set_status("⚠ Scan interrompu.", self.YELLOW)
            self._log(self.log_all, "\n⚠  Scan interrompu par l'utilisateur.", "yellow")
            self.btn_quarantine.config(state=tk.DISABLED)
            return
        r      = self.results
        stats  = r["stats"]
        elapsed = r["elapsed"]
        dupes_count = getattr(self, "results_dupes_count", stats.get("duplicates", 0))
        self._terminal_freeze_bars()
        self._card_set(self.card_scanned,   f"{stats['scanned']:,}",        flash=True)
        self._card_set(self.card_size,       format_size(stats["total_size"]))
        self._card_set(self.card_corrupted,  str(stats["corrupted"]),        flash=stats["corrupted"] > 0)
        self._card_set(self.card_suspects,   str(stats.get("suspects", 0)),  flash=stats.get("suspects", 0) > 0)
        self._card_set(self.card_dupes,      str(dupes_count),               flash=dupes_count > 0)
        self._card_set(self.card_errors,     str(stats.get("encrypted", 0)), flash=stats.get("encrypted", 0) > 0)
        self._log(self.log_all, f"\n{'═'*60}", "cyan")
        self._log(self.log_all, f"  SCAN TERMINÉ — {format_duration(elapsed)}", "cyan")
        self._log(self.log_all, f"  Fichiers       : {stats['scanned']:,}", "green")
        self._log(self.log_all, f"  Taille         : {format_size(stats['total_size'])}", "green")
        self._log(self.log_all, f"  Corrompus      : {stats['corrupted']}", "red")
        self._log(self.log_all, f"  Chiffrés       : {stats.get('encrypted', 0)}", "orange")
        self._log(self.log_all, f"  Suspects       : {stats.get('suspects', 0)}", "orange")
        self._log(self.log_all, f"  Doublons       : {dupes_count}", "purple")


        # Mettre à jour le canvas stats final
        self._update_stats_canvas()
        self._update_pie_canvas()
        self._update_speed_canvas()

        if self.var_copy_corrupted.get() and r["corrupted"]:
            self._copy_corrupted(r["corrupted"])
        dupes_pairs = getattr(self, "_dupes_pairs", [])
        if self.var_delete_dupes.get() and dupes_pairs:
            if messagebox.askyesno("Supprimer les doublons",
                                   f"{len(dupes_pairs)} doublons trouvés.\n"
                                   "Voulez-vous les supprimer (l'original est conservé) ?"):
                self._delete_dupes_with_progress_pairs(dupes_pairs)
        if self.var_save_report.get():
            self.report_path = self._save_report(r)
            if self.report_path:
                self._log(self.log_all, f"\n✓ Rapport : {self.report_path}", "green")
                self.btn_report.config(state=tk.NORMAL)
        if dupes_pairs:
            self.btn_del_dupes.config(state=tk.NORMAL)
        if r.get("suspects"):
            self.btn_open_suspects.config(state=tk.NORMAL)
            self.btn_quarantine.config(state=tk.NORMAL)

        self.btn_export_csv.config(state=tk.NORMAL)

        # Son de fin
        if self.var_sound.get():
            play_done_sound()

        # Notification
        self._set_status(
            f"✓ Scan terminé — {stats['scanned']:,} fichiers en {format_duration(elapsed)}",
            self.GREEN)

        # Historique
        save_history({
            "date":       datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "roots":      self.scan_roots,
            "scanned":    stats["scanned"],
            "size":       stats["total_size"],
            "corrupted":  stats["corrupted"],
            "suspects":   stats.get("suspects", 0),
            "duplicates": stats["duplicates"],
            "errors":     stats["errors"],
            "elapsed":    elapsed,
            "report":     self.report_path or "",
        })

    # ── Terminal ───────────────────────────────────────────────────────────────

    def _terminal_write_header(self, roots):
        w = self.log_all
        w.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        w.insert(tk.END, f"=== SCAN DÉMARRÉ {ts} ===\n", "cyan")
        for r in roots:
            w.insert(tk.END, f"  ▶ {r}\n", "dim")
        w.insert(tk.END, "\n")
        w.insert(tk.END, "  Comptage...  [" + " " * 50 + "]  0 fichiers\n", "cyan")
        self._bar_line = w.index(f"{int(str(w.index(tk.END)).split('.')[0]) - 1}.0")
        w.insert(tk.END, "\n")
        self._file_line = w.index(f"{int(str(w.index(tk.END)).split('.')[0]) - 1}.0")
        w.see(tk.END)
        w.config(state=tk.DISABLED)

    def _terminal_update_bounce(self, count):
        elapsed = time.time() - self._count_start if hasattr(self, "_count_start") else 0
        m, s = divmod(int(elapsed), 60)
        elapsed_str = f"{m}m{s:02d}s"
        bar_txt, self._bounce_pos, self._bounce_dir = make_bounce_bar(self._bounce_pos, self._bounce_dir)
        self._terminal_replace_line(self.log_all, self._bar_line,
                                    f"  Comptage...  {bar_txt}  {count:,} fichiers   Écoulé : {elapsed_str}", "cyan")

    def _terminal_update_progress(self, pct, eta, speed, scanned, total, elapsed=0):
        bar_txt = make_progress_bar(pct)
        m_eta, s_eta = divmod(int(max(eta, 0)), 60)
        m_el,  s_el  = divmod(int(elapsed), 60)
        eta_str     = f"{m_eta}m{s_eta:02d}s"
        elapsed_str = f"{m_el}m{s_el:02d}s"
        line = (f"  {bar_txt}  {pct:.0f}%"
                f"   {scanned:,}/{total:,}"
                f"   ETA : {eta_str}"
                f"   Écoulé : {elapsed_str}"
                f"   {speed:,.0f} f/s")
        self._terminal_replace_line(self.log_all, self._bar_line, line, "cyan")

    def _terminal_update_file(self, filepath):
        if len(filepath) > 80:
            filepath = "…" + filepath[-79:]
        self._terminal_replace_line(self.log_all, self._file_line, f"  ▶ {filepath}", "dim")

    def _terminal_replace_line(self, widget, line_idx, text, tag):
        widget.config(state=tk.NORMAL)
        line_num = int(str(widget.index(line_idx)).split(".")[0])
        widget.delete(f"{line_num}.0", f"{line_num}.end")
        widget.insert(f"{line_num}.0", text, tag)
        widget.config(state=tk.DISABLED)

    def _terminal_freeze_bars(self):
        w = self.log_all
        w.config(state=tk.NORMAL)
        if self._bar_line:
            ln = int(str(w.index(self._bar_line)).split(".")[0])
            w.delete(f"{ln}.0", f"{ln}.end")
            w.insert(f"{ln}.0", "  " + make_progress_bar(100) + "  100%   Terminé !", "green")
        if self._file_line:
            ln = int(str(w.index(self._file_line)).split(".")[0])
            w.delete(f"{ln}.0", f"{ln}.end")
        self._bar_line = self._file_line = None
        w.config(state=tk.DISABLED)

    def _clear_logs(self):
        for w in (self.log_all, self.log_corrupted, self.log_dupes, self.log_errors):
            w.config(state=tk.NORMAL)
            w.delete("1.0", tk.END)
            w.config(state=tk.DISABLED)
        for item in self.tree_suspects.get_children():
            self.tree_suspects.delete(item)
        self._bar_line = self._file_line = None
        self._bounce_pos = 0
        self._bounce_dir = 1

    def _set_status(self, text, color=None):
        self.status_bar.config(text=text, fg=color or self.DIMFG)

    def _log(self, widget, text, tag=None):
        widget.config(state=tk.NORMAL)
        if self._bar_line and widget == self.log_all:
            insert_at = self._bar_line
            widget.insert(insert_at, text + "\n", tag or "")
            self._bar_line = self._line_index_after(widget, insert_at, 1)
            if self._file_line:
                self._file_line = self._line_index_after(widget, self._bar_line, 1)
        else:
            widget.insert(tk.END, text + "\n", tag or "")
            widget.see(tk.END)
        widget.config(state=tk.DISABLED)

    def _line_index_after(self, widget, idx, n):
        line_num = int(str(widget.index(idx)).split(".")[0])
        return f"{line_num + n}.0"

    # ── Post-actions ───────────────────────────────────────────────────────────

    def _copy_corrupted(self, corrupted):
        dest_dir = os.path.join(get_desktop(), "FICHIERS_CORROMPUS")
        os.makedirs(dest_dir, exist_ok=True)
        copied = failed = 0
        for path, _ in corrupted:
            try:
                basename = os.path.basename(path)
                dest = os.path.join(dest_dir, basename)
                n = 1
                while os.path.exists(dest):
                    name, ext = os.path.splitext(basename)
                    dest = os.path.join(dest_dir, f"{name}_{n}{ext}")
                    n += 1
                shutil.copy2(path, dest)
                copied += 1
            except Exception:
                failed += 1
        self._log(self.log_all, f"\n✓ {copied} fichier(s) corrompu(s) copié(s) → {dest_dir}", "yellow")

    def _manual_delete_dupes(self):
        dupes_pairs = getattr(self, "_dupes_pairs", [])
        if not dupes_pairs:
            messagebox.showinfo("Aucun doublon", "Aucun doublon à supprimer.")
            return
        if messagebox.askyesno("Supprimer les doublons",
                               f"{len(dupes_pairs):,} doublon(s) trouvé(s).\n"
                               "Voulez-vous les supprimer ? (l'original de chaque paire est conservé)"):
            self._delete_dupes_with_progress_pairs(dupes_pairs)
            self.btn_del_dupes.config(state=tk.DISABLED)

    def _delete_dupes_with_progress_pairs(self, pairs):
        """Supprime les fichiers doublons (le 2e de chaque paire nom identique)."""
        deleted = 0
        failed  = 0
        for original, duplicate in pairs:
            try:
                if os.path.exists(duplicate):
                    os.remove(duplicate)
                    deleted += 1
            except Exception:
                failed += 1
        self._log(self.log_all,
                  f"\n🗑  {deleted} doublon(s) supprimé(s)"
                  + (f" — {failed} échec(s)" if failed else ""), "purple")


    def _open_suspect_paths(self):
        """Ouvre le dossier parent de chaque fichier suspect dans l'explorateur."""
        suspects = self.results.get("suspects", [])
        if not suspects:
            messagebox.showinfo("Aucun suspect", "Aucun fichier suspect trouvé.")
            return
        paths = [p for p, _ in suspects]
        total = len(paths)
        if total > 15:
            ok = messagebox.askyesno(
                "Ouvrir les chemins",
                f"{total} fichiers suspects détectés.\n"
                f"Cela va ouvrir jusqu'à {min(total, 15)} fenêtres d'explorateur.\n\n"
                "Continuer ?")
            if not ok:
                return
        opened_dirs = set()
        count = 0
        for path in paths:
            parent = os.path.dirname(path)
            if parent not in opened_dirs:
                opened_dirs.add(parent)
                self._open_parent(path)
                count += 1
                if count >= 15:
                    break
        self._log(self.log_all,
                  f"📂 {count} dossier(s) suspect(s) ouverts dans l'explorateur.", "orange")

    def _quarantine_suspects(self):
        """Déplace les fichiers suspects dans QUARANTAINE_SCANNER sur le Bureau."""
        suspects = self.results.get("suspects", [])
        if not suspects:
            messagebox.showinfo("Quarantaine", "Aucun fichier suspect.")
            return
        total = len(suspects)
        dest_dir = os.path.join(get_desktop(), "QUARANTAINE_SCANNER")
        ok = messagebox.askyesno(
            "⚠️  Quarantaine — Confirmation",
            f"{total} fichier(s) suspect(s) vont être DÉPLACÉS.\n\n"
            f"Destination :\n{dest_dir}\n\n"
            "⚠️  Les fichiers disparaissent de leur emplacement d'origine.\n"
            "Cette action est difficile à annuler.\n\nContinuer ?",
            icon="warning")
        if not ok:
            return
        os.makedirs(dest_dir, exist_ok=True)
        moved = 0
        failed_paths = []
        for path, reason in suspects:
            try:
                if not os.path.exists(path):
                    continue
                basename = os.path.basename(path)
                dest = os.path.join(dest_dir, basename)
                n = 1
                while os.path.exists(dest):
                    name_p, ext_p = os.path.splitext(basename)
                    dest = os.path.join(dest_dir, f"{name_p}_{n}{ext_p}")
                    n += 1
                shutil.move(path, dest)
                moved += 1
            except Exception:
                failed_paths.append(path)

        if failed_paths and platform.system() == "Windows":
            # Proposer une relance en admin via UAC pour les fichiers qui ont échoué
            retry = messagebox.askyesno(
                "Droits insuffisants",
                f"{len(failed_paths)} fichier(s) n'ont pas pu être déplacés\n"
                "(droits insuffisants).\n\n"
                "Relancer la quarantaine en tant qu'Administrateur ?",
                icon="warning")
            if retry:
                import ctypes
                # Construire la liste des chemins à déplacer dans un fichier temp
                tmp_list = os.path.join(os.path.expanduser("~"), "_quar_list.txt")
                with open(tmp_list, "w", encoding="utf-8") as f:
                    for p in failed_paths:
                        f.write(p + "\n")
                # Script PowerShell inline qui lit la liste et déplace en admin
                ps_cmd = (
                    f'$dest="{dest_dir}"; '
                    f'Get-Content "{tmp_list}" | ForEach-Object {{ '
                    f'  if (Test-Path $_) {{ Move-Item -Path $_ -Destination $dest -Force }} '
                    f'}}; '
                    f'Remove-Item "{tmp_list}" -Force'
                )
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "powershell.exe",
                    f'-NoProfile -WindowStyle Hidden -Command "{ps_cmd}"',
                    None, 1)
                messagebox.showinfo("Quarantaine Admin",
                    "La fenêtre UAC va s'ouvrir.\n"
                    "Acceptez pour terminer la quarantaine en admin.")

        msg = f"✓ {moved} fichier(s) mis en quarantaine → {dest_dir}"
        if failed_paths:
            msg += f"\n✗ {len(failed_paths)} échec(s)"
        messagebox.showinfo("Quarantaine terminée", msg)
        self._log(self.log_all, f"\n🔒 Quarantaine : {moved} fichier(s) → {dest_dir}", "red")
        self.btn_quarantine.config(state=tk.DISABLED)


        to_delete = []
        for paths in groups.values():
            to_delete.extend(paths[1:])
        total = len(to_delete)
        if total == 0:
            return

        win = tk.Toplevel(self.root)
        win.title("Suppression des doublons")
        win.geometry("540x230")
        win.configure(bg=self.BG)
        win.resizable(False, False)
        win.grab_set()

        tk.Label(win, text="🗑  SUPPRESSION DES DOUBLONS",
                 font=("Consolas", 11, "bold"), fg=self.RED, bg=self.BG).pack(pady=(16, 4))
        lbl_file = tk.Label(win, text="", font=("Consolas", 7), fg=self.DIMFG, bg=self.BG,
                            wraplength=500, anchor="w")
        lbl_file.pack(fill=tk.X, padx=16)

        bar_frame = tk.Frame(win, bg=self.BG)
        bar_frame.pack(fill=tk.X, padx=16, pady=6)
        canvas = tk.Canvas(bar_frame, height=18, bg=self.BG3, highlightthickness=0)
        canvas.pack(fill=tk.X)
        fill_rect = canvas.create_rectangle(0, 0, 0, 18, fill=self.RED, outline="")

        lbl_stats = tk.Label(win, text=f"0 / {total:,}   |   ETA : --   |   0 f/s",
                             font=("Consolas", 8), fg=self.FG, bg=self.BG)
        lbl_stats.pack()
        lbl_freed = tk.Label(win, text="Libéré : 0 o", font=("Consolas", 8), fg=self.GREEN, bg=self.BG)
        lbl_freed.pack(pady=2)

        del_q = queue.Queue()

        def worker():
            deleted = freed = failed = 0
            t0 = time.time()
            for i, dup in enumerate(to_delete):
                try:
                    sz = os.path.getsize(dup)
                    os.remove(dup)
                    deleted += 1
                    freed += sz
                except Exception:
                    failed += 1
                elapsed = time.time() - t0
                speed   = (i + 1) / elapsed if elapsed > 0 else 0
                remaining = (total - i - 1) / speed if speed > 0 else 0
                del_q.put({"i": i+1, "total": total, "speed": speed,
                           "eta": remaining, "freed": freed, "file": dup, "done": False})
            del_q.put({"done": True, "deleted": deleted, "freed": freed, "failed": failed})

        def poll():
            try:
                while True:
                    msg = del_q.get_nowait()
                    if msg["done"]:
                        canvas.coords(fill_rect, 0, 0, canvas.winfo_width(), 18)
                        lbl_stats.config(text=f"{msg['deleted']:,} supprimé(s)  |  {msg['failed']} échec(s)")
                        lbl_freed.config(text=f"Libéré : {format_size(msg['freed'])}")
                        lbl_file.config(text="✓ Suppression terminée !")
                        self._log(self.log_all,
                                  f"✓ {msg['deleted']:,} doublon(s) supprimé(s) — "
                                  f"{format_size(msg['freed'])} libéré(s)", "purple")
                        self._card_set(self.card_dupes, "0")
                        win.after(1800, win.destroy)
                        return
                    pct = msg["i"] / msg["total"]
                    w   = canvas.winfo_width()
                    canvas.coords(fill_rect, 0, 0, int(w * pct), 18)
                    short = msg["file"]
                    if len(short) > 68:
                        short = "…" + short[-67:]
                    lbl_file.config(text=short)
                    lbl_stats.config(
                        text=f"{msg['i']:,} / {msg['total']:,}   |   "
                             f"ETA : {format_duration(msg['eta'])}   |   "
                             f"{msg['speed']:.0f} f/s")
                    lbl_freed.config(text=f"Libéré : {format_size(msg['freed'])}")
            except queue.Empty:
                pass
            win.after(80, poll)

        threading.Thread(target=worker, daemon=True).start()
        win.after(80, poll)

    # ── Export CSV ─────────────────────────────────────────────────────────────

    def _export_csv(self):
        r = self.results
        if not r:
            messagebox.showinfo("Export CSV", "Aucun résultat à exporter.")
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(os.path.expanduser("~"), f"scan_export_{ts}.csv")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["Type", "Chemin", "Raison / Info"])
                for p, reason in r.get("corrupted", []):
                    writer.writerow(["Corrompu", p, reason])
                for p, reason in r.get("suspects", []):
                    writer.writerow(["Suspect (virus/malware)", p, reason])
                for p, err in r.get("errors", []):
                    writer.writerow(["Erreur", p, err])
                for original, duplicate in getattr(self, "_dupes_pairs", []):
                    writer.writerow(["Doublon — original", original, "ORIGINAL"])
                    writer.writerow(["Doublon — copie",   duplicate, "COPIE"])
            messagebox.showinfo("Export CSV", f"Exporté :\n{path}")
            self._log(self.log_all, f"\n✓ Export CSV : {path}", "green")
        except Exception as e:
            messagebox.showerror("Erreur export", str(e))

    # ── Historique ─────────────────────────────────────────────────────────────

    def _show_history(self):
        history = load_history()
        win = tk.Toplevel(self.root)
        win.title("Historique des scans")
        win.geometry("720x460")
        win.configure(bg=self.BG)
        win.grab_set()

        tk.Label(win, text="🕓  HISTORIQUE DES SCANS",
                 font=("Consolas", 11, "bold"), fg=self.ACCENT, bg=self.BG).pack(pady=(14, 4))

        if not history:
            tk.Label(win, text="Aucun scan enregistré.", font=("Consolas", 9),
                     fg=self.DIMFG, bg=self.BG).pack(pady=20)
            return

        frame = tk.Frame(win, bg=self.BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        txt = scrolledtext.ScrolledText(frame, bg=self.BG2, fg=self.FG,
                                        font=("Consolas", 8), wrap=tk.WORD,
                                        borderwidth=0, state=tk.NORMAL)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.tag_config("cyan",   foreground=self.ACCENT)
        txt.tag_config("green",  foreground=self.GREEN)
        txt.tag_config("dim",    foreground=self.DIMFG)
        txt.tag_config("purple", foreground=self.PURPLE)
        txt.tag_config("red",    foreground=self.RED)

        for i, entry in enumerate(history, 1):
            txt.insert(tk.END, f"── #{i}  {entry.get('date','?')} ──────────────────────────────\n", "cyan")
            roots_str = ", ".join(entry.get("roots", []))
            txt.insert(tk.END, f"  Dossiers  : {roots_str}\n", "dim")
            txt.insert(tk.END, f"  Fichiers  : {entry.get('scanned', 0):,}   "
                               f"Taille : {format_size(entry.get('size', 0))}   "
                               f"Durée : {format_duration(entry.get('elapsed', 0))}\n", "green")
            txt.insert(tk.END, f"  Corrompus : {entry.get('corrupted',0)}   "
                               f"Doublons : {entry.get('duplicates',0)}   "
                               f"Erreurs : {entry.get('errors',0)}\n", "purple")
            if entry.get("report"):
                lbl = entry["report"]
                txt.insert(tk.END, f"  Rapport   : {lbl}\n", "dim")
            txt.insert(tk.END, "\n")

        txt.config(state=tk.DISABLED)

        btn_frame = tk.Frame(win, bg=self.BG)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="Effacer l'historique",
                  font=("Consolas", 8), bg=self.BG3, fg=self.RED,
                  activebackground=self.BG2, borderwidth=0, padx=10, pady=4,
                  cursor="hand2", relief=tk.FLAT,
                  command=lambda: self._clear_history(win)).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Fermer",
                  font=("Consolas", 8), bg=self.BG3, fg=self.DIMFG,
                  activebackground=self.BG2, borderwidth=0, padx=10, pady=4,
                  cursor="hand2", relief=tk.FLAT,
                  command=win.destroy).pack(side=tk.LEFT, padx=6)

    def _clear_history(self, win):
        try:
            os.remove(HISTORY_PATH)
        except Exception:
            pass
        win.destroy()
        messagebox.showinfo("Historique", "Historique effacé.")

    # ── Rapport ────────────────────────────────────────────────────────────────

    def _save_report(self, r):
        stats            = r["stats"]
        elapsed          = r["elapsed"]
        corrupted        = r["corrupted"]
        suspects         = r.get("suspects", [])
        dupes_pairs      = getattr(self, "_dupes_pairs", [])
        errors           = r["errors"]
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(os.path.expanduser("~"), f"scan_report_{ts}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"RAPPORT DE SCAN - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Fichiers scannés   : {stats['scanned']:,}\n")
                f.write(f"Taille totale      : {format_size(stats['total_size'])}\n")
                f.write(f"Durée              : {format_duration(elapsed)}\n")
                f.write(f"Fichiers corrompus : {stats['corrupted']:,}\n")
                f.write(f"Fichiers suspects  : {stats.get('suspects', 0):,}\n")
                f.write(f"Doublons           : {len(dupes_pairs):,}\n")
                f.write(f"Erreurs d'accès    : {stats['errors']:,}\n\n")
                if corrupted:
                    f.write("\n" + "─" * 80 + "\n")
                    f.write(f"FICHIERS CORROMPUS ({len(corrupted)})\n")
                    f.write("─" * 80 + "\n")
                    for p, reason in corrupted:
                        f.write(f"[{reason}]\n  {p}\n")
                if suspects:
                    f.write("\n" + "─" * 80 + "\n")
                    f.write(f"FICHIERS SUSPECTS — RISQUE VIRUS/MALWARE ({len(suspects)})\n")
                    f.write("─" * 80 + "\n")
                    for p, reason in suspects:
                        f.write(f"[{reason}]\n  {p}\n")
                if dupes_pairs:
                    f.write("\n" + "─" * 80 + "\n")
                    f.write(f"FICHIERS EN DOUBLE ({len(dupes_pairs)})\n")
                    f.write("─" * 80 + "\n")
                    for original, duplicate in dupes_pairs:
                        f.write(f"  ✓ ORIGINAL : {original}\n  ✗ COPIE    : {duplicate}\n\n")
                if errors:
                    f.write("\n" + "─" * 80 + "\n")
                    f.write(f"ERREURS D'ACCÈS ({len(errors)})\n")
                    f.write("─" * 80 + "\n")
                    for p, err in errors:
                        f.write(f"[{err}]\n  {p}\n")
            return path
        except Exception:
            return None

    def _open_report(self):
        if self.report_path and os.path.exists(self.report_path):
            if platform.system() == "Windows":
                os.startfile(self.report_path)
            elif platform.system() == "Darwin":
                os.system(f"open '{self.report_path}'")
            else:
                os.system(f"xdg-open '{self.report_path}'")


# ─── Élévation admin (UAC Windows) ───────────────────────────────────────────

def is_admin():
    """Retourne True si le processus tourne déjà en administrateur."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # Non-Windows : on considère que c'est OK

def elevate_and_run_ps(ps_cmd):
    """
    Exécute une commande PowerShell en admin via la vraie fenêtre UAC Windows.
    Retourne True si réussi, False si refusé ou erreur.
    """
    import ctypes
    import subprocess
    if is_admin():
        # Déjà admin : exécuter directement
        ret = subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
            capture_output=True)
        return ret.returncode == 0, ret.stderr.decode(errors="replace").strip()
    else:
        # Pas admin : déclencher UAC via ShellExecute "runas"
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "powershell.exe",
            f'-NoProfile -WindowStyle Hidden -Command "{ps_cmd}"',
            None, 1)
        # ret > 32 = succès (lancé), on ne peut pas savoir si ça a vraiment marché
        return ret > 32, "" if ret > 32 else f"UAC refusé ou erreur (code {ret})"


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app  = ScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
