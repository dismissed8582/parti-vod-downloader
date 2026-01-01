import os
import re
import sys
import html
import time
import threading
import subprocess
from typing import Optional, Tuple, List, Dict

import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from playwright.sync_api import sync_playwright

__app_name__ = "Parti VOD Downloader"
__version__ = "1.0 (WIP)"



# ==========================
# Backend / Resolver
# ==========================

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# main/master manifest
PARTI_MANIFEST_M3U8_RE = re.compile(
    r"https?://media\.parti\.com/[^\"\'\s<>]+/(?:main|master)\.m3u8(?:\?[^\s\"\'<>]+)?",
    re.IGNORECASE
)

# best playlist requested by the player
PARTI_INDEX1_M3U8_RE = re.compile(
    r"https?://media\.parti\.com/[^\"\'\s<>]+/index-1\.m3u8(?:\?[^\s\"\'<>]+)?",
    re.IGNORECASE
)

STREAM_INF_RE = re.compile(r"#EXT-X-STREAM-INF:(.*)", re.IGNORECASE)
RESOLUTION_RE = re.compile(r"RESOLUTION=(\d+)x(\d+)", re.IGNORECASE)
BANDWIDTH_RE = re.compile(r"BANDWIDTH=(\d+)", re.IGNORECASE)
FRAME_RATE_RE = re.compile(r"FRAME-RATE=([0-9.]+)", re.IGNORECASE)


def ffmpeg_exists() -> bool:
    try:
        subprocess.run(["ffmpeg", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return True
    except Exception:
        return False


def session_from_playwright_cookies(cookies, referer: Optional[str]) -> requests.Session:
    s = requests.Session()
    headers = DEFAULT_HEADERS.copy()
    if referer:
        headers["Referer"] = referer
    s.headers.update(headers)
    for c in cookies:
        s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
    return s


def resolve_parti_page_to_media_urls(page_url: str) -> Tuple[Optional[str], Optional[str], Optional[list]]:
    """
    Returns: (index1_url, manifest_url, cookies)
      - index1_url:  .../index-1.m3u8   (best)
      - manifest_url: ...(main|master).m3u8 (normal)
    """
    # Step 1: HTML scan
    try:
        r = requests.get(page_url, headers={**DEFAULT_HEADERS, "Referer": "https://parti.com/"}, timeout=12)
        r.raise_for_status()
        text = html.unescape(r.text)

        idx = PARTI_INDEX1_M3U8_RE.search(text)
        man = PARTI_MANIFEST_M3U8_RE.search(text)

        if idx or man:
            return (idx.group(0) if idx else None, man.group(0) if man else None, None)
    except Exception:
        pass

    # Step 2: Playwright network capture
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        context.set_extra_http_headers({"Referer": "https://parti.com/"})
        page = context.new_page()

        found = {"index1": None, "manifest": None}

        def on_request(req):
            u = req.url
            if found["index1"] is None and PARTI_INDEX1_M3U8_RE.match(u):
                found["index1"] = u
            if found["manifest"] is None and PARTI_MANIFEST_M3U8_RE.match(u):
                found["manifest"] = u

        page.on("request", on_request)

        page.goto(page_url, wait_until="domcontentloaded", timeout=30000)

        # Try triggering playback
        try:
            page.mouse.click(600, 350)
        except Exception:
            pass
        try:
            page.keyboard.press("Space")
        except Exception:
            pass

        deadline = time.time() + 10.0
        while time.time() < deadline and (found["index1"] is None and found["manifest"] is None):
            page.wait_for_timeout(250)

        cookies = context.cookies()
        browser.close()
        return found["index1"], found["manifest"], cookies


def resolve_input_to_urls(user_url: str) -> Tuple[Optional[str], Optional[str], Optional[requests.Session], Optional[str]]:
    """
    Returns: (index1_url, manifest_url, session, referer)
    """
    u = (user_url or "").strip()
    if not u:
        return None, None, None, None

    if u.lower().endswith(".m3u8"):
        s = requests.Session()
        s.headers.update(DEFAULT_HEADERS)
        if PARTI_INDEX1_M3U8_RE.match(u):
            return u, None, s, None
        return None, u, s, None

    if "parti.com/video/" in u:
        index1_url, manifest_url, cookies = resolve_parti_page_to_media_urls(u)
        if not index1_url and not manifest_url:
            return None, None, None, None

        if cookies:
            s = session_from_playwright_cookies(cookies, referer=u)
            return index1_url, manifest_url, s, u

        s = requests.Session()
        s.headers.update({**DEFAULT_HEADERS, "Referer": u})
        return index1_url, manifest_url, s, u

    return None, None, None, None


def list_quality_variants(master_url: str, session: requests.Session) -> List[Dict]:
    r = session.get(master_url, timeout=12)
    r.raise_for_status()
    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
    base = master_url.rsplit("/", 1)[0]

    variants = []
    last_inf = None

    for ln in lines:
        m = STREAM_INF_RE.match(ln)
        if m:
            last_inf = m.group(1)
            continue

        if last_inf and (ln.endswith(".m3u8") or ".m3u8?" in ln):
            abs_url = urljoin(base + "/", ln)

            height = -1
            bw = -1
            fps = -1.0

            rm = RESOLUTION_RE.search(last_inf)
            if rm:
                height = int(rm.group(2))

            bm = BANDWIDTH_RE.search(last_inf)
            if bm:
                bw = int(bm.group(1))

            fm = FRAME_RATE_RE.search(last_inf)
            if fm:
                try:
                    fps = float(fm.group(1))
                except Exception:
                    fps = -1.0

            res_label = f"{height}p" if height > 0 else "unknown"
            fps_label = f"{int(round(fps))}" if fps >= 50 else ""
            mbps_label = f"{bw/1_000_000:.2f} Mbps" if bw > 0 else ""

            left = res_label + (fps_label if fps_label else "")
            label = left + (f"  |  {mbps_label}" if mbps_label else "")

            variants.append({
                "label": label,
                "url": abs_url,
                "height": height,
                "bandwidth": bw,
                "fps": fps,
            })

            last_inf = None

    variants.sort(key=lambda v: (v["height"], v["bandwidth"]), reverse=True)
    return variants


def get_final_m3u8(url: str, session: requests.Session) -> Optional[str]:
    r = session.get(url, timeout=12)
    r.raise_for_status()
    lines = r.text.splitlines()
    base = url.rsplit("/", 1)[0]

    ts_files = [urljoin(base + "/", l.strip()) for l in lines if l.strip().endswith(".ts")]
    if ts_files:
        return url

    sub_m3u8 = [urljoin(base + "/", l.strip()) for l in lines if l.strip().endswith(".m3u8")]
    if sub_m3u8:
        return get_final_m3u8(sub_m3u8[0], session)

    return None


def download_segment(ts_url: str, folder: str, i: int, session: requests.Session, cancel_event: threading.Event) -> int:
    if cancel_event.is_set():
        raise RuntimeError("cancelled")

    local_path = os.path.join(folder, f"seg_{i:05}.ts")
    r = session.get(ts_url, stream=True, timeout=(8, 20))
    r.raise_for_status()

    try:
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(1024 * 512):
                if cancel_event.is_set():
                    raise RuntimeError("cancelled")
                if chunk:
                    f.write(chunk)
    finally:
        try:
            r.close()
        except Exception:
            pass

    return i


# ==========================
# GUI
# ==========================

class PlaceholderEntry(tk.Entry):
    def __init__(self, master, placeholder: str = "", placeholder_fg="#9aa0a6", **kwargs):
        super().__init__(master, **kwargs)
        self.placeholder = placeholder
        self.placeholder_fg = placeholder_fg
        self.default_fg = kwargs.get("fg", "#111111")
        self._is_placeholder = False
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._show_placeholder)
        self._show_placeholder()

    def _show_placeholder(self, *_):
        if not self.get():
            self._is_placeholder = True
            self.configure(fg=self.placeholder_fg)
            self.insert(0, self.placeholder)

    def _clear_placeholder(self, *_):
        if self._is_placeholder:
            self.delete(0, tk.END)
            self.configure(fg=self.default_fg)
            self._is_placeholder = False

    def get_value(self) -> str:
        if self._is_placeholder:
            return ""
        return self.get().strip()


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{__app_name__} v{__version__}")
        self.root.geometry("860x590")
        self.root.minsize(1127, 940)

        # Theme
        self.dark_mode = tk.BooleanVar(value=False)

        # State
        self.session: Optional[requests.Session] = None
        self.index1_url: Optional[str] = None
        self.manifest_url: Optional[str] = None
        self.variants: List[Dict] = []
        self.variant_by_label: Dict[str, str] = {}

        # Cancellation / processes
        self.cancel_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._ffmpeg_proc: Optional[subprocess.Popen] = None
        self.downloading = False
        self._current_segments_dir: Optional[str] = None

        # Vars
        self.output_folder_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads"))
        self.output_filename_var = tk.StringVar(value="video.mp4")

        self.source_var = tk.StringVar(value="Best (index-1)")
        self.quality_var = tk.StringVar(value="Auto")
        self.use_best_var = tk.BooleanVar(value=True)
        self.keep_segments_var = tk.BooleanVar(value=False)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value="0%")
        self.status_var = tk.StringVar(value="Ready to download...")

        self._build_ui()
        self._apply_theme()

    def _build_ui(self):
        self.root.configure(bg="#f5f6f8")
        self.container = tk.Frame(self.root, bg="#f5f6f8")
        self.container.pack(fill="both", expand=True, padx=18, pady=16)

        header = tk.Frame(self.container, bg="#ffffff", highlightthickness=1, highlightbackground="#e5e7eb")
        header.pack(fill="x")
        header.grid_columnconfigure(0, weight=1)

        title = tk.Label(header, text=__app_name__, font=("Segoe UI", 18, "bold"), bg="#ffffff", fg="#111827")
        subtitle = tk.Label(
            header,
            text="Paste a Parti page URL • Choose Best or Normal",
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#6b7280",
        )
        title.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 0))
        subtitle.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 14))

        self.theme_btn = tk.Button(header, text="🌙", font=("Segoe UI", 12), bd=0,
                                   command=self.toggle_theme, cursor="hand2")
        self.theme_btn.grid(row=0, column=1, rowspan=2, sticky="e", padx=16)

        body = tk.Frame(self.container, bg="#ffffff", highlightthickness=1, highlightbackground="#e5e7eb")
        body.pack(fill="both", expand=True, pady=(14, 0))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(4, weight=1)

        url_row = tk.Frame(body, bg="#ffffff")
        url_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 10))
        url_row.grid_columnconfigure(0, weight=1)

        tk.Label(url_row, text="URL", font=("Segoe UI", 10, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=0, column=0, sticky="w", pady=(0, 6))

        entry_row = tk.Frame(url_row, bg="#ffffff")
        entry_row.grid(row=1, column=0, sticky="ew")
        entry_row.grid_columnconfigure(0, weight=1)

        self.url_entry = PlaceholderEntry(
            entry_row,
            placeholder="Paste the URL (e.g. https://parti.com/video/129054)",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1,
            highlightthickness=1
        )
        self.url_entry.grid(row=0, column=0, sticky="ew", ipady=8)

        self.paste_btn = tk.Button(entry_row, text="📋  Paste", font=("Segoe UI", 10, "bold"),
                                   command=self.paste_clipboard, cursor="hand2")
        self.paste_btn.grid(row=0, column=1, padx=(10, 10), ipady=6)

        self.download_btn = tk.Button(entry_row, text="⬇  Download", font=("Segoe UI", 10, "bold"),
                                      command=self.on_download_clicked, cursor="hand2")
        self.download_btn.grid(row=0, column=2, padx=(0, 10), ipady=6)

        self.cancel_top_btn = tk.Button(entry_row, text="✖  Cancel", font=("Segoe UI", 10, "bold"),
                                        command=self.cancel_download, cursor="hand2")
        self.cancel_top_btn.grid(row=0, column=3, ipady=6)

        options_box = tk.LabelFrame(body, text="Options", font=("Segoe UI", 10, "bold"),
                                    bg="#ffffff", fg="#111827", bd=1, relief="groove")
        options_box.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 12))
        options_box.grid_columnconfigure(0, weight=1)
        options_box.grid_columnconfigure(1, weight=1)

        tk.Label(options_box, text="Playlist Source", font=("Segoe UI", 9, "bold"),
                 bg="#ffffff", fg="#111827").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self.source_combo = ttk.Combobox(
            options_box,
            textvariable=self.source_var,
            state="readonly",
            values=["Best (index-1)", "Normal (main/master)"]
        )
        self.source_combo.grid(row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 10))
        self.source_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_source_change())

        tk.Label(options_box, text="Quality", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=2, column=0, sticky="w", padx=12, pady=(0, 4))
        tk.Label(options_box, text="Output Filename", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=2, column=1, sticky="w", padx=12, pady=(0, 4))

        self.quality_combo = ttk.Combobox(options_box, textvariable=self.quality_var,
                                          state="readonly", values=["Auto"], width=30)
        self.quality_combo.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))

        self.filename_entry = tk.Entry(options_box, textvariable=self.output_filename_var,
                                       font=("Segoe UI", 10), relief="flat", bd=1, highlightthickness=1)
        self.filename_entry.grid(row=3, column=1, sticky="ew", padx=12, pady=(0, 8), ipady=6)

        self.use_best_chk = tk.Checkbutton(options_box, text="Use best available quality automatically",
                                           variable=self.use_best_var, bg="#ffffff", fg="#111827",
                                           font=("Segoe UI", 9), command=self._on_best_toggle)
        self.use_best_chk.grid(row=4, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 4))

        self.keep_segments_chk = tk.Checkbutton(options_box, text="Keep segments folder (debug)",
                                                variable=self.keep_segments_var, bg="#ffffff", fg="#111827",
                                                font=("Segoe UI", 9))
        self.keep_segments_chk.grid(row=5, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 10))

        out_row = tk.Frame(body, bg="#ffffff")
        out_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(6, 8))
        out_row.grid_columnconfigure(0, weight=1)

        tk.Label(out_row, text="Output Folder", font=("Segoe UI", 10, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=0, column=0, sticky="w", pady=(0, 6))

        out_path_row = tk.Frame(out_row, bg="#ffffff")
        out_path_row.grid(row=1, column=0, sticky="ew")
        out_path_row.grid_columnconfigure(0, weight=1)

        self.out_entry = tk.Entry(out_path_row, textvariable=self.output_folder_var, font=("Segoe UI", 10),
                                  relief="flat", bd=1, highlightthickness=1)
        self.out_entry.grid(row=0, column=0, sticky="ew", ipady=8)

        self.browse_btn = tk.Button(out_path_row, text="📁  Browse…", font=("Segoe UI", 10, "bold"),
                                    command=self.browse_folder, cursor="hand2")
        self.browse_btn.grid(row=0, column=1, padx=(10, 0), ipady=6)

        prog_row = tk.Frame(body, bg="#ffffff")
        prog_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(6, 6))
        prog_row.grid_columnconfigure(0, weight=1)

        tk.Label(prog_row, text="Progress", font=("Segoe UI", 10, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=0, column=0, sticky="w")

        self.progress_label = tk.Label(prog_row, textvariable=self.progress_text_var,
                                       font=("Segoe UI", 10), bg="#ffffff", fg="#111827")
        self.progress_label.grid(row=0, column=1, sticky="e")

        self.progress = ttk.Progressbar(prog_row, orient="horizontal", mode="determinate",
                                        maximum=100.0, variable=self.progress_var)
        self.progress.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        status_row = tk.Frame(body, bg="#ffffff")
        status_row.grid(row=4, column=0, sticky="nsew", padx=16, pady=(10, 10))
        status_row.grid_columnconfigure(0, weight=1)
        status_row.grid_rowconfigure(2, weight=1)

        tk.Label(status_row, text="Status", font=("Segoe UI", 10, "bold"), bg="#ffffff", fg="#111827") \
            .grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.status_line = tk.Label(status_row, textvariable=self.status_var,
                                    font=("Segoe UI", 10), bg="#ffffff", fg="#6b7280")
        self.status_line.grid(row=1, column=0, sticky="w", pady=(0, 6))

        text_frame = tk.Frame(status_row, bg="#ffffff")
        text_frame.grid(row=2, column=0, sticky="nsew")
        text_frame.grid_columnconfigure(0, weight=1)
        text_frame.grid_rowconfigure(0, weight=1)

        self.log_text = tk.Text(text_frame, wrap="word", font=("Consolas", 9),
                                relief="flat", bd=1, highlightthickness=1, height=8)
        self.log_text.grid(row=0, column=0, sticky="nsew")

        self.log_scroll = tk.Scrollbar(text_frame, command=self.log_text.yview)
        self.log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=self.log_scroll.set)
        self.log_text.configure(state="disabled")
        self._log("Ready to download...")

        bottom = tk.Frame(body, bg="#ffffff")
        bottom.grid(row=5, column=0, sticky="ew", padx=16, pady=(6, 16))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)

        self.open_folder_btn = tk.Button(bottom, text="📂  Open Output Folder",
                                         font=("Segoe UI", 10, "bold"),
                                         command=self.open_output_folder, cursor="hand2")
        self.open_folder_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=8)

        self.cancel_btn = tk.Button(bottom, text="✖  Cancel Download",
                                    font=("Segoe UI", 10, "bold"),
                                    command=self.cancel_download, cursor="hand2")
        self.cancel_btn.grid(row=0, column=1, sticky="ew", padx=(8, 0), ipady=8)

        self._set_downloading(False)
        self._on_source_change()

    def toggle_theme(self):
        self.dark_mode.set(not self.dark_mode.get())
        self._apply_theme()

    def _apply_theme(self):
        dark = self.dark_mode.get()
        if dark:
            bg, card, border = "#0b0f14", "#0f172a", "#1f2937"
            text, sub = "#e5e7eb", "#9ca3af"
            entry_bg, entry_border = "#0b1220", "#243244"
            btn_bg, btn_fg = "#111827", "#e5e7eb"
            primary_bg, primary_fg = "#111827", "#ffffff"
            danger_bg, danger_fg = "#7f1d1d", "#ffffff"
            self.theme_btn.configure(text="☀️")
        else:
            bg, card, border = "#f5f6f8", "#ffffff", "#e5e7eb"
            text, sub = "#111827", "#6b7280"
            entry_bg, entry_border = "#f3f4f6", "#e5e7eb"
            btn_bg, btn_fg = "#eef2f7", "#111827"
            primary_bg, primary_fg = "#111827", "#ffffff"
            danger_bg, danger_fg = "#ef8996", "#ffffff"
            self.theme_btn.configure(text="🌙")

        self.root.configure(bg=bg)
        self.container.configure(bg=bg)
        for w in self.container.winfo_children():
            if isinstance(w, tk.Frame):
                w.configure(bg=card, highlightbackground=border)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TProgressbar", thickness=16)
        style.configure("TCombobox", padding=6)

        def recolor(widget):
            for child in widget.winfo_children():
                try:
                    if isinstance(child, tk.Label):
                        child.configure(bg=child.master["bg"])
                        if child is self.status_line:
                            child.configure(fg=sub)
                        else:
                            child.configure(fg=sub if child.cget("fg") in ("#6b7280", "#9ca3af") else text)
                    elif isinstance(child, (tk.Frame, tk.LabelFrame)):
                        child.configure(bg=card, highlightbackground=border)
                    elif isinstance(child, tk.Checkbutton):
                        child.configure(bg=card, fg=text, activebackground=card, activeforeground=text, selectcolor=card)
                    elif isinstance(child, tk.Entry):
                        child.configure(bg=entry_bg, fg=text,
                                        highlightbackground=entry_border, highlightcolor=entry_border,
                                        insertbackground=text)
                    elif isinstance(child, tk.Text):
                        child.configure(bg=entry_bg, fg=text,
                                        highlightbackground=entry_border, highlightcolor=entry_border,
                                        insertbackground=text)
                except Exception:
                    pass
                recolor(child)

        recolor(self.container)

        self.paste_btn.configure(bg=btn_bg, fg=btn_fg, activebackground=btn_bg, activeforeground=btn_fg)
        self.browse_btn.configure(bg=btn_bg, fg=btn_fg, activebackground=btn_bg, activeforeground=btn_fg)
        self.open_folder_btn.configure(bg=btn_bg, fg=btn_fg, activebackground=btn_bg, activeforeground=btn_fg)
        self.download_btn.configure(bg=primary_bg, fg=primary_fg, activebackground=primary_bg, activeforeground=primary_fg)
        self.cancel_btn.configure(bg=danger_bg, fg=danger_fg, activebackground=danger_bg, activeforeground=danger_fg)
        self.cancel_top_btn.configure(bg=danger_bg, fg=danger_fg, activebackground=danger_bg, activeforeground=danger_fg)

        try:
            header_bg = self.container.winfo_children()[0]["bg"]
            self.theme_btn.configure(bg=header_bg, fg=text, activebackground=header_bg)
        except Exception:
            pass

    def _set_status(self, msg: str):
        self.status_var.set(msg)

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def paste_clipboard(self):
        try:
            clip = self.root.clipboard_get().strip()
            if clip:
                self.url_entry._clear_placeholder()
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, clip)
                self._log("Pasted URL from clipboard.")
        except Exception:
            messagebox.showerror("Clipboard", "Could not read clipboard.")

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_folder_var.set(folder)
            self._log(f"Output folder set to: {folder}")

    def open_output_folder(self):
        folder = self.output_folder_var.get().strip()
        if not folder:
            return
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception:
            messagebox.showerror("Open Folder", "Could not open output folder.")

    def cancel_download(self):
        if not self.downloading:
            self._log("Nothing to cancel.")
            return

        self.cancel_event.set()
        self._set_status("Cancel requested… stopping downloads/merge.")
        self._log("Cancel requested...")

        try:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

        try:
            if self._ffmpeg_proc is not None and self._ffmpeg_proc.poll() is None:
                self._ffmpeg_proc.terminate()
                try:
                    self._ffmpeg_proc.wait(timeout=2)
                except Exception:
                    self._ffmpeg_proc.kill()
        except Exception:
            pass

    def _set_downloading(self, downloading: bool):
        self.downloading = downloading
        state = "disabled" if downloading else "normal"

        self.download_btn.configure(state="disabled" if downloading else "normal")
        self.paste_btn.configure(state=state)
        self.browse_btn.configure(state=state)
        self.url_entry.configure(state=state)
        self.filename_entry.configure(state=state)
        self.out_entry.configure(state=state)
        self.source_combo.configure(state="disabled" if downloading else "readonly")

        self.cancel_btn.configure(state="normal" if downloading else "disabled")
        self.cancel_top_btn.configure(state="normal" if downloading else "disabled")

        if downloading:
            self.quality_combo.configure(state="disabled")
            self.use_best_chk.configure(state="disabled")
            self.keep_segments_chk.configure(state="disabled")
        else:
            self.keep_segments_chk.configure(state="normal")
            self._on_source_change()

    def _on_source_change(self):
        if self.downloading:
            return

        src = self.source_var.get().strip()
        if src.startswith("Best"):
            self.use_best_chk.configure(state="disabled")
            self.quality_combo.configure(state="disabled")
            self.quality_var.set("Index-1 (Best)")
        else:
            self.use_best_chk.configure(state="normal")
            if self.variants and self.use_best_var.get():
                self.quality_var.set("Auto (Best)")
                self.quality_combo.configure(state="disabled")
            else:
                self.quality_combo.configure(state="readonly")
                if self.quality_var.get() == "Index-1 (Best)":
                    self.quality_var.set("Auto")

    def _on_best_toggle(self):
        if self.downloading:
            return
        if self.source_var.get().startswith("Best"):
            self._on_source_change()
            return
        if self.use_best_var.get():
            if self.variants:
                self.quality_var.set("Auto (Best)")
                self.quality_combo.configure(state="disabled")
            else:
                self.quality_var.set("Auto")
                self.quality_combo.configure(state="readonly")
        else:
            self.quality_combo.configure(state="readonly")
            if not self.variants:
                self.quality_var.set("Auto")

    def _validate_filename(self, name: str) -> str:
        name = (name or "").strip()
        if not name:
            name = "video.mp4"
        for b in ['\\', '/', ':', '*', '?', '"', '<', '>', '|']:
            name = name.replace(b, "_")
        if not name.lower().endswith(".mp4"):
            name += ".mp4"
        return name

    def on_download_clicked(self):
        if self.downloading:
            return

        if not ffmpeg_exists():
            messagebox.showerror("Missing dependency", "ffmpeg was not found. Install ffmpeg and make sure it's in PATH.")
            return

        user_url = self.url_entry.get_value()
        if not user_url:
            messagebox.showerror("Invalid", "Please enter a URL.")
            return

        out_folder = self.output_folder_var.get().strip()
        if not out_folder:
            messagebox.showerror("Invalid", "Please select an output folder.")
            return

        out_name = self._validate_filename(self.output_filename_var.get())
        self.output_filename_var.set(out_name)

        self.progress_var.set(0.0)
        self.progress_text_var.set("0%")
        self.cancel_event.clear()
        self._set_status("Resolving URL…")
        self._log("Resolving URL -> index-1 + main/master ...")

        self._set_downloading(True)

        threading.Thread(
            target=self._resolve_and_download_thread,
            args=(user_url, out_folder, out_name),
            daemon=True
        ).start()

    def _resolve_and_download_thread(self, user_url: str, out_folder: str, out_name: str):
        try:
            index1_url, manifest_url, session, _ = resolve_input_to_urls(user_url)
            if not session or (not index1_url and not manifest_url):
                self.root.after(0, self._on_error, "Could not capture media.parti.com .m3u8 URLs from that page.")
                return

            self.session = session
            self.index1_url = index1_url
            self.manifest_url = manifest_url

            self.root.after(0, self._log, f"Captured index-1: {index1_url}" if index1_url else "Captured index-1: (none)")
            self.root.after(0, self._log, f"Captured main/master: {manifest_url}" if manifest_url else "Captured main/master: (none)")

            self.variants = []
            self.variant_by_label = {}

            if manifest_url:
                self.root.after(0, self._set_status, "Parsing qualities…")
                try:
                    self.variants = list_quality_variants(manifest_url, session)
                except Exception:
                    self.variants = []

            values = ["Auto"]
            if self.variants:
                for v in self.variants:
                    self.variant_by_label[v["label"]] = v["url"]
                    values.append(v["label"])

            def update_quality_ui():
                self.quality_combo.configure(values=values)
                self._on_source_change()

            self.root.after(0, update_quality_ui)

            chosen = self._choose_base_playlist()
            self.root.after(0, self._log, f"Base playlist chosen: {chosen}")

            chosen = self._apply_variant_choice(chosen)
            self.root.after(0, self._log, f"Final playlist chosen: {chosen}")

            self._download_pipeline(chosen, session, out_folder, out_name)

        except Exception as e:
            self.root.after(0, self._on_error, str(e))

    def _choose_base_playlist(self) -> str:
        want_best = self.source_var.get().startswith("Best")

        if want_best:
            if self.index1_url:
                return self.index1_url
            if self.manifest_url:
                self.root.after(0, self._log, "Index-1 not found; falling back to main/master.")
                return self.manifest_url
        else:
            if self.manifest_url:
                return self.manifest_url
            if self.index1_url:
                self.root.after(0, self._log, "Main/master not found; falling back to index-1.")
                return self.index1_url

        raise RuntimeError("No playable playlist URL available.")

    def _apply_variant_choice(self, base_url: str) -> str:
        if self.source_var.get().startswith("Best"):
            return base_url

        if not self.manifest_url:
            return base_url
        if self.index1_url and base_url == self.index1_url:
            return base_url

        if self.use_best_var.get() and self.variants:
            return self.variants[0]["url"]

        sel = self.quality_var.get()
        if sel in self.variant_by_label:
            return self.variant_by_label[sel]

        return base_url

    def _download_pipeline(self, m3u8_url: str, session: requests.Session, out_folder: str, out_name: str):
        try:
            if self.cancel_event.is_set():
                self.root.after(0, self._on_cancelled)
                return

            self.root.after(0, self._set_status, "Fetching playlist…")
            final_url = get_final_m3u8(m3u8_url, session)
            if not final_url:
                self.root.after(0, self._on_error, "No playable streams found.")
                return

            r = session.get(final_url, timeout=12)
            r.raise_for_status()

            lines = r.text.splitlines()
            base_url = final_url.rsplit("/", 1)[0]
            ts_urls = [urljoin(base_url + "/", l.strip()) for l in lines if l.strip().endswith(".ts")]

            if not ts_urls:
                self.root.after(0, self._on_error, "No TS segments found.")
                return

            total = len(ts_urls)
            self.root.after(0, self._log, f"Downloading {total} segments...")
            self.root.after(0, self._set_status, f"Downloading… (0/{total})")

            # ✅ unique temp dir per run
            run_id = time.strftime("%Y%m%d_%H%M%S")
            temp_folder = os.path.join(out_folder, f"segments_{run_id}")
            self._current_segments_dir = temp_folder
            os.makedirs(temp_folder, exist_ok=True)

            completed = 0
            self._executor = ThreadPoolExecutor(max_workers=8)

            try:
                futures = {
                    self._executor.submit(download_segment, ts, temp_folder, i, session, self.cancel_event): i
                    for i, ts in enumerate(ts_urls, 1)
                }

                for future in as_completed(futures):
                    if self.cancel_event.is_set():
                        for f in futures:
                            f.cancel()
                        break

                    try:
                        future.result()
                    except RuntimeError as ex:
                        if "cancelled" in str(ex).lower():
                            self.cancel_event.set()
                            break
                        raise

                    completed += 1
                    pct = (completed / total) * 100.0
                    self.root.after(0, self._update_progress, pct, completed, total)

            finally:
                try:
                    self._executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    try:
                        self._executor.shutdown(wait=False)
                    except Exception:
                        pass
                self._executor = None

            if self.cancel_event.is_set():
                self.root.after(0, self._log, "Cancelled. Cleaning up…")
                self.root.after(0, self._set_status, "Cancelled. Cleaning up…")
                if not self.keep_segments_var.get():
                    self._cleanup_segments(temp_folder)
                self.root.after(0, self._on_cancelled)
                return

            self.root.after(0, self._log, "Merging segments into MP4…")
            self.root.after(0, self._set_status, "Merging…")

            list_path = os.path.join(temp_folder, "list.txt")
            with open(list_path, "w", encoding="utf-8") as f:
                for i in range(1, total + 1):
                    f.write(f"file 'seg_{i:05}.ts'\n")

            output_file = os.path.join(out_folder, out_name)
            cmd = ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", list_path, "-c", "copy", output_file]

            self._ffmpeg_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            while self._ffmpeg_proc.poll() is None:
                if self.cancel_event.is_set():
                    try:
                        self._ffmpeg_proc.terminate()
                        self._ffmpeg_proc.wait(timeout=2)
                    except Exception:
                        try:
                            self._ffmpeg_proc.kill()
                        except Exception:
                            pass
                    break
                time.sleep(0.1)

            self._ffmpeg_proc = None

            if self.cancel_event.is_set():
                self.root.after(0, self._log, "Cancelled during merge. Cleaning up…")
                self.root.after(0, self._set_status, "Cancelled during merge. Cleaning up…")
                if not self.keep_segments_var.get():
                    self._cleanup_segments(temp_folder)
                self.root.after(0, self._on_cancelled)
                return

            if not self.keep_segments_var.get():
                self._cleanup_segments(temp_folder)

            self.root.after(0, self._update_progress, 100.0, total, total)
            self.root.after(0, self._set_status, f"Done! Saved: {output_file}")
            self.root.after(0, self._log, f"Done! Saved as: {output_file}")
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Download complete!\nSaved as:\n{output_file}"))
            self.root.after(0, lambda: self._set_downloading(False))

        except Exception as e:
            self.root.after(0, self._on_error, str(e))

    def _cleanup_segments(self, temp_folder: str):
        try:
            if os.path.isdir(temp_folder):
                for file in os.listdir(temp_folder):
                    try:
                        os.remove(os.path.join(temp_folder, file))
                    except Exception:
                        pass
                try:
                    os.rmdir(temp_folder)
                except Exception:
                    pass
        except Exception:
            pass
        self._current_segments_dir = None

    def _update_progress(self, pct: float, completed: int, total: int):
        pct = max(0.0, min(100.0, pct))
        self.progress_var.set(pct)
        self.progress_text_var.set(f"{int(pct)}%")
        self._set_status(f"Downloading… ({completed}/{total})")
        if completed == total or completed % 25 == 0:
            self._log(f"Downloading {completed}/{total}…")

    def _on_error(self, msg: str):
        self._log(f"Error: {msg}")
        self._set_status("Error.")
        self._set_downloading(False)
        messagebox.showerror("Error", msg)

    def _on_cancelled(self):
        self._log("Download cancelled.")
        self._set_status("Cancelled.")
        self.progress_text_var.set("0%")
        self.progress_var.set(0.0)
        self._set_downloading(False)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
