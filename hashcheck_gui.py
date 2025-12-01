
#!/usr/bin/env python3
"""
HashCheck GUI (dark mode + table fix)
- Dark theme with sleek look using pure ttk styles (no external themes).
- Fixed _insert_row: removed incorrect use of Treeview.tag_has (method) that caused TypeError.
- Results table with status-based row coloring (MISMATCH red, NEW orange, MISSING gray, ERROR magenta).
- Compact CSV export (no run_id), still reuses your hashcheck.py functions.
"""

import os
import sys
import csv
import platform
import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional
import threading
import queue
import traceback

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception as e:
    print("[-] Tkinter is required. On some Linux distros, install: python3-tk", file=sys.stderr)
    raise

# --- dynamic import of user's hashcheck.py ---
def load_hashcheck_module(module_path: Path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("hashcheck", str(module_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod

DEFAULT_HASHCHECK_CANDIDATES = [
    Path(__file__).with_name("hashcheck.py"),
    Path.cwd() / "hashcheck.py",
]

def utc_iso(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"

@dataclass
class ScanOptions:
    path: Path
    algo: str
    recursive: bool
    out_csv: Path

@dataclass
class VerifyOptions:
    path: Path
    manifest: Path
    algo: str
    recursive: bool
    out_csv: Path

TABLE_COLUMNS = ("path","size_bytes","mtime_utc","algo","hash","status","error")

STATUS_STYLES = {
    "OK":      {"foreground": "",       "background": ""},
    "BASELINE":{"foreground": "",       "background": ""},
    "MISMATCH":{"foreground": "#ffffff","background": "#cc3333"},
    "NEW":     {"foreground": "#111111","background": "#ffcc66"},
    "MISSING": {"foreground": "#111111","background": "#bfbfbf"},
    "ERROR":   {"foreground": "#ffffff","background": "#b300b3"},
}

DARK = {
    "bg": "#0f1216",
    "panel": "#151a21",
    "fg": "#e6e6e6",
    "muted": "#b3b3b3",
    "accent": "#6aa0ff",
    "entry": "#0b0e12",
    "sel_bg": "#264066",
    "sel_fg": "#ffffff",
    "row_alt": "#131821",
    "tree_bg": "#0f1216",
    "tree_field": "#0f1216",
    "tree_heading_bg": "#1b2230",
    "tree_heading_fg": "#e6e6e6",
    "button_bg": "#1b2230",
    "button_fg": "#e6e6e6",
    "progress_bg": "#1b2230",
    "progress_bar": "#6aa0ff",
}

class HashCheckGUI(tk.Tk):
    def __init__(self, hashcheck_mod):
        super().__init__()
        self.title("HashCheck GUI")
        self.geometry("1000x680")
        self.minsize(920, 560)

        self.hashcheck = hashcheck_mod
        self.stop_flag = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.msg_q: "queue.Queue[str]" = queue.Queue()

        self._apply_dark_theme()
        self._build_ui()
        self._poll_msgs()

    # --------- Dark Theme ---------
    def _apply_dark_theme(self):
        self.configure(bg=DARK["bg"])
        style = ttk.Style(self)
        # Prefer 'clam' for better color support
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Base colors
        style.configure(".", background=DARK["bg"], foreground=DARK["fg"])

        # Frames / LabelFrames
        style.configure("TFrame", background=DARK["bg"])
        style.configure("TLabelframe", background=DARK["bg"])
        style.configure("TLabelframe.Label", background=DARK["bg"], foreground=DARK["muted"])

        # Notebook
        style.configure("TNotebook", background=DARK["bg"], tabmargins= [2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=DARK["panel"], foreground=DARK["fg"], padding=[12,6])
        style.map("TNotebook.Tab",
                  background=[("selected", DARK["tree_heading_bg"])],
                  foreground=[("selected", DARK["fg"])])

        # Labels
        style.configure("TLabel", background=DARK["bg"], foreground=DARK["fg"])

        # Buttons
        style.configure("TButton", background=DARK["button_bg"], foreground=DARK["button_fg"], padding=6, relief="flat")
        style.map("TButton",
                  background=[("active", DARK["sel_bg"])],
                  foreground=[("active", DARK["sel_fg"])])

        # Entries & Comboboxes
        style.configure("TEntry", fieldbackground=DARK["entry"], insertcolor=DARK["fg"],
                        foreground=DARK["fg"], background=DARK["entry"])
        style.configure("TCombobox", fieldbackground=DARK["entry"], background=DARK["entry"], foreground=DARK["fg"])

        # Checkbuttons
        style.configure("TCheckbutton", background=DARK["bg"], foreground=DARK["fg"])

        # Treeview
        style.configure("Treeview",
                        background=DARK["tree_bg"],
                        fieldbackground=DARK["tree_field"],
                        foreground=DARK["fg"],
                        bordercolor=DARK["panel"],
                        rowheight=24)
        style.map("Treeview",
                  background=[("selected", DARK["sel_bg"])],
                  foreground=[("selected", DARK["sel_fg"])])

        style.configure("Treeview.Heading",
                        background=DARK["tree_heading_bg"],
                        foreground=DARK["tree_heading_fg"],
                        relief="flat")
        style.map("Treeview.Heading",
                  background=[("active", DARK["tree_heading_bg"])],
                  foreground=[("active", DARK["tree_heading_fg"])])

        # Progressbar
        style.configure("Horizontal.TProgressbar",
                        background=DARK["progress_bar"],
                        troughcolor=DARK["progress_bg"])

    def _build_ui(self):
        # Tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="x", expand=False, padx=8, pady=8)

        # --- Scan tab ---
        self.tab_scan = ttk.Frame(nb)
        nb.add(self.tab_scan, text="Scan (make manifest)")

        self.scan_path_var = tk.StringVar()
        self.scan_algo_var = tk.StringVar(value="sha256")
        self.scan_recursive_var = tk.BooleanVar(value=True)
        self.scan_out_var = tk.StringVar(value=str(Path.cwd() / "manifest.csv"))

        self._build_scan_tab(self.tab_scan)

        # --- Verify tab ---
        self.tab_verify = ttk.Frame(nb)
        nb.add(self.tab_verify, text="Verify (compare to manifest)")

        self.verify_path_var = tk.StringVar()
        self.verify_manifest_var = tk.StringVar()
        self.verify_algo_var = tk.StringVar(value="sha256")
        self.verify_recursive_var = tk.BooleanVar(value=True)
        self.verify_out_var = tk.StringVar(value=str(Path.cwd() / "verify_report.csv"))

        self._build_verify_tab(self.tab_verify)

        # Actions row
        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=8, pady=(0,8))
        self.btn_stop = ttk.Button(actions, text="Stop", command=self._on_stop, state="disabled")
        self.btn_stop.pack(side="right")
        self.progress = ttk.Progressbar(actions, orient="horizontal", mode="determinate")
        self.progress.pack(side="right", fill="x", expand=True, padx=(0,8))
        ttk.Button(actions, text="Export Table → CSV", command=self._export_table_csv).pack(side="left")

        # Results table
        table_frame = ttk.LabelFrame(self, text="Results")
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))

        self.tree = ttk.Treeview(table_frame, columns=TABLE_COLUMNS, show="headings")
        for col in TABLE_COLUMNS:
            self.tree.heading(col, text=col)
            if col == "path":
                self.tree.column(col, width=420, anchor="w")
            elif col == "hash":
                self.tree.column(col, width=360, anchor="w")
            elif col == "status":
                self.tree.column(col, width=110, anchor="center")
            elif col == "error":
                self.tree.column(col, width=240, anchor="w")
            else:
                self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, side="left")

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Row tag styles
        self._init_row_styles()

        # Log
        logf = ttk.LabelFrame(self, text="Log")
        logf.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.txt = tk.Text(logf, height=9, wrap="word",
                           bg=DARK["panel"], fg=DARK["fg"], insertbackground=DARK["fg"])
        self.txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.txt.configure(state="disabled")

    def _init_row_styles(self):
        # Apply tag-based row colors
        for status, cfg in STATUS_STYLES.items():
            tag = f"st_{status}"
            self.tree.tag_configure(tag,
                                    foreground=cfg.get("foreground",""),
                                    background=cfg.get("background",""))

    # -------- Scan tab --------
    def _build_scan_tab(self, parent):
        frm = ttk.Frame(parent)
        frm.pack(fill="x", expand=False, padx=8, pady=8)

        row = 0
        ttk.Label(frm, text="Target (file or folder):").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.scan_path_var, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_scan_path).grid(row=row, column=2)
        row += 1

        ttk.Label(frm, text="Algorithm:").grid(row=row, column=0, sticky="w")
        algo = ttk.Combobox(frm, textvariable=self.scan_algo_var, values=["sha256","sha1","md5"], width=10, state="readonly")
        algo.grid(row=row, column=1, sticky="w", padx=6)
        ttk.Checkbutton(frm, text="Recursive", variable=self.scan_recursive_var).grid(row=row, column=2, sticky="w")
        row += 1

        ttk.Label(frm, text="Output CSV:").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.scan_out_var, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Save as…", command=self._browse_scan_out).grid(row=row, column=2)
        row += 1

        ttk.Button(frm, text="Run Scan", command=self._run_scan).grid(row=row, column=0, columnspan=3, pady=6, sticky="we")
        frm.grid_columnconfigure(1, weight=1)

    # -------- Verify tab --------
    def _build_verify_tab(self, parent):
        frm = ttk.Frame(parent)
        frm.pack(fill="x", expand=False, padx=8, pady=8)

        row = 0
        ttk.Label(frm, text="Target (file or folder):").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.verify_path_var, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_verify_path).grid(row=row, column=2)
        row += 1

        ttk.Label(frm, text="Manifest CSV:").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.verify_manifest_var, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Choose…", command=self._browse_verify_manifest).grid(row=row, column=2)
        row += 1

        ttk.Label(frm, text="Algorithm:").grid(row=row, column=0, sticky="w")
        algo = ttk.Combobox(frm, textvariable=self.verify_algo_var, values=["sha256","sha1","md5"], width=10, state="readonly")
        algo.grid(row=row, column=1, sticky="w", padx=6)
        ttk.Checkbutton(frm, text="Recursive", variable=self.verify_recursive_var).grid(row=row, column=2, sticky="w")
        row += 1

        ttk.Label(frm, text="Output CSV:").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.verify_out_var, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Save as…", command=self._browse_verify_out).grid(row=row, column=2)
        row += 1

        ttk.Button(frm, text="Run Verify", command=self._run_verify).grid(row=row, column=0, columnspan=3, pady=6, sticky="we")
        frm.grid_columnconfigure(1, weight=1)

    # ---------- Browsers ----------
    def _browse_scan_path(self):
        path = filedialog.askopenfilename(title="Choose file to scan")
        if not path:
            path = filedialog.askdirectory(title="…or choose folder to scan")
        if path:
            self.scan_path_var.set(path)

    def _browse_scan_out(self):
        out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save manifest CSV as")
        if out:
            self.scan_out_var.set(out)

    def _browse_verify_path(self):
        path = filedialog.askopenfilename(title="Choose file to verify")
        if not path:
            path = filedialog.askdirectory(title="…or choose folder to verify")
        if path:
            self.verify_path_var.set(path)

    def _browse_verify_manifest(self):
        mf = filedialog.askopenfilename(filetypes=[("CSV","*.csv")], title="Choose manifest CSV")
        if mf:
            self.verify_manifest_var.set(mf)

    def _browse_verify_out(self):
        out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save verify report CSV as")
        if out:
            self.verify_out_var.set(out)

    # ---------- Run buttons ----------
    def _run_scan(self):
        try:
            opts = ScanOptions(
                path=Path(self.scan_path_var.get()).expanduser(),
                algo=self.scan_algo_var.get(),
                recursive=self.scan_recursive_var.get(),
                out_csv=Path(self.scan_out_var.get()).expanduser()
            )
        except Exception as e:
            messagebox.showerror("Invalid options", str(e)); return
        self._start_worker(self._worker_scan, opts)

    def _run_verify(self):
        try:
            opts = VerifyOptions(
                path=Path(self.verify_path_var.get()).expanduser(),
                manifest=Path(self.verify_manifest_var.get()).expanduser(),
                algo=self.verify_algo_var.get(),
                recursive=self.verify_recursive_var.get(),
                out_csv=Path(self.verify_out_var.get()).expanduser()
            )
        except Exception as e:
            messagebox.showerror("Invalid options", str(e)); return
        self._start_worker(self._worker_verify, opts)

    # ---------- Worker plumbing ----------
    def _start_worker(self, fn, opts):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Busy", "A job is already running."); return
        self.stop_flag.clear()
        self.progress.configure(mode="determinate", value=0, maximum=100)
        self.btn_stop.configure(state="normal")
        self._log_clear()
        self._table_clear()
        self._log("[*] Starting…")
        self.worker_thread = threading.Thread(target=self._wrap_worker, args=(fn, opts), daemon=True)
        self.worker_thread.start()

    def _wrap_worker(self, fn, opts):
        try:
            fn(opts)
        except Exception as e:
            self._log(f"[!] Error: {e}")
            tb = traceback.format_exc()
            self._log(tb)
        finally:
            self.msg_q.put("__DONE__")

    def _on_stop(self):
        self.stop_flag.set()
        self._log("[*] Stop requested…")

    def _poll_msgs(self):
        try:
            while True:
                msg = self.msg_q.get_nowait()
                if msg == "__PROGRESS__":
                    value, maximum = self._progress_cache
                    self.progress.configure(maximum=max(maximum, 1), value=min(value, maximum))
                elif msg == "__DONE__":
                    self.btn_stop.configure(state="disabled")
                    self._log("[*] Finished.")
                else:
                    self._log(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_msgs)

    def _log(self, text: str):
        self.txt.configure(state="normal")
        self.txt.insert("end", text + "\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _log_clear(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")

    def _table_clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)

    def _insert_row(self, rec: Dict[str,str]):
        # Fixed: don't try to iterate over tag_has method; just apply the tag unconditionally.
        values = tuple(rec.get(k, "") for k in TABLE_COLUMNS)
        status = (rec.get("status") or "").upper() or "BASELINE"
        tag = f"st_{status}"
        iid = self.tree.insert("", "end", values=values, tags=(tag,))
        self.tree.see(iid)

    def _set_progress(self, value: int, maximum: int):
        self._progress_cache = (value, maximum)
        self.msg_q.put("__PROGRESS__")

    # ---------- Core workers ----------
    def _collect_files(self, root: Path, recursive: bool) -> List[Path]:
        files: List[Path] = []
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            if recursive:
                for p in root.rglob("*"):
                    if p.is_file():
                        files.append(p)
            else:
                for p in root.iterdir():
                    if p.is_file():
                        files.append(p)
        return files

    def _write_compact_csv(self, rows: List[Dict[str,str]], out: Path):
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["run_started_utc","tool_version","host","os","algo","path","size_bytes","mtime_utc","hash","status","error"])
            run_started_utc = utc_iso(datetime.datetime.utcnow().timestamp())
            tool_version = "0.3.0"
            host = platform.node()
            osdesc = f"{platform.system()} {platform.release()}"
            for r in rows:
                w.writerow([
                    run_started_utc, tool_version, host, osdesc,
                    r.get("algo",""), r.get("path",""), r.get("size_bytes",""),
                    r.get("mtime_utc",""), r.get("hash",""), r.get("status",""), r.get("error","")
                ])

    def _worker_scan(self, opts: "ScanOptions"):
        files = self._collect_files(opts.path, opts.recursive)
        total = len(files)
        if total == 0:
            self._log("[!] No files found."); return

        rows: List[Dict[str, str]] = []
        for idx, p in enumerate(files, start=1):
            if self.stop_flag.is_set():
                self._log("[*] Stopped."); break
            try:
                rec = self.hashcheck.hash_file(p, opts.algo)
                rec["status"] = "BASELINE"
                rec["error"] = ""
            except Exception as e:
                rec = {
                    "path": str(p.resolve()), "size_bytes":"", "mtime_utc":"",
                    "algo": opts.algo, "hash":"", "status":"ERROR",
                    "error": f"{type(e).__name__}: {e}"
                }
            rows.append(rec)
            self._insert_row(rec)
            if idx % 25 == 0 or idx == total:
                self._set_progress(idx, total)

        self._write_compact_csv(rows, Path(opts.out_csv))
        self._log(f"[+] Wrote CSV: {opts.out_csv} ({len(rows)} rows)")

    def _worker_verify(self, opts: "VerifyOptions"):
        files = self._collect_files(opts.path, opts.recursive)
        total = len(files)
        if total == 0:
            self._log("[!] No files found."); return

        known = self.hashcheck.load_manifest(Path(opts.manifest))

        rows: List[Dict[str, str]] = []
        seen = set()
        ok=mismatch=new=missing=err=0

        for idx, p in enumerate(files, start=1):
            if self.stop_flag.is_set():
                self._log("[*] Stopped."); break
            try:
                rec = self.hashcheck.hash_file(p, opts.algo)
                kpath = str(Path(rec["path"]))
                if kpath in known:
                    expected = known[kpath]["hash"]
                    st = "OK" if rec["hash"] == expected else "MISMATCH"
                    rec["status"] = st
                    rec["error"] = "" if st=="OK" else f"expected {expected[:12]}…"
                    ok += (st=="OK")
                    mismatch += (st=="MISMATCH")
                else:
                    rec["status"] = "NEW"
                    rec["error"] = ""
                    new += 1
                rows.append(rec); seen.add(kpath)
                self._insert_row(rec)
            except Exception as e:
                e_rec = {
                    "path": str(p.resolve()), "size_bytes":"", "mtime_utc":"",
                    "algo": opts.algo, "hash":"", "status":"ERROR",
                    "error": f"{type(e).__name__}: {e}",
                }
                rows.append(e_rec)
                self._insert_row(e_rec)
                err += 1

            if idx % 25 == 0 or idx == total:
                self._set_progress(idx, total)

        # Add MISSING rows for files in manifest not present now
        for kpath, kentry in known.items():
            if self.stop_flag.is_set():
                break
            if kpath not in seen:
                m_rec = {
                    "path": kpath, "size_bytes":"", "mtime_utc":"",
                    "algo": kentry.get("algo", opts.algo),
                    "hash": kentry.get("hash",""),
                    "status":"MISSING",
                    "error": "",
                }
                rows.append(m_rec)
                self._insert_row(m_rec)
                missing += 1

        self._write_compact_csv(rows, Path(opts.out_csv))
        self._log(f"[+] Wrote CSV: {opts.out_csv} (OK={ok}, MISMATCH={mismatch}, NEW={new}, MISSING={missing}, ERROR={err})")

    # ---------- Export table ----------
    def _export_table_csv(self):
        out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Export table to CSV")
        if not out:
            return
        rows = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            row = {k: v for k, v in zip(TABLE_COLUMNS, vals)}
            rows.append(row)
        try:
            self._write_compact_csv(rows, Path(out))
            messagebox.showinfo("Export complete", f"Saved {len(rows)} rows to:\n{out}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

def main():
    # Find & load hashcheck.py
    module_path = None
    if len(sys.argv) > 1:
        p = Path(sys.argv[1]).expanduser()
        if p.exists():
            module_path = p
    if module_path is None:
        for cand in DEFAULT_HASHCHECK_CANDIDATES:
            if cand.exists():
                module_path = cand; break
    if module_path is None:
        messagebox.showerror("Missing hashcheck.py",
                             "Could not find hashcheck.py. Place it next to this GUI or pass a path as an argument.")
        sys.exit(1)

    try:
        hc = load_hashcheck_module(module_path)
    except Exception as e:
        messagebox.showerror("Load error", f"Failed to load hashcheck.py:\n{e}")
        sys.exit(1)

    app = HashCheckGUI(hc)
    app.mainloop()

if __name__ == "__main__":
    main()
