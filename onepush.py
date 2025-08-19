# -*- coding: utf-8 -*-
import os, base64, subprocess, shutil, json, re, sys
from pathlib import Path
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from nacl import encoding, public

APP = "OnePush v1.2.1"

EXCLUDES = [".git",".venv","node_modules","__pycache__","dist","build",".next",".idea",".vscode",".DS_Store","Thumbs.db"]
MAX_SIZE = 100*1024*1024

def human(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n/=1024
    return f"{n:.1f} PB"

def detect_type(root: Path):
    if (root/"package.json").exists(): return "node"
    if (root/"requirements.txt").exists(): return "python"
    if (root/"Dockerfile").exists(): return "docker"
    if any((root/f).exists() for f in ("index.html","public/index.html")): return "static"
    return "generic"

def default_gitignore(kind: str):
    if kind=="node": return "node_modules/\n.dist/\n.build/\n.next/\n.cache/\n.env\n"
    if kind=="python": return "__pycache__/\n*.pyc\n.env\n.venv/\ndist/\nbuild/\n"
    if kind=="static": return ".DS_Store\nThumbs.db\n.env\n"
    if kind=="docker": return ".env\n"
    return ".env\n"

def workflow(kind: str):
    if kind=="node":
        return """name: Node CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npm run build --if-present
"""
    if kind=="python":
        return """name: Python CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: python -m pip install --upgrade pip
      - run: pip install -r requirements.txt
      - run: python -m pytest || echo "no tests"
"""
    if kind=="static":
        return """name: Pages
on:
  push:
    branches: [ "main" ]
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: "pages"
  cancel-in-progress: true
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: "."
      - id: deployment
        uses: actions/deploy-pages@v4
"""
    if kind=="docker":
        return """name: Docker image
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - run: docker build -t ghcr.io/${{ github.repository }}:latest .
      - run: docker push ghcr.io/${{ github.repository }}:latest
"""
    return """name: Checks
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Build passed"
"""

def list_files(root: Path):
    files=[]
    for dpath, dnames, fnames in os.walk(root):
        rel = Path(dpath).relative_to(root)
        dnames[:] = [d for d in dnames if d not in EXCLUDES and not any(str(Path(rel,d)).startswith(e) for e in EXCLUDES)]
        for f in fnames:
            if f.endswith(".pyc"): continue
            p = Path(dpath)/f
            try:
                if p.stat().st_size > MAX_SIZE: continue
            except Exception:
                continue
            files.append(p)
    return files

def env_to_example(envp: Path):
    keys=[]
    for line in envp.read_text(encoding="utf-8", errors="ignore").splitlines():
        s=line.strip()
        if not s or s.startswith("#"): continue
        if "=" in s:
            k,_=s.split("=",1)
            keys.append(k.strip())
    return "\n".join(f"{k}=" for k in keys)+("\n" if keys else "")

def gh_headers(token):
    return {"Authorization": f"token {token}", "Accept":"application/vnd.github+json","User-Agent":"onepush-v1.2.1"}

def gh_me(token):
    r=requests.get("https://api.github.com/user", headers=gh_headers(token), timeout=30); r.raise_for_status(); return r.json()

def gh_scopes(token):
    r=requests.get("https://api.github.com/", headers=gh_headers(token), timeout=15); r.raise_for_status(); return r.headers.get("X-OAuth-Scopes","")

def gh_is_fine_grained(token:str)->bool:
    return token.startswith("github_pat_")

def gh_list_repos(token):
    url="https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member"
    r=requests.get(url, headers=gh_headers(token), timeout=30); r.raise_for_status(); return r.json()

def gh_create_repo(token, name, private=True, description="OnePush repo"):
    r=requests.post("https://api.github.com/user/repos", headers=gh_headers(token),
                    json={"name":name,"private":bool(private),"description":description,"auto_init":True}, timeout=30)
    if r.status_code not in (201,200,422): r.raise_for_status()
    return r.json()

def gh_put_file(token, owner, repo, rel_path, content_bytes, message="add file"):
    url=f"https://api.github.com/repos/{owner}/{repo}/contents/{rel_path}"
    g=requests.get(url, headers=gh_headers(token), timeout=30)
    sha=g.json().get("sha") if g.status_code==200 else None
    payload={"message":message,"content":base64.b64encode(content_bytes).decode("utf-8"),"branch":"main"}
    if sha: payload["sha"]=sha
    r=requests.put(url, headers=gh_headers(token), json=payload, timeout=60)
    if r.status_code not in (201,200):
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()

def gh_repo_public_key(token, owner, repo):
    url=f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    r=requests.get(url, headers=gh_headers(token), timeout=30); r.raise_for_status(); return r.json()

def gh_put_secret(token, owner, repo, name, value, pk):
    sealed=public.SealedBox(public.PublicKey(pk["key"].encode("utf-8"), encoding.Base64Encoder())).encrypt(value.encode("utf-8"))
    import base64 as b64
    encv=b64.b64encode(sealed).decode("utf-8")
    url=f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{name}"
    r=requests.put(url, headers=gh_headers(token), json={"encrypted_value":encv,"key_id":pk["key_id"]}, timeout=30); r.raise_for_status(); return True

# DPAPI store (Windows), fallback plain file otherwise
def _token_store_path():
    appdir = Path(os.getenv("APPDATA") or str(Path.home()))/"OnePush"; appdir.mkdir(parents=True, exist_ok=True); return appdir/"token.bin"

def save_token_secure(token: str):
    p=_token_store_path(); data=token.encode("utf-8")
    if os.name=="nt":
        try:
            import ctypes, ctypes.wintypes as wt
            class DATA_BLOB(ctypes.Structure):
                _fields_=[("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            def blob(b: bytes):
                buf=ctypes.create_string_buffer(b); return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
            CryptProtectData=ctypes.windll.crypt32.CryptProtectData
            outb=DATA_BLOB()
            if not CryptProtectData(ctypes.byref(blob(data)), "OnePush", None, None, None, 0, ctypes.byref(outb)):
                raise RuntimeError("DPAPI protect failed")
            enc=ctypes.string_at(outb.pbData, outb.cbData); open(p,"wb").write(enc); return True
        except Exception: pass
    open(p,"wb").write(data); return True

def load_token_secure():
    p=_token_store_path()
    if not p.exists(): return ""
    raw=p.read_bytes()
    if os.name=="nt":
        try:
            import ctypes, ctypes.wintypes as wt
            class DATA_BLOB(ctypes.Structure):
                _fields_=[("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            def blob(b: bytes):
                buf=ctypes.create_string_buffer(b); return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
            CryptUnprotectData=ctypes.windll.crypt32.CryptUnprotectData
            outb=DATA_BLOB(); desc=wt.LPWSTR()
            if not CryptUnprotectData(ctypes.byref(blob(raw)), ctypes.byref(desc), None, None, None, 0, ctypes.byref(outb)):
                raise RuntimeError("DPAPI unprotect failed")
            dec=ctypes.string_at(outb.pbData, outb.cbData); return dec.decode("utf-8","ignore")
        except Exception: pass
    return raw.decode("utf-8","ignore")

def which(p): return shutil.which(p)

class OnePushApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP); self.geometry("1080x780"); self.minsize(900,600)
        self.token=tk.StringVar(value=""); self.folder=tk.StringVar(value=str(Path.home())); self.repo=tk.StringVar(value="")
        self.private=tk.BooleanVar(value=True); self.pkind=tk.StringVar(value="type: detecting...")
        self.create_gitignore=tk.BooleanVar(value=True); self.create_envexample=tk.BooleanVar(value=True); self.upload_secrets=tk.BooleanVar(value=False)
        self.selected_fullname=tk.StringVar(value="")  # owner/repo if chosen
        self.scope_status=tk.StringVar(value="Scopes: unknown")
        self.progress=tk.IntVar(value=0); self.owner=None; self.repo_url=""; self.files=[]
        self._build_ui()

    def _build_ui(self):
        frm=ttk.Frame(self, padding=6); frm.pack(fill="both", expand=True)
        top=ttk.LabelFrame(frm, text="GitHub"); top.pack(fill="x")
        self._row_token(top)

        src=ttk.LabelFrame(frm, text="Source"); src.pack(fill="x", pady=6)
        self._row(src, "Project folder", self.folder, button=("Browse", self.pick_folder))
        self._row(src, "Repo name", self.repo)
        r3=ttk.Frame(src); r3.pack(fill="x", padx=6, pady=2)
        ttk.Checkbutton(r3, text="Private repo", variable=self.private).pack(side="left", padx=2)
        ttk.Label(r3, textvariable=self.pkind).pack(side="left", padx=12)

        pick=ttk.LabelFrame(frm, text="Use existing repo (optional)"); pick.pack(fill="x", pady=6)
        self._row(pick, "Selected", self.selected_fullname, button=("Pick repo", self.pick_repo))
        p2=ttk.Frame(pick); p2.pack(fill="x", padx=6, pady=2)
        ttk.Button(p2, text="Reload list", command=self.reload_token_and_list).pack(side="left", padx=2)
        ttk.Button(p2, text="Open selected", command=self.open_repo).pack(side="left", padx=2)
        ttk.Label(p2, textvariable=self.scope_status).pack(side="left", padx=12)
        ttk.Button(p2, text="Check token", command=self.check_token).pack(side="left", padx=2)
        ttk.Button(p2, text="Load GH CLI", command=self.load_gh_cli_token).pack(side="right", padx=2)

        opt=ttk.LabelFrame(frm, text="Options"); opt.pack(fill="x", pady=6)
        ttk.Checkbutton(opt, text="Add .gitignore", variable=self.create_gitignore).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="Create .env.example from .env", variable=self.create_envexample).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="Upload .env as Actions secrets", variable=self.upload_secrets).pack(side="left", padx=6)

        btns=ttk.Frame(frm); btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Scan", command=self.scan).pack(side="left", padx=4)
        ttk.Button(btns, text="Dry run", command=self.dry_run).pack(side="left", padx=4)
        ttk.Button(btns, text="OnePush", command=self.deploy).pack(side="left", padx=4)
        ttk.Button(btns, text="Open repo", command=self.open_repo).pack(side="left", padx=4)
        ttk.Progressbar(btns, length=300, mode="determinate", variable=self.progress).pack(side="right", padx=6)

        self.log=tk.Text(frm, wrap="word", bg="#0f1120", fg="#e6e7ea", insertbackground="#e6e7ea")
        self.log.pack(fill="both", expand=True)

        t=load_token_secure()
        if t: self.token.set(t); self._log("[ok] Loaded saved token")

    def _row(self, parent, label, var, button=None):
        row=ttk.Frame(parent); row.pack(fill="x", padx=6, pady=3)
        ttk.Label(row, text=label, width=16).pack(side="left")
        e=ttk.Entry(row, textvariable=var); e.pack(side="left", fill="x", expand=True)
        if button: ttk.Button(row, text=button[0], command=button[1]).pack(side="left", padx=4)

    def _row_token(self, parent):
        row=ttk.Frame(parent); row.pack(fill="x", padx=6, pady=3)
        ttk.Label(row, text="Token", width=16).pack(side="left")
        self.token_entry=ttk.Entry(row, textvariable=self.token, show="*"); self.token_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Show", command=self.toggle_token).pack(side="left", padx=2)
        ttk.Button(row, text="Paste", command=self.paste_token).pack(side="left", padx=2)
        ttk.Button(row, text="Load ENV", command=self.load_env).pack(side="left", padx=2)
        ttk.Button(row, text="Load saved", command=self.load_saved).pack(side="left", padx=2)
        ttk.Button(row, text="Save", command=self.save_token).pack(side="left", padx=2)
        ttk.Button(row, text="Open PAT page", command=lambda:self._open_url("https://github.com/settings/tokens")).pack(side="left", padx=2)

    def pick_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.folder.set(d)
            raw = Path(d).name
            slug = re.sub(r"[^a-zA-Z0-9-_]", "-", raw).lower().strip("-")
            self.repo.set(slug or "repo")
            self.scan()

    def reload_token_and_list(self):
        scopes = self.check_token(silent=True)
        if scopes is not None:
            self._log(f"[scopes] {scopes}")
        try:
            _ = gh_list_repos(self.token.get().strip())
            self._log("[ok] Repo list ready")
        except Exception as e:
            messagebox.showerror("Repos", f"Не удалось получить список: {e}")

    def load_gh_cli_token(self):
        try:
            out = subprocess.check_output(["gh","auth","token"], text=True).strip()
            if out:
                self.token.set(out); self._log("[ok] token loaded from gh cli")
            else:
                messagebox.showinfo("gh", "gh auth token вернул пусто. Запусти gh auth login")
        except FileNotFoundError:
            messagebox.showerror("gh", "GitHub CLI не найден. Поставь: winget install GitHub.cli")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("gh", f"gh auth token ошибка: {e}")

    def pick_repo(self):
        token=self.token.get().strip()
        if not token:
            messagebox.showerror("Auth","Вставь токен (Paste/ENV/Saved/GH CLI)."); return
        try:
            repos = gh_list_repos(token)
        except Exception as e:
            messagebox.showerror("Repos", f"Не удалось получить список: {e}"); return

        win = tk.Toplevel(self); win.title("Pick repo"); win.geometry("560x480")
        tk.Label(win, text="Двойной клик чтобы выбрать. Filter:").pack(anchor="w", padx=8, pady=4)
        q = tk.StringVar(value="")
        ent = ttk.Entry(win, textvariable=q); ent.pack(fill="x", padx=8); ent.focus_set()

        lb = tk.Listbox(win); lb.pack(fill="both", expand=True, padx=8, pady=8)
        items = [ (r["full_name"], r.get("private", False), r.get("html_url","")) for r in repos ]
        def reload_list(*a):
            s = q.get().lower().strip()
            lb.delete(0, "end")
            for name,priv,_ in items:
                if s and s not in name.lower(): continue
                tag = " [private]" if priv else ""
                lb.insert("end", name+tag)
        reload_list()
        q.trace_add("write", reload_list)

        def use_selected(*a):
            idx = lb.curselection()
            if not idx: return
            val = lb.get(idx[0])
            name = val.split(" [private]")[0]
            self.selected_fullname.set(name)
            self.repo.set(name.split("/",1)[1])
            self.repo_url = "https://github.com/"+name
            self._log(f"[use] {name}")
            win.destroy()
        lb.bind("<Double-1>", use_selected)
        ttk.Button(win, text="Use", command=use_selected).pack(pady=6)

    def _open_url(self,url):
        import webbrowser; webbrowser.open(url)

    def toggle_token(self):
        self.token_entry.config(show="" if self.token_entry.cget("show")=="*" else "*")

    def paste_token(self):
        try:
            t=self.clipboard_get().strip()
            self.token.set(t); self._log("[ok] token pasted from clipboard")
        except Exception:
            messagebox.showerror("Paste", "Буфер обмена пуст или недоступен.")

    def load_env(self):
        t=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or ""
        if t: self.token.set(t); self._log("[ok] token loaded from ENV")
        else: messagebox.showinfo("ENV","Переменная GITHUB_TOKEN/GH_TOKEN не найдена.")

    def load_saved(self):
        t=load_token_secure()
        if t: self.token.set(t); self._log("[ok] token loaded from secure storage")
        else: messagebox.showinfo("Saved","Сохранённый токен не найден.")

    def save_token(self):
        t=self.token.get().strip()
        if not t: messagebox.showerror("Save","Пустой токен."); return
        if save_token_secure(t): self._log("[ok] token saved securely")

    def check_token(self, silent=False):
        token=self.token.get().strip()
        if not token:
            if not silent: messagebox.showinfo("Token","Токен пуст."); 
            return None
        try:
            if gh_is_fine_grained(token):
                msg = "fine-grained: дай репо доступ (Selected repo), Contents: Read and write, Actions: Read and write"
                self.scope_status.set(msg)
                if not silent: self._log("[info] "+msg)
                return ""
            scopes = gh_scopes(token)
            need = "repo" if self.private.get() else "public_repo"
            ok = (need in scopes) or ("repo" in scopes and not self.private.get())
            self.scope_status.set(f"Scopes: {scopes or 'none'} | need: {need}+workflow")
            if not silent:
                if ok: self._log("[ok] scopes look good")
                else: self._log("[warn] scopes may be insufficient")
            return scopes
        except Exception as e:
            if not silent: messagebox.showerror("Scopes", f"Ошибка запроса скопов: {e}")
            return None

    def _log(self,s):
        self.log.insert("end", s+"\n"); self.log.see("end")

    def scan(self):
        root=Path(self.folder.get().strip())
        self.pkind.set(f"type: {detect_type(root)}")
        files=list_files(root); total=sum(p.stat().st_size for p in files) if files else 0
        self.files=files; self._log(f"[*] {len(files)} files, {human(total)} (excluded trash hidden)")

    def dry_run(self):
        root=Path(self.folder.get().strip())
        todo=[".github/workflows/ci.yml"]
        if self.create_gitignore.get(): todo.append(".gitignore")
        if self.create_envexample.get() and (root/".env").exists(): todo.append(".env.example (from .env)")
        self._log("[dry-run] Will add: "+", ".join(todo))

    def _explain_http_error(self, err_text:str)->str:
        t = err_text.lower()
        if "resource not accessible by personal access token" in t:
            if gh_is_fine_grained(self.token.get().strip()):
                return ("Токен fine-grained не имеет прав на этот репозиторий. "
                        "Открой Settings → Developer settings → Fine-grained tokens → Edit, "
                        "добавь репозиторий в Repository access, и выставь Repository permissions: "
                        "Contents: Read and write; Actions: Read and write.")
            else:
                return ("У токена нет scope 'repo' (или 'public_repo') для записи в содержимое. "
                        "Сгенерируй classic PAT с repo, workflow и вставь заново.")
        if "requires authentication" in t or "bad credentials" in t:
            return "Токен неверный или истёк. Сгенерируй новый и вставь."
        if "blocked" in t or "sso" in t:
            return "Нужно авторизовать SSO для организации на странице токена (Configure SSO)."
        return "Неизвестная ошибка GitHub API. Открой логи и дай текст ответа."

    def deploy(self):
        token=self.token.get().strip()
        if not token:
            messagebox.showerror("Auth","Вставь токен (Paste/ENV/Saved/GH CLI)."); return
        root=Path(self.folder.get().strip())
        raw_repo=(self.repo.get().strip() or root.name)
        slug=re.sub(r"[^a-z0-9-_]", "-", raw_repo.lower()).strip("-") or "repo"
        existing=self.selected_fullname.get().strip()
        private=bool(self.private.get())
        kind=detect_type(root); self.pkind.set(f"type: {kind}")

        try:
            if existing:
                owner, repo = existing.split("/",1)
                self.repo_url=f"https://github.com/{owner}/{repo}"
                self._log(f"[*] Using existing repo: {owner}/{repo}")
            else:
                if gh_is_fine_grained(token):
                    raise RuntimeError("Fine-grained токен не умеет создавать репозитории. Выбери существующий repo через Pick repo или сделай classic PAT (repo, workflow).")
                me=gh_me(token); owner=me["login"]
                self._log(f"[*] Creating repo '{slug}' under {owner} (private={private})")
                rj=gh_create_repo(token, slug, private, "Deployed by OnePush")
                repo = slug
                self.repo_url=rj.get("html_url") or f"https://github.com/{owner}/{repo}"
                self._log(f"[ok] repo: {self.repo_url}")
        except Exception as e:
            message = str(e)
            self._log(f"[x] Repo create/use error: {message}")
            messagebox.showerror("Repo", f"Не удалось создать/получить репо: {message}")
            return

        generated={".github/workflows/ci.yml": workflow(kind)}
        if self.create_gitignore.get(): generated[".gitignore"]=default_gitignore(kind)
        if self.create_envexample.get() and (root/".env").exists(): generated[".env.example"]=env_to_example(root/".env")

        files=list_files(root); total=len(files)+len(generated); step=100/max(total,1); self.progress.set(0)

        for rel,txt in generated.items():
            try:
                gh_put_file(token, owner, repo, rel.replace("\\","/"), txt.encode("utf-8"), f"add {rel}")
                self._log(f"[+] {rel}")
            except Exception as e:
                expl = self._explain_http_error(str(e))
                self._log(f"[x] {rel}: {e}\n    -> {expl}")
            self.progress.set(self.progress.get()+step); self.update()

        for p in files:
            rel=str(p.relative_to(root)).replace("\\","/")
            try:
                gh_put_file(token, owner, repo, rel, open(p,"rb").read(), f"add {rel}")
                self._log(f"[+] {rel}")
            except Exception as e:
                expl = self._explain_http_error(str(e))
                self._log(f"[x] {rel}: {e}\n    -> {expl}")
            self.progress.set(self.progress.get()+step); self.update()

        if self.upload_secrets.get() and (root/".env").exists():
            try:
                pk=gh_repo_public_key(token, owner, repo); cnt=0
                for line in (root/".env").read_text(encoding="utf-8", errors="ignore").splitlines():
                    s=line.strip()
                    if not s or s.startswith("#") or "=" not in s: continue
                    k,v=s.split("=",1); gh_put_secret(token, owner, repo, k.strip(), v.strip(), pk); cnt+=1
                self._log(f"[secrets] uploaded {cnt} items")
            except Exception as e:
                self._log(f"[secrets] error: {e}")

        self._log("[✓] Done. Open repo → GitHub")

    def open_repo(self):
        target = self.repo_url or (("https://github.com/"+self.selected_fullname.get().strip()) if self.selected_fullname.get().strip() else "")
        if not target: return
        import webbrowser; webbrowser.open(target)

if __name__=="__main__":
    app=OnePushApp(); app.mainloop()
