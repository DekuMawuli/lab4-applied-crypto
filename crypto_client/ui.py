"""tkinter shell: a ttk.Notebook with a Lab 3 tab (AES-GCM encrypt/decrypt,
custom HMAC compute/verify, unchanged from lab3) and a Lab 4 tab
(certificate fetch+verify, AES key generation, El Gamal key transport).
Only this module imports tkinter."""
import base64
import os
import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from crypto_client import cert, crypto_ops, net
from crypto_client.ca_info import load_ca_info
from crypto_client.companions import companion_path
from crypto_client.config import load_config
from crypto_client.crypto_ops import MAX_PLAINTEXT_LEN
from crypto_client.elgamal import encode_b64_string
from crypto_client.ui_common import WorkerPanel

CONFIG_DIR = Path(__file__).resolve().parent.parent
CA_INFO_PATH = CONFIG_DIR / "Pre_installed_CA_information.txt"

# spec section 4.1: cert_username is 1-32 chars from A-Z a-z 0-9 _ - (no dot)
CERT_USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


class Lab3Tab(ttk.Frame, WorkerPanel):
    """AES-GCM encrypt/decrypt and the custom HMAC compute/verify workflow,
    identical in behavior to lab3's ui.py, but sharing the connection
    fields with the parent app instead of owning them."""

    def __init__(self, parent, server_ip: tk.StringVar, port: tk.StringVar, username: tk.StringVar):
        super().__init__(parent)
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self._key: bytes | None = None
        self._base_file = tk.StringVar()

        self._init_worker_panel()
        self._build_widgets()

    def _build_widgets(self):
        pad = {"padx": 6, "pady": 3}
        row = 0

        ttk.Button(self, text="Get Key", command=self._on_get_key).grid(row=row, column=0, **pad)
        row += 1

        ttk.Label(self, text="Base file").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(self, textvariable=self._base_file, width=36).grid(row=row, column=1, columnspan=2, **pad)
        ttk.Button(self, text="Browse...", command=self._on_browse).grid(row=row, column=3, **pad)
        row += 1

        ttk.Button(self, text="Encrypt", command=self._on_encrypt).grid(row=row, column=0, **pad)
        ttk.Button(self, text="Decrypt", command=self._on_decrypt).grid(row=row, column=1, **pad)
        ttk.Button(self, text="Compute HMAC", command=self._on_compute_hmac).grid(row=row, column=2, **pad)
        ttk.Button(self, text="Verify HMAC", command=self._on_verify_hmac).grid(row=row, column=3, **pad)
        row += 1

        self._build_status_row(self, row)

    def _on_browse(self):
        path = filedialog.askopenfilename()
        if path:
            self._base_file.set(path)

    def _connection_fields(self):
        if not self.server_ip.get() or not self.username.get():
            self._set_status("error", "Server IP and username are required.")
            return None
        try:
            port = int(self.port.get())
        except ValueError:
            self._set_status("error", "Port must be a number.")
            return None
        return self.server_ip.get(), port, self.username.get()

    def _base_file_or_error(self):
        path = self._base_file.get()
        if not path or not os.path.exists(path):
            self._set_status("error", "Choose a file that exists first.")
            return None
        if os.path.getsize(path) > MAX_PLAINTEXT_LEN:
            self._set_status("error", f"File exceeds the {MAX_PLAINTEXT_LEN}-byte limit.")
            return None
        return path

    def _on_get_key(self):
        fields = self._connection_fields()
        if not fields:
            return
        host, port, username = fields

        def work():
            with net.connect(host, port) as sock:
                self._key = net.get_key(sock, username)
            return "ok", "Key fetched."

        self._run_in_background(work)

    def _on_encrypt(self):
        base = self._base_file_or_error()
        if base is None or self._key is None:
            if self._key is None:
                self._set_status("error", "Get a key first.")
            return

        def work():
            with open(base, "rb") as f:
                plaintext = f.read()
            encrypted = crypto_ops.encrypt_file(self._key, plaintext)
            Path(companion_path(base, "enc")).write_bytes(encrypted)
            Path(companion_path(base, "key")).write_text(base64.b64encode(self._key).decode())
            return "ok", f"Encrypted -> {companion_path(base, 'enc')}"

        self._run_in_background(work)

    def _on_decrypt(self):
        fields = self._connection_fields()
        base = self._base_file_or_error()
        if not fields or base is None:
            return
        host, port, username = fields

        def work():
            key = base64.b64decode(Path(companion_path(base, "key")).read_text())
            encrypted = Path(companion_path(base, "enc")).read_bytes()
            with net.connect(host, port) as sock:
                decrypted = net.decrypt(sock, username, key, encrypted)
            out_path = companion_path(base, "dec")
            Path(out_path).write_bytes(decrypted)
            return "ok", f"Decrypted -> {out_path}"

        self._run_in_background(work)

    def _on_compute_hmac(self):
        base = self._base_file_or_error()
        if base is None or self._key is None:
            if self._key is None:
                self._set_status("error", "Get a key first.")
            return

        def work():
            file_bytes = Path(base).read_bytes()
            mac = crypto_ops.custom_hmac(self._key, file_bytes)
            Path(companion_path(base, "hmac")).write_text(base64.b64encode(mac).decode())
            Path(companion_path(base, "hmackey")).write_text(base64.b64encode(self._key).decode())
            return "ok", f"HMAC written -> {companion_path(base, 'hmac')}"

        self._run_in_background(work)

    def _on_verify_hmac(self):
        fields = self._connection_fields()
        base = self._base_file_or_error()
        if not fields or base is None:
            return
        host, port, username = fields

        def work():
            key = base64.b64decode(Path(companion_path(base, "hmackey")).read_text())
            mac = base64.b64decode(Path(companion_path(base, "hmac")).read_text())
            file_bytes = Path(base).read_bytes()
            with net.connect(host, port) as sock:
                result = net.verify_hmac(sock, username, key, mac, file_bytes)
            if result == "VERIFIED":
                return "verified", "VERIFIED"
            return "failed", "FAILED (HMAC did not match)"

        self._run_in_background(work)


class Lab4Tab(ttk.Frame, WorkerPanel):
    """Certificate fetch+verify and El Gamal key transport (Lab 4)."""

    def __init__(self, parent, server_ip: tk.StringVar, port: tk.StringVar, username: tk.StringVar):
        super().__init__(parent)
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.cert_username = tk.StringVar()
        self._aes_key_b64: str | None = None
        self._verified_cert: cert.Certificate | None = None
        self._ca_info = load_ca_info(CA_INFO_PATH)

        self._init_worker_panel()
        self._build_widgets()

    def _build_widgets(self):
        pad = {"padx": 6, "pady": 3}
        row = 0

        ttk.Label(self, text="Recipient Andrew ID").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(self, textvariable=self.cert_username, width=20).grid(row=row, column=1, **pad)
        ttk.Button(self, text="Get Certificate", command=self._on_get_certificate).grid(row=row, column=2, **pad)
        row += 1

        ttk.Button(self, text="Generate AES Key", command=self._on_generate_aes_key).grid(row=row, column=0, **pad)
        ttk.Button(
            self, text="Encrypt Key for Recipient", command=self._on_encrypt_key_for_recipient
        ).grid(row=row, column=1, columnspan=2, **pad)
        row += 1

        self._build_status_row(self, row)

    def _connection_fields(self):
        if not self.server_ip.get() or not self.username.get():
            self._set_status("error", "Server IP and username are required.")
            return None
        try:
            port = int(self.port.get())
        except ValueError:
            self._set_status("error", "Port must be a number.")
            return None
        return self.server_ip.get(), port, self.username.get()

    def _on_get_certificate(self):
        fields = self._connection_fields()
        cert_username = self.cert_username.get().strip()
        if not fields or not cert_username:
            self._set_status("error", "Server IP, username, and recipient Andrew ID are required.")
            return
        if not CERT_USERNAME_RE.fullmatch(cert_username):
            self._set_status(
                "error", "Recipient Andrew ID must be 1-32 characters from A-Z a-z 0-9 _ -"
            )
            return
        host, port, username = fields

        # Clear any previously verified certificate before this fetch even starts: if this
        # fetch fails or is for a different recipient, a stale public key for someone else
        # must never be left behind for "Encrypt Key for Recipient" to pick up.
        self._verified_cert = None

        def work():
            with net.connect(host, port) as sock:
                cert_bytes = net.get_certificate(sock, username, cert_username)
            if cert_bytes is None:
                return "error", "no certificate for that user"
            try:
                certificate = cert.verify_certificate(cert_bytes, cert_username, self._ca_info)
            except cert.CertificateError as e:
                return "error", f"certificate rejected: {e}"
            self._verified_cert = certificate
            return "ok", f"Verified: {certificate.username}, pubkey={certificate.public_key}"

        self._run_in_background(work)

    def _on_generate_aes_key(self):
        self._aes_key_b64 = crypto_ops.generate_aes_key_b64()
        out_path = str(CONFIG_DIR / "aes_key.b64.txt")
        Path(out_path).write_text(self._aes_key_b64)
        self._set_status("ok", f"Key written -> {out_path}")

    def _on_encrypt_key_for_recipient(self):
        if self._aes_key_b64 is None:
            self._set_status("error", "Generate an AES key first.")
            return
        if self._verified_cert is None:
            self._set_status("error", "Get a verified certificate first.")
            return

        lines = encode_b64_string(
            self._aes_key_b64, self._verified_cert.public_key, self._ca_info.p, self._ca_info.alpha
        )
        # Named from the verified certificate's own username, not the live entry field --
        # they can differ if the field was edited after the last successful fetch.
        out_path = str(CONFIG_DIR / f"{self._verified_cert.username}_encrypted_key.txt")
        Path(out_path).write_bytes(("\r\n".join(lines) + "\r\n").encode("ascii"))
        self._set_status("ok", f"Encrypted -> {out_path}")


class CryptoClientApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Crypto Client")

        config = load_config(
            CONFIG_DIR / "config.local.json",
            fallback=CONFIG_DIR / "config.example.json",
        )

        pad = {"padx": 6, "pady": 3}
        self.server_ip = tk.StringVar(value=config.get("server_ip", ""))
        self.port = tk.StringVar(value=str(config.get("port", 8080)))
        self.username = tk.StringVar(value=config.get("username", ""))

        ttk.Label(root, text="Server IP").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(root, textvariable=self.server_ip, width=20).grid(row=0, column=1, **pad)
        ttk.Label(root, text="Port").grid(row=0, column=2, sticky="w", **pad)
        ttk.Entry(root, textvariable=self.port, width=8).grid(row=0, column=3, **pad)
        ttk.Label(root, text="Username").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(root, textvariable=self.username, width=20).grid(row=1, column=1, **pad)

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=2, column=0, columnspan=4, sticky="nsew", **pad)

        self.lab3_tab = Lab3Tab(self.notebook, self.server_ip, self.port, self.username)
        self.lab4_tab = Lab4Tab(self.notebook, self.server_ip, self.port, self.username)
        self.notebook.add(self.lab3_tab, text="Lab 3")
        self.notebook.add(self.lab4_tab, text="Lab 4")


def main():
    root = tk.Tk()
    CryptoClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
