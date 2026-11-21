import tkinter as tk

import pytest

from crypto_client import cert as cert_module
from crypto_client.ui import CryptoClientApp, Lab4Tab


@pytest.fixture
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    yield root
    root.destroy()


def test_app_builds_two_tabs(tk_root):
    app = CryptoClientApp(tk_root)
    tab_texts = [app.notebook.tab(i, "text") for i in range(app.notebook.index("end"))]
    assert tab_texts == ["Lab 3", "Lab 4"]


class _NullConnection:
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


def _make_lab4_tab(tk_root):
    return Lab4Tab(
        tk_root,
        server_ip=tk.StringVar(value="127.0.0.1"),
        port=tk.StringVar(value="8080"),
        username=tk.StringVar(value="me"),
    )


def test_get_certificate_clears_stale_verified_cert_before_fetching(tk_root, monkeypatch):
    tab = _make_lab4_tab(tk_root)
    stale = cert_module.Certificate(p=tab._ca_info.p, alpha=tab._ca_info.alpha, username="alice", public_key=42)
    tab._verified_cert = stale
    tab.cert_username.set("bob")

    monkeypatch.setattr("crypto_client.ui.net.connect", lambda *a, **k: _NullConnection())
    monkeypatch.setattr("crypto_client.ui.net.get_certificate", lambda *a, **k: None)

    tab._on_get_certificate()

    assert tab._verified_cert is None, "a stale certificate for a different recipient must not survive a new fetch"


def test_encrypt_key_names_file_from_verified_certificate_not_the_live_entry(tk_root, monkeypatch, tmp_path):
    tab = _make_lab4_tab(tk_root)
    tab._aes_key_b64 = "A" * 43 + "="
    tab._verified_cert = cert_module.Certificate(
        p=tab._ca_info.p, alpha=tab._ca_info.alpha, username="bob", public_key=5
    )
    tab.cert_username.set("not-bob")  # the live field no longer matches the verified cert

    monkeypatch.setattr("crypto_client.ui.CONFIG_DIR", tmp_path)

    tab._on_encrypt_key_for_recipient()

    assert (tmp_path / "bob_encrypted_key.txt").exists()
    assert not (tmp_path / "not-bob_encrypted_key.txt").exists()


def test_encrypt_key_writes_crlf_line_endings_as_bytes(tk_root, monkeypatch, tmp_path):
    tab = _make_lab4_tab(tk_root)
    tab._aes_key_b64 = "A" * 43 + "="
    tab._verified_cert = cert_module.Certificate(
        p=tab._ca_info.p, alpha=tab._ca_info.alpha, username="bob", public_key=5
    )
    monkeypatch.setattr("crypto_client.ui.CONFIG_DIR", tmp_path)

    tab._on_encrypt_key_for_recipient()

    raw = (tmp_path / "bob_encrypted_key.txt").read_bytes()
    assert raw.count(b"\r\n") == 11
    assert b"\r\r\n" not in raw


def test_get_certificate_rejects_malformed_cert_username(tk_root):
    tab = _make_lab4_tab(tk_root)
    tab.cert_username.set("not a valid id!")

    tab._on_get_certificate()

    assert "1-32 characters" in tab.status.get()
