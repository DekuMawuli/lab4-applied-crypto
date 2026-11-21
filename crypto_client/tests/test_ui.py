import tkinter as tk

import pytest

from crypto_client.ui import CryptoClientApp


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
