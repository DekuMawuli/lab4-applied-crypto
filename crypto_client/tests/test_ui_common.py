import time
import tkinter as tk
from tkinter import ttk

import pytest

from crypto_client.ui_common import WorkerPanel


@pytest.fixture
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    yield root
    root.destroy()


def test_run_in_background_updates_status_via_queue(tk_root):
    panel = ttk.Frame(tk_root)
    panel.__class__ = type("P", (ttk.Frame, WorkerPanel), {})
    panel._init_worker_panel()
    panel._build_status_row(panel, 0)

    panel._run_in_background(lambda: ("ok", "done"))
    tk_root.update()
    time.sleep(0.2)
    panel._poll_queue()
    assert panel.status.get() == "done"
