"""Thread/queue/status plumbing shared by every tab, lifted from lab3's
ui.py (where it lived inline in CryptoClientApp) so both the Lab 3 and
Lab 4 tabs can reuse it instead of duplicating it. Every network/crypto
call runs in a worker thread; results come back through a queue polled
with root.after, so the window never blocks."""
import queue
import threading
import tkinter as tk
from tkinter import ttk

# "" leaves "ok" at the theme's default label color, so it stays
# readable in both light and dark mode instead of a hardcoded black
# that disappears against a dark background.
_STATUS_COLORS = {"error": "#e05252", "failed": "#e0a030", "verified": "#4caf50", "ok": ""}


class WorkerPanel:
    """Mixin for a ttk.Frame subclass. Call _init_worker_panel() once in
    __init__ and _build_status_row(parent, row) to lay out the progress
    bar + status label."""

    def _init_worker_panel(self):
        self._queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self.status = tk.StringVar(value="Ready.")
        self.winfo_toplevel().after(50, self._poll_queue)

    def _build_status_row(self, parent, row):
        pad = {"padx": 6, "pady": 3}
        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.grid(row=row, column=0, columnspan=4, sticky="ew", **pad)
        self.status_label = ttk.Label(parent, textvariable=self.status)
        self.status_label.grid(row=row + 1, column=0, columnspan=4, sticky="w", **pad)

    def _set_status(self, kind: str, text: str):
        self.status.set(text)
        self.status_label.configure(foreground=_STATUS_COLORS.get(kind, ""))

    def _run_in_background(self, fn):
        """fn runs on a worker thread and must not touch any Tk widget or
        variable directly; it returns (kind, status_text) and the result
        is applied to the UI on the main thread by _poll_queue."""
        self.progress.start(10)
        threading.Thread(target=self._worker, args=(fn,), daemon=True).start()

    def _worker(self, fn):
        from crypto_client import net

        try:
            kind, text = fn()
        except net.ServerError as e:
            kind, text = "error", f"error: {e}"
        except Exception as e:
            kind, text = "error", str(e)
        self._queue.put((kind, text))

    def _poll_queue(self):
        try:
            while True:
                kind, text = self._queue.get_nowait()
                self.progress.stop()
                self._set_status(kind, text)
        except queue.Empty:
            pass
        self.winfo_toplevel().after(50, self._poll_queue)
