"""One-off script to drive the real tkinter UI through the Lab 4 workflow
against the real server and screenshot the actual window at each step. Not
part of the submitted client code -- a demo/evidence harness only."""
import subprocess
import time
import tkinter as tk
from pathlib import Path

from crypto_client.ui import CryptoClientApp

ROOT_DIR = Path(__file__).resolve().parent.parent.parent  # lab4/
SHOT_DIR = Path(__file__).resolve().parent
BASE_FILE = str(ROOT_DIR / "results" / "sample.txt")


def screenshot(root: tk.Tk, name: str):
    root.update()
    x = root.winfo_rootx()
    y = root.winfo_rooty()
    w = root.winfo_width()
    h = root.winfo_height()
    out = SHOT_DIR / f"{name}.png"
    subprocess.run(["screencapture", "-x", "-R", f"{x},{y},{w},{h}", str(out)], check=True)
    print(f"captured {out}")


def run_action_and_wait(root: tk.Tk, status_var: tk.StringVar, action, timeout=20.0):
    """Trigger a button action and pump the Tk event loop until the worker
    thread posts its result (the status text changes from what it was)."""
    previous_status = status_var.get()
    action()
    deadline = time.time() + timeout
    while time.time() < deadline:
        root.update()
        if status_var.get() != previous_status:
            time.sleep(0.4)  # let the label color/text settle visually
            root.update()
            return
        time.sleep(0.05)
    raise TimeoutError(f"status never changed from {previous_status!r}")


def main():
    root = tk.Tk()
    app = CryptoClientApp(root)
    app.lab3_tab._base_file.set(BASE_FILE)
    root.geometry("+100+100")
    root.update()

    screenshot(root, "01_initial_state")

    # --- Lab 3 tab: prove no regression ---
    run_action_and_wait(root, app.lab3_tab.status, app.lab3_tab._on_get_key)
    screenshot(root, "02_lab3_get_key")

    run_action_and_wait(root, app.lab3_tab.status, app.lab3_tab._on_encrypt)
    screenshot(root, "03_lab3_encrypted")

    run_action_and_wait(root, app.lab3_tab.status, app.lab3_tab._on_decrypt)
    screenshot(root, "04_lab3_decrypted")

    decrypted = Path(BASE_FILE + ".dec").read_bytes()
    original = Path(BASE_FILE).read_bytes()
    assert decrypted == original, "decrypted output does not match original!"
    print("Lab 3 AES round trip verified byte-for-byte.")

    # --- Lab 4 tab: certificate fetch + verify + El Gamal key transport ---
    app.notebook.select(app.lab4_tab)
    root.update()
    screenshot(root, "05_lab4_tab_initial")

    app.lab4_tab.cert_username.set("oobed")
    run_action_and_wait(root, app.lab4_tab.status, app.lab4_tab._on_get_certificate)
    screenshot(root, "06_lab4_certificate_verified")

    app.lab4_tab._on_generate_aes_key()
    root.update()
    screenshot(root, "07_lab4_aes_key_generated")

    app.lab4_tab._on_encrypt_key_for_recipient()
    root.update()
    screenshot(root, "08_lab4_key_encrypted_for_recipient")

    root.destroy()
    print("done")


if __name__ == "__main__":
    main()
