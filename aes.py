import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import subprocess

# Global variables to store the last used file and mode of operation
last_filename = ""
last_mode = "ECB"


def aes_encrypt(plaintext, key, mode, c0=None):
    try:
        if mode == AES.MODE_ECB:
            cipher = AES.new(key, mode)
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
        else:
            cipher = AES.new(key, mode, c0)
            ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    except Exception as e:
        print(f"Cipher error: {e}")
        messagebox.showwarning("Cipher error", "Error cipherying the file.")
        return None


def aes_decrypt(ciphertext, key, mode, c0=None):
    try:
        if mode == AES.MODE_ECB:
            cipher = AES.new(key, mode)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        else:
            cipher = AES.new(key, mode, c0)
            plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except ValueError:
        print("Decipher error: Invalid padding.")
        messagebox.showwarning("Decipher error", "The ciphertext has invalid padding.")
        return None
    except Exception as e:
        print(f"Decipher error: {e}")
        messagebox.showwarning("Decipher error", "Error decipherying the file.")
        return None


def encrypt_file(filename, key, mode, c0):
    key, c0, mode = verify_parameters(filename, key, mode, c0)
    if key is None:
        return
    header, plaintext = read_file(filename)
    ciphertext = aes_encrypt(plaintext, key, getattr(AES, f"MODE_{mode}"), c0)
    write_file(filename, header, ciphertext, mode, "e")


def decrypt_file(filename, key, mode, c0):
    key, c0, mode = verify_parameters(filename, key, mode, c0)
    if key is None:
        return
    header, ciphertext = read_file(filename)
    plaintext = aes_decrypt(ciphertext, key, getattr(AES, f"MODE_{mode}"), c0)
    write_file(filename, header, plaintext, mode, "d")


def verify_parameters(filename, key, mode, c0):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not filename:
        messagebox.showwarning("Warning", "Please select a file.")
        return None, None, None
    if not os.path.exists(filename):
        messagebox.showwarning("Warning", "The file does not exist.")
        return None, None, None
    if mode not in ["CBC", "CFB", "OFB", "ECB"]:
        messagebox.showwarning("Warning", "Please select a valid mode.")
        return None, None, None
    key_encoded = key.encode("utf-8")
    if len(key_encoded) != 16:
        messagebox.showwarning("Warning", "The key must be 16 bytes long.")
        return None, None, None
    c0_encoded = c0.encode("utf-8")
    if mode != "ECB" and len(c0_encoded) != 16:
        messagebox.showwarning(
            "Warning", "The initialization vector c0 must be 16 bytes long."
        )
        return None, None, None
    return key_encoded, c0_encoded, mode


def read_file(filename):
    try:
        with open(filename, "rb") as f:
            header = f.read(54) if filename.endswith(".bmp") else b""
            data = f.read()
        return header, data
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", "Error reading the file.")
        return None, None


def write_file(filename, header, data, mode, prefix):
    global last_filename, last_mode
    filename_base = filename.rsplit(".", 1)[-2]
    extension = filename.rsplit(".", 1)[-1]
    new_filename = f"{filename_base}_{prefix}{mode}.{extension}"
    try:
        with open(new_filename, "wb") as f:
            f.write(header + data)
        last_filename = new_filename
        last_mode = mode
        print(f"File saved as: {new_filename}")
        messagebox.showinfo(
            "File saved",
            f"File saved as: {os.path.basename(new_filename)}",
        )
        subprocess.run(["start", new_filename], shell=True)
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", "Error saving the file.")


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("AES Cipher")
    main_menu_window.geometry("400x100")

    # Central container for buttons
    button_frame = tk.Frame(main_menu_window)
    button_frame.pack(pady=30)  # Center the frame vertically and add some padding

    # Encrypt button
    tk.Button(
        button_frame,
        text="Cipher",
        command=lambda: cipher_decipher_menu(main_menu_window, "Cipher"),
        bg="#e06666",
        width=10,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    # Decrypt button
    tk.Button(
        button_frame,
        text="Decipher",
        command=lambda: cipher_decipher_menu(main_menu_window, "Decipher"),
        bg="#93c47d",
        width=10,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    main_menu_window.mainloop()


def cipher_decipher_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(action)
    action_window.geometry("400x400")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    # File path
    tk.Label(frame, text="File path:").pack(anchor="w")
    filename_text = Text(frame, height=1, width=40)
    filename_text.pack(fill="x", expand=True)
    filename_text.insert(tk.END, last_filename)
    scrollbar = Scrollbar(frame, orient="horizontal", command=filename_text.xview)
    filename_text.configure(wrap="none", xscrollcommand=scrollbar.set)
    scrollbar.pack(fill="x")
    tk.Button(frame, text="Select", command=lambda: select_file(filename_text)).pack(
        anchor="e"
    )

    # Key
    tk.Label(frame, text="Key (K):").pack(anchor="w")
    key_entry = tk.Entry(frame, show="*", width=40)
    key_entry.pack(fill="x", expand=True)

    # Mode of operation
    tk.Label(frame, text="Mode of operation:").pack(anchor="w")
    modes = {"ECB": "ECB", "CBC": "CBC", "CFB": "CFB", "OFB": "OFB"}
    mode_var = tk.StringVar(
        value=last_mode if last_mode in modes.values() else list(modes.values())[-1]
    )
    modes_frame = tk.Frame(frame)
    modes_frame.pack(fill="x", expand=True)
    for mode, value in modes.items():
        tk.Radiobutton(
            modes_frame,
            text=mode,
            variable=mode_var,
            value=value,
            command=lambda: update_iv_entry_state(iv_entry, mode_var),
        ).pack()  # side="left"

    # Initialization Vector
    tk.Label(frame, text="Initialization Vector (C0):").pack(anchor="w")
    iv_entry = tk.Entry(frame, show="*", width=40)
    iv_entry.pack(fill="x", expand=True)
    update_iv_entry_state(
        iv_entry, mode_var
    )  # Make sure to call this function to set the initial state correctly

    # Central container for buttons
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)  # Center the frame vertically and add some padding

    # Action buttons
    if action == "Cipher":
        button_color = "#e06666"
        command = lambda: encrypt_file(
            filename_text.get("1.0", "end-1c"),
            key_entry.get(),
            mode_var.get(),
            iv_entry.get(),
        )
    else:  # Decrypt
        button_color = "#93c47d"
        command = lambda: decrypt_file(
            filename_text.get("1.0", "end-1c"),
            key_entry.get(),
            mode_var.get(),
            iv_entry.get(),
        )
    tk.Button(
        button_frame,
        text="Back",
        command=lambda: close_window(action_window, parent_window),
    ).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(button_frame, text=action, command=command, bg=button_color).pack(
        side=tk.LEFT, padx=10, pady=10
    )


def update_iv_entry_state(iv_entry, mode_var):
    if mode_var.get() == "ECB":
        iv_entry.config(state="disabled")
    else:
        iv_entry.config(state="normal")


def select_file(text_widget):
    filename = filedialog.askopenfilename()
    text_widget.delete("1.0", tk.END)
    text_widget.insert("1.0", filename)


def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()


if __name__ == "__main__":
    main_menu()
