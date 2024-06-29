import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import subprocess

# Global variables to store the last used file and mode of operation
last_file_path = ""
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


def encrypt_file(file_path, key, mode, c0):
    global last_mode, last_file_path
    key, c0, mode = verify_parameters(file_path, key, mode, c0)
    if key is None:
        return
    content = read_file(file_path)
    extension = file_path.rsplit(".", 1)[-1]
    header, plaintext, _ = (
        extract_content(content, 54, 0)
        if extension == "bmp"
        else extract_content(content, 0, 0)
    )
    ciphertext = aes_encrypt(plaintext, key, getattr(AES, f"MODE_{mode}"), c0)
    last_file_path = write_file(file_path, header + ciphertext, f"e{mode}")
    last_mode = mode


def decrypt_file(file_path, key, mode, c0):
    global last_mode, last_file_path
    key, c0, mode = verify_parameters(file_path, key, mode, c0)
    if key is None:
        return
    content = read_file(file_path)
    extension = file_path.rsplit(".", 1)[-1]
    header, ciphertext, _ = (
        extract_content(content, 54, 0)
        if extension == "bmp"
        else extract_content(content, 0, 0)
    )
    plaintext = aes_decrypt(ciphertext, key, getattr(AES, f"MODE_{mode}"), c0)
    last_file_path = write_file(file_path, header + plaintext, f"d{mode}")
    last_mode = mode


def verify_parameters(file_path, key, mode, c0):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file.")
        return None, None, None
    if not os.path.exists(file_path):
        messagebox.showwarning("Warning", "The file does not exist.")
        return None, None, None
    if mode not in ["CBC", "CFB", "OFB", "ECB"]:
        messagebox.showwarning("Warning", "Please select a valid mode.")
        return None, None, None
    try:
        key = bytes.fromhex(key)
        if len(key) != 16:
            messagebox.showwarning("Warning", "The key must be 16 bytes long.")
            return None, None, None
    except ValueError as e:
        messagebox.showwarning("Warning", f"Invalid key hex string: {e}")
        return None, None, None
    try:
        if mode != "ECB":  # Only necessary if using modes that require an IV
            c0 = bytes.fromhex(c0)
            if len(c0) != 16:
                messagebox.showwarning(
                    "Warning", "The initialization vector c0 must be 16 bytes long."
                )
                return None, None, None
        else:
            c0 = None
    except ValueError as e:
        messagebox.showwarning("Warning", f"Invalid IV hex string: {e}")
        return None, None, None

    return key, c0, mode


def extract_content(content, header_size, footer_size):
    if content is not None:
        header = content[:header_size] if header_size > 0 else b""
        footer = content[-footer_size:] if footer_size > 0 else b""
        data = (
            content[header_size:-footer_size]
            if footer_size > 0
            else content[header_size:]
        )
        return header, data, footer
    else:
        return None, None, None


def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", f"Error reading the file. {e}")
        return None


def write_file(file_path, data, sufix=None):
    file_path_base = file_path.rsplit(".", 1)[-2]
    extension = file_path.rsplit(".", 1)[-1]
    new_file_path = (
        f"{file_path_base}{('_' + sufix) if sufix is not None else ''}.{extension}"
    )
    try:
        with open(new_file_path, "wb") as f:
            f.write(data)
        print(f"File saved as: {new_file_path}")
        messagebox.showinfo(
            "File saved",
            f"File saved as: {os.path.basename(new_file_path)}",
        )
        subprocess.run(["start", new_file_path], shell=True)
        return new_file_path
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", f"Error saving the file. {e}")
        return None


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
    action_window.title(f"{action} File")
    action_window.geometry("400x450")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    # File path
    tk.Label(frame, text="File path:").pack(anchor="w")
    file_path_text = Text(frame, height=1, width=40)
    file_path_text.pack(fill="x", expand=True)
    file_path_text.insert(tk.END, last_file_path)
    scrollbar = Scrollbar(frame, orient="horizontal", command=file_path_text.xview)
    file_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
    scrollbar.pack(fill="x")
    tk.Button(
        frame, text="Select File", command=lambda: select_file(file_path_text)
    ).pack(anchor="e")

    # Key
    tk.Label(frame, text="Key (K) [32 hex characters]:").pack(anchor="w")
    key_entry = tk.Entry(frame, width=40)
    key_entry.pack(fill="x", expand=True)
    tk.Button(
        frame, text="Load from file", command=lambda: select_file_and_load_content(key_entry,[("Hex files", "*.hex"), ("All files", "*.*")]),
    ).pack(anchor="e")

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
            command=lambda: update_iv_entry_state(iv_entry, load_iv_button, mode_var),
        ).pack()  # side="left"

    # Initialization Vector
    tk.Label(frame, text="Initialization Vector (C0 or IV) [32 hex characters]:").pack(
        anchor="w"
    )
    iv_entry = tk.Entry(frame, width=40)
    iv_entry.pack(fill="x", expand=True)
    load_iv_button = tk.Button(
        frame, text="Load from file", command=lambda: select_file_and_load_content(iv_entry,[("Hex files", "*.hex"), ("All files", "*.*")]),
    )
    load_iv_button.pack(anchor="e")
    update_iv_entry_state(
        iv_entry, load_iv_button, mode_var
    )

    # Action buttons
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)

    if action == "Cipher":
        button_color = "#e06666"
        command = lambda: encrypt_file(
            file_path_text.get("1.0", "end-1c"),
            key_entry.get(),
            mode_var.get(),
            iv_entry.get(),
        )
    else:  # Decrypt
        button_color = "#93c47d"
        command = lambda: decrypt_file(
            file_path_text.get("1.0", "end-1c"),
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


def update_iv_entry_state(iv_entry, load_iv_button, mode_var):
    if mode_var.get() == "ECB":
        iv_entry.config(state="disabled")
        load_iv_button.config(state="disabled")
    else:
        iv_entry.config(state="normal")
        load_iv_button.config(state="normal")


def select_file(text_widget, filetypes=[("All files", "*.*")]):
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    text_widget.delete("1.0", tk.END)
    text_widget.insert("1.0", file_path)


def select_file_and_load_content(entry_widget, filetypes=[("All files", "*.*")]):
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    if file_path:
        data = read_file(file_path)
        if data is not None:
            string = data.decode("utf-8")
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, string)
        else:
            messagebox.showerror("Error", "Failed to load data from file.")


def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()


if __name__ == "__main__":
    main_menu()
