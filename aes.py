import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


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
        print(f"Error al cifrar: {e}")
        messagebox.showwarning("Error al cifrar", "Error al cifrar el archivo.")
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
        print("Error al descifrar: el texto cifrado tiene un relleno incorrecto.")
        messagebox.showwarning("Error al descifrar", "El texto cifrado tiene un relleno incorrecto.")  
        return None
    except Exception as e:
        print(f"Error al descifrar: {e}")
        messagebox.showwarning("Error al descifrar", "Error al descifrar el archivo.")
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
    root.withdraw()  # Ocultar la ventana principal de Tkinter
    if not filename:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo.")
        return None, None, None
    if not os.path.exists(filename):
        messagebox.showwarning("Advertencia", "El archivo no existe.")
        return None, None, None
    if mode not in ["CBC", "CFB", "OFB", "ECB"]:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un modo válido.")
        return None, None, None
    key_encoded = key.encode("utf-8")
    if len(key_encoded) != 16:
        messagebox.showwarning("Advertencia", "La clave debe ser de 16 bytes.")
        return None, None, None
    c0_encoded = c0.encode("utf-8")
    if mode != "ECB" and len(c0_encoded) != 16:
        messagebox.showwarning(
            "Advertencia", "El vector de inicialización c0 debe ser de 16 bytes."
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
        print(f"Error al leer el archivo: {e}")
        messagebox.showwarning("Error al leer", "Error al leer el archivo.")
        return None, None


def write_file(filename, header, data, mode, prefix):
    filename_base = filename.rsplit(".", 1)[-2]
    extension = filename.rsplit(".", 1)[-1]
    new_filename = f"{filename_base}_{prefix}{mode}.{extension}"
    try:
        with open(new_filename, "wb") as f:
            f.write(header + data)
        print(f"Archivo guardado como: {new_filename}")
        messagebox.showinfo("Archivo guardado", f"Archivo guardado como: {os.path.basename(new_filename)}")  
    except Exception as e:
        print(f"Error al guardar el archivo: {e}")
        messagebox.showwarning("Error al guardar", "Error al guardar el archivo.")


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("Cifrador AES")
    main_menu_window.geometry("400x100")

    tk.Button(
        main_menu_window,
        text="Cifrar",
        command=lambda: cipher_decipher_menu(main_menu_window, "Cifrar"),
        width=10,
    ).pack(pady=10)
    tk.Button(
        main_menu_window,
        text="Descifrar",
        command=lambda: cipher_decipher_menu(main_menu_window, "Descifrar"),
        width=10,
    ).pack()

    main_menu_window.mainloop()


def cipher_decipher_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(action)
    action_window.geometry("400x350")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    tk.Label(frame, text="Ruta del archivo:").pack(anchor="w")
    filename_entry = tk.Entry(frame, width=40)
    filename_entry.pack(fill="x", expand=True)
    tk.Button(
        frame, text="Seleccionar", command=lambda: select_file(filename_entry)
    ).pack(anchor="e")

    tk.Label(frame, text="Clave:").pack(anchor="w")
    key_entry = tk.Entry(frame, show="*", width=40)
    key_entry.pack(fill="x", expand=True)

    tk.Label(frame, text="Modo de operación:").pack(anchor="w")
    modes = {"ECB": "ECB", "CBC": "CBC", "CFB": "CFB", "OFB": "OFB"}
    mode_var = tk.StringVar(value=list(modes.values())[-1])

    tk.Label(frame, text="Vector de Inicialización:").pack(anchor="w")
    iv_entry = tk.Entry(frame, show="*", width=40)
    iv_entry.pack(fill="x", expand=True)

    def update_iv_entry_state():
        if mode_var.get() == "ECB":
            iv_entry.config(state="disabled")
        else:
            iv_entry.config(state="normal")

    for mode, value in modes.items():
        tk.Radiobutton(
            frame,
            text=mode,
            variable=mode_var,
            value=value,
            command=update_iv_entry_state,
        ).pack()

    if action == "Cifrar":
        button_color = "red"
        command = lambda: encrypt_file(
            filename_entry.get(), key_entry.get(), mode_var.get(), iv_entry.get()
        )
    else:  # Descifrar
        button_color = "green"
        command = lambda: decrypt_file(
            filename_entry.get(), key_entry.get(), mode_var.get(), iv_entry.get()
        )

    tk.Button(frame, text=action, command=command, bg=button_color).pack(pady=5)
    tk.Button(
        frame, text="Volver", command=lambda: close_window(action_window, parent_window)
    ).pack(pady=5)

    update_iv_entry_state()


def select_file(filename_entry):
    filename = filedialog.askopenfilename()
    filename_entry.delete(0, tk.END)
    filename_entry.insert(0, filename)


def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()


if __name__ == "__main__":
    main_menu()
