import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from Crypto.Random import get_random_bytes

def encrypt(plaintext, key, mode, c0=None):
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
        return None

def decrypt(ciphertext, key, mode, c0=None):
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
        return None
    except Exception as e:
        print(f"Error al descifrar: {e}")
        return None


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("Cifrador AES")
    main_menu_window.geometry("400x100")

    tk.Button(main_menu_window, text="Cifrar", command=lambda: cipher_menu(main_menu_window), width=10).pack(pady=10)
    tk.Button(main_menu_window, text="Descifrar", command=lambda: decipher_menu(main_menu_window), width=10).pack()

    main_menu_window.mainloop()

def cipher_menu(parent_window):
    parent_window.withdraw()
    cipher_window = tk.Toplevel()
    cipher_window.title("Cifrado")
    cipher_window.geometry("400x350")

    frame = tk.Frame(cipher_window)
    frame.pack(padx=10, pady=10)

    tk.Label(frame, text="Ruta del archivo:").pack(anchor='w')
    filename_entry = tk.Entry(frame, width=40)
    filename_entry.pack(fill='x', expand=True)
    tk.Button(frame, text="Seleccionar", command=lambda: select_file(filename_entry)).pack(anchor='e')

    tk.Label(frame, text="Clave:").pack(anchor='w')
    key_entry = tk.Entry(frame, show="*", width=40)
    key_entry.pack(fill='x', expand=True)

    tk.Label(frame, text="Vector de Inicialización (opcional):").pack(anchor='w')
    iv_entry = tk.Entry(frame, show="*", width=40)
    iv_entry.pack(fill='x', expand=True)

    modes = {"ECB": "ECB", "CBC": "CBC", "CFB": "CFB", "OFB": "OFB"}
    mode_var = tk.StringVar(value=list(modes.values())[-1])

    for mode, value in modes.items():
        tk.Radiobutton(frame, text=mode, variable=mode_var, value=value).pack()

    tk.Button(frame, text="Cifrar", command=lambda: cipher(filename_entry.get(), key_entry.get(), mode_var.get(), iv_entry.get())).pack(pady=5)
    tk.Button(frame, text="Volver", command=lambda: close_window(cipher_window, parent_window)).pack(pady=5)

def decipher_menu(parent_window):
    parent_window.withdraw()
    decipher_window = tk.Toplevel()
    decipher_window.title("Descifrado")
    decipher_window.geometry("400x350")

    frame = tk.Frame(decipher_window)
    frame.pack(padx=10, pady=10)

    tk.Label(frame, text="Ruta del archivo:").pack(anchor='w')
    filename_entry = tk.Entry(frame, width=40)
    filename_entry.pack(fill='x', expand=True)
    tk.Button(frame, text="Seleccionar", command=lambda: select_file(filename_entry)).pack(anchor='e')

    tk.Label(frame, text="Clave:").pack(anchor='w')
    key_entry = tk.Entry(frame, show="*", width=40)
    key_entry.pack(fill='x', expand=True)

    tk.Label(frame, text="Vector de Inicialización (opcional):").pack(anchor='w')
    iv_entry = tk.Entry(frame, show="*", width=40)
    iv_entry.pack(fill='x', expand=True)

    modes = {"ECB": "ECB", "CBC": "CBC", "CFB": "CFB", "OFB": "OFB"}
    mode_var = tk.StringVar(value=list(modes.values())[-1])

    for mode, value in modes.items():
        tk.Radiobutton(frame, text=mode, variable=mode_var, value=value).pack()

    tk.Button(frame, text="Descifrar", command=lambda: decipher(filename_entry.get(), key_entry.get(), mode_var.get(), iv_entry.get())).pack(pady=5)
    tk.Button(frame, text="Volver", command=lambda: close_window(decipher_window, parent_window)).pack(pady=5)

def select_file(filename_entry):
    filename = filedialog.askopenfilename()
    filename_entry.delete(0, tk.END)
    filename_entry.insert(0, filename)
    print(f"Archivo seleccionado: {filename}")

def cipher(filename, key, mode, c0):
    if not mode:
        print("Por favor, selecciona un modo.")
        return
    print(f"Cifrando {filename}, clave: {key} modo: {mode} c0: {c0}")
    key = key.encode("utf-8")
    c0 = c0.encode("utf-8") if c0 else None
    with open(filename, 'rb') as f:
        header = f.read(54)  # Leer la cabecera
        plaintext = f.read()  # Leer los datos de la imagen
    ciphertext = encrypt(plaintext, key, getattr(AES, f"MODE_{mode}"), c0)
    filename_base = filename.split('.', 1)[0]
    with open(f'{filename_base}_e{mode}.bmp', 'wb') as f:
        f.write(header + ciphertext)  # Escribir la cabecera y los datos cifrados

def decipher(filename, key, mode, c0):
    if not mode:
        print("Por favor, selecciona un modo.")
        return
    print(f"Descifrando {filename}, clave: {key} modo: {mode} c0: {c0}")
    key = key.encode("utf-8")
    c0 = c0.encode("utf-8") if c0 else None
    with open(filename, 'rb') as f:
        header = f.read(54)  # Leer la cabecera
        ciphertext = f.read()  # Leer los datos cifrados
    plaintext = decrypt(ciphertext, key, getattr(AES, f"MODE_{mode}"), c0)
    filename_base = filename.split('.', 1)[0]
    with open(f'{filename_base}_d{mode}.bmp', 'wb') as f:
        f.write(header + plaintext)  # Escribir la cabecera y los datos descifrados

def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()

if __name__ == "__main__":
    main_menu()
