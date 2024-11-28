import tkinter as tk
import tkinter.messagebox
import base64

# Şifreleme ve Şifre Çözme Fonksiyonları
def encode(key, clear):
    enc = [(ord(clear[i]) + ord(key[i % len(key)])) % 256 for i in range(len(clear))]
    return base64.urlsafe_b64encode(bytes(enc)).decode()

def decode(key, enc):
    enc = base64.urlsafe_b64decode(enc)
    dec = [(256 + enc[i] - ord(key[i % len(key)])) % 256 for i in range(len(enc))]
    return "".join(map(chr, dec))

# Kayıt Fonksiyonu
def save_secret():
    title = title_input.get()
    secret = text_widget.get("1.0", "end").strip()
    key = key_input.get()

    if not title or not secret or not key:
        tk.messagebox.showwarning("Error", "Please fill in all fields.")
        return

    encoded_secret = encode(key, secret)
    with open("secrets.txt", "a") as file:
        file.write(f"{title}---{encoded_secret}\n")

    title_input.delete(0, tk.END)
    text_widget.delete("1.0", tk.END)
    key_input.delete(0, tk.END)
    tk.messagebox.showinfo("Success", "Secret saved successfully!")

# Şifre Çözme Fonksiyonu
def decode_secret():
    secret = text_widget.get("1.0", "end").strip()
    key = key_input.get()

    if not secret or not key:
        tk.messagebox.showwarning("Error", "Please fill in all fields.")
        return

    try:
        decoded_secret = decode(key, secret)
        text_widget.delete("1.0", tk.END)
        text_widget.insert("1.0", decoded_secret)
    except Exception:
        tk.messagebox.showerror("Error", "Decryption failed. Check your input.")

# Arayüz
window = tk.Tk()
window.title("Secret Notes")
window.geometry("300x400")
window.configure(bg="lightgray")

tk.Label(window, text="Title").pack(pady=5)
title_input = tk.Entry(window, width=30)
title_input.pack()

tk.Label(window, text="Secret").pack(pady=5)
text_widget = tk.Text(window, height=8, width=30)
text_widget.pack()

tk.Label(window, text="Key").pack(pady=5)
key_input = tk.Entry(window, width=30)
key_input.pack()

tk.Button(window, text="Save & Encrypt", command=save_secret, bg="lightblue").pack(pady=5)
tk.Button(window, text="Decrypt", command=decode_secret, bg="lightgreen").pack(pady=5)

window.mainloop()
