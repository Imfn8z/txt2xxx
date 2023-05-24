import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import pyperclip

class App:
    def __init__(self, master):
        print("Initializing App...")
        self.master = master
        master.title("PRE-AES加密解密程序")

        self.label = tk.Label(master, text="请输入要加密/解密的文本和密钥：")
        self.label.grid(row=0, column=0, columnspan=2)

        self.text = tk.Text(master, height=10, width=50)
        self.text.grid(row=1, column=0, columnspan=2)

        self.key_label = tk.Label(master, text="密钥（4位数字）：")
        self.key_label.grid(row=2, column=0)

        self.key_entry = tk.Entry(master, show="*")
        self.key_entry.grid(row=2, column=1)

        self.encrypt_button = tk.Button(master, text="加密", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=0)

        self.decrypt_button = tk.Button(master, text="解密", command=self.decrypt)
        self.decrypt_button.grid(row=3, column=1)

        self.copy_button = tk.Button(master, text="复制", command=self.copy_text)
        self.copy_button.grid(row=4, column=0)

        self.paste_button = tk.Button(master, text="粘贴", command=self.paste_text)
        self.paste_button.grid(row=4, column=1)

    def encrypt(self):
        try:
            print("Starting encryption...")
            text = self.text.get("1.0", "end-1c")
            password = self.key_entry.get()
            print(f"Text to encrypt: {text}")
            print(f"Password: {password}")
            salt = get_random_bytes(8)
            key = PBKDF2(password, salt, 16)
            cipher = AES.new(key, AES.MODE_GCM)
            ct_bytes, tag = cipher.encrypt_and_digest(text.encode())
            iv = base64.b64encode(cipher.nonce).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            encoded_tag = base64.b64encode(tag).decode('utf-8')
            encoded_salt = base64.b64encode(salt).decode('utf-8')
            self.text.delete("1.0", "end")
            self.text.insert("1.0", encoded_salt + ',' + iv + ',' + ct + ',' + encoded_tag)
            print("Encryption finished.")
        except Exception as e:
            print(f"Encryption error: {e}")
            messagebox.showerror("错误", str(e))

    def decrypt(self):
        try:
            print("Starting decryption...")
            ciphertext = self.text.get("1.0", "end-1c").split(',')
            password = self.key_entry.get()
            print(f"Ciphertext: {ciphertext}")
            print(f"Password: {password}")
            salt = base64.b64decode(ciphertext[0])
            iv = base64.b64decode(ciphertext[1])
            ct = base64.b64decode(ciphertext[2])
            tag = base64.b64decode(ciphertext[3])
            key = PBKDF2(password, salt, 16)
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            data = cipher.decrypt_and_verify(ct, tag) # Here we replaced 'update' with 'decrypt_and_verify'
            self.text.delete("1.0", "end")
            self.text.insert("1.0", data.decode('utf-8'))
            print("Decryption successful!")
        except Exception as e:
            print(f"Decryption error: {e}")
            messagebox.showerror("错误", str(e))


    def copy_text(self):
        selected_text = self.text.get(tk.SEL_FIRST, tk.SEL_LAST)
        if selected_text:
            pyperclip.copy(selected_text)
        else:
            pass

    def paste_text(self):
        clipboard_text = pyperclip.paste()
        if clipboard_text:
            self.text.insert(tk.INSERT, clipboard_text)

root = tk.Tk()
app = App(root)
root.mainloop()