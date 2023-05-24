import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import pyperclip

class App:
    def __init__(self, master):
        self.master = master
        master.title("AES加密解密程序")

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

    def pad_key(self, key):
        return (key * 4)[:16]

    def encrypt(self):
        text = self.text.get("1.0", "end-1c")
        key = self.pad_key(self.key_entry.get())
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        self.text.delete("1.0", "end")
        self.text.insert("1.0", iv + ct)

    def decrypt(self):
        ciphertext = self.text.get("1.0", "end-1c")
        key = self.pad_key(self.key_entry.get())
        iv = base64.b64decode(ciphertext[:24])
        ct = base64.b64decode(ciphertext[24:])
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        self.text.delete("1.0", "end")
        self.text.insert("1.0", pt.decode('utf-8'))

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