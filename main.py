import base64
import os
import os.path
import tkinter as tk
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# def writeKey():
#     key = Fernet.generate_key()
#     file = open('key.key', 'wb')
#     file.write(key)
#     file.close()


# def readKey():
#     file = open('key.key', 'rb')
#     key = file.read()
#     file.close()
#     return key


# def keyExist():
#     return os.path.exists('key.key')

windows = []


def encrypt(message, textbox, key):
    encoded = message.encode()
    f = Fernet(key)
    encrypted = f.encrypt(encoded)
    setText(textbox, encrypted)


def decrypt(cipher, textbox, key):
    encoded = cipher.encode()
    f = Fernet(key)
    decrypted = f.decrypt(encoded)

    setText(textbox, decrypted)


def setText(textbox, text):
    textbox.delete('1.0', 'end')
    textbox.insert('1.0', text)


def clearText(textboxList):
    for textbox in textboxList:
        textbox.delete('1.0', 'end')


def destroyAllWindows():
    for w in windows:
        w.destroy()


def askSeed():
    seedWindow = tk.Tk()
    global windows
    windows.append(seedWindow)
    seedWindow.title("Enter Seed")
    frame = tk.Frame(seedWindow)
    frame.pack()

    label = tk.Label(frame, text="Enter Seed")
    label.pack(side=tk.LEFT)
    seedEntry = tk.Entry(frame)
    seedEntry.pack(side=tk.RIGHT)

    enterButton = tk.Button(seedWindow, text="Enter",
                            command=lambda: generateKey(seedEntry.get()))

    enterButton.pack()

    seedWindow.mainloop()


def generateKey(seed):
    seedEncoded = seed.encode()

    salt = b'\x1e[7K]\x99RTb\xfa\xd3\xe8\x83s,\x92'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=100000, backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(seedEncoded))

    launch(key)


def launch(key):
    root = tk.Tk()
    global windows
    windows.append(root)
    root.title("Secret Messenge Encryptor")
    tk.Label(root, text="Input").grid(row=0)
    tk.Label(root, text="Output").grid(row=1)

    input = tk.Text(root, width=80, height=10, wrap='word')
    output = tk.Text(root, width=80, height=10, wrap='word')

    input.grid(row=0, column=1)
    output.grid(row=1, column=1)

    tk.Button(root, text='Encrypt', command=lambda: encrypt(input.get("1.0", 'end'), output, key)).grid(
        row=3, column=0, sticky=tk.W, pady=4)
    tk.Button(root, text='Decrypt', command=lambda: decrypt(input.get("1.0", 'end'), output, key)).grid(
        row=3, column=1, sticky=tk.W, pady=4)
    tk.Button(root, text='Clear All',
              command=lambda: clearText([input, output])).grid(row=3, column=2, sticky=tk.W, pady=4)

    root.protocol("WM_DELETE_WINDOW", destroyAllWindows)

    root.mainloop()


if __name__ == "__main__":

    askSeed()
