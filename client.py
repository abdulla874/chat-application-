import socket
import rsa
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# AES Encrypt/Decrypt
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    return iv + cipher.update(plaintext) + cipher.finalize()

def decrypt_message(key, ciphertext):
    iv, data = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    return cipher.update(data) + cipher.finalize()

# Chat Client
class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.session_key = self.username = None
        self.running = False
        self.init_auth_page()

    def hash_password(self, pwd):
        return hashlib.sha256(pwd.encode()).hexdigest()

    def auth_user(self, register=False):
        user, pwd = self.user_entry.get(), self.pass_entry.get()
        if not user or not pwd:
            messagebox.showerror("Error", "Fill all fields!")
            return
        pwd_hash = self.hash_password(pwd)
        cred_file = "credentials.txt"
        if register:
            if ":" in user or ":" in pwd:
                messagebox.showerror("Error", "':' not allowed in username/password")
                return
            with open(cred_file, "a") as f:
                f.write(f"{user}:{pwd_hash}\n")
            messagebox.showinfo("Success", "Registration complete!")
        else:
            if os.path.exists(cred_file):
                with open(cred_file, "r") as f:
                    if f"{user}:{pwd_hash}" in f.read():
                        self.username = user
                        self.init_chat_page()
                        return
            messagebox.showerror("Error", "Invalid credentials!")

    def init_auth_page(self):
        self.clear_window()
        tk.Label(self.root, text="Secure Chat", font="Helvetica 16 bold").pack(pady=10)
        tk.Label(self.root, text="Username:").pack()
        self.user_entry = tk.Entry(self.root)
        self.user_entry.pack()
        tk.Label(self.root, text="Password:").pack()
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack()
        tk.Button(self.root, text="Login", command=lambda: self.auth_user()).pack(pady=5)
        tk.Button(self.root, text="Register", command=lambda: self.auth_user(register=True)).pack()

    def init_chat_page(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome, {self.username}", font="Helvetica 14 bold").pack(pady=10)
        self.chat_display = scrolledtext.ScrolledText(self.root, state="disabled")
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.msg_entry = tk.Entry(self.root)
        self.msg_entry.pack(fill=tk.X, padx=10, pady=5)
        self.msg_entry.bind("<Return>", self.send_message)
        tk.Button(self.root, text="Send", command=self.send_message).pack(pady=5)
        self.connect_to_server()

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(("localhost", 1111))  # Ensure this matches the server port
            pubkey_data = self.sock.recv(1024)
            self.session_key = os.urandom(16)
            self.sock.send(rsa.encrypt(self.session_key, rsa.PublicKey.load_pkcs1(pubkey_data)))
            self.display_message("Connected to the server.\n")
            self.running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

    def send_message(self, event=None):
        msg = self.msg_entry.get().strip()
        if msg:
            try:
                # Encrypt the message
                enc_msg = encrypt_message(self.session_key, f"{self.username}: {msg}".encode())

                # Print the encrypted message in the terminal
                print(f"Encrypted Message Sent: {enc_msg.hex()}")  # Hexadecimal format for readability

                # Send the encrypted message to the server
                self.sock.send(enc_msg)

                # Display the plaintext message in the GUI
                self.display_message(f"You: {msg}\n")

                # Clear the input field
                self.msg_entry.delete(0, tk.END)
            except Exception as e:
                self.display_message(f"Error sending message: {e}\n")

    def receive_messages(self):
        while self.running:
            try:
                encrypted_msg = self.sock.recv(1024)
                if encrypted_msg:
                    msg = decrypt_message(self.session_key, encrypted_msg).decode()
                    self.display_message(msg)
            except Exception as e:
                messagebox.showerror("Error", f"Message receiving failed: {e}")
                break

    def display_message(self, msg):
        self.chat_display.config(state="normal")
        self.chat_display.insert(tk.END, msg)
        self.chat_display.config(state="disabled")
        self.chat_display.yview(tk.END)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def stop(self):
        self.running = False
        self.sock.close()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.stop)
    root.mainloop()
