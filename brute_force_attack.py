import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import itertools
import string
import threading

# Mock login function
def login(username, password):
    return password == "Pass123"

class PasswordCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker")
        self.root.configure(bg="black")
        self.root.geometry("700x500")

        # Pixel font substitute
        self.pixel_font = ("Courier New", 10, "bold")

        # Title label
        tk.Label(root, text="PASSWORD CRACKER", fg="#00FF00", bg="black", font=self.pixel_font).pack(pady=10)

        # Username input
        frame_user = tk.Frame(root, bg="black")
        frame_user.pack(pady=5)
        tk.Label(frame_user, text="Username:", fg="#00FF00", bg="black", font=self.pixel_font).pack(side=tk.LEFT)
        self.username_entry = tk.Entry(frame_user, font=self.pixel_font, bg="black", fg="#00FF00", insertbackground="#00FF00", width=20)
        self.username_entry.pack(side=tk.LEFT, padx=10)

        # Wordlist input
        frame_wordlist = tk.Frame(root, bg="black")
        frame_wordlist.pack(pady=5)
        tk.Label(frame_wordlist, text="Wordlist File:", fg="#00FF00", bg="black", font=self.pixel_font).pack(side=tk.LEFT)
        self.wordlist_path = tk.StringVar()
        self.wordlist_entry = tk.Entry(frame_wordlist, textvariable=self.wordlist_path, font=self.pixel_font, bg="black", fg="#00FF00", insertbackground="#00FF00", width=40)
        self.wordlist_entry.pack(side=tk.LEFT, padx=10)
        tk.Button(frame_wordlist, text="Browse", command=self.browse_file, bg="#003300", fg="#00FF00", font=self.pixel_font).pack(side=tk.LEFT)

        # Buttons frame
        frame_buttons = tk.Frame(root, bg="black")
        frame_buttons.pack(pady=10)

        self.dict_btn = tk.Button(frame_buttons, text="Dictionary Attack", command=self.start_dictionary_attack, bg="#003300", fg="#00FF00", font=self.pixel_font, width=20)
        self.dict_btn.pack(side=tk.LEFT, padx=5)

        self.brute_btn = tk.Button(frame_buttons, text="Brute Force Attack", command=self.start_brute_force_attack, bg="#003300", fg="#00FF00", font=self.pixel_font, width=20)
        self.brute_btn.pack(side=tk.LEFT, padx=5)

        # Output box
        self.output_box = scrolledtext.ScrolledText(root, bg="black", fg="#00FF00", font=self.pixel_font, insertbackground="#00FF00", width=80, height=20)
        self.output_box.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.wordlist_path.set(file_path)

    def log(self, message):
        self.output_box.insert(tk.END, message + "\n")
        self.output_box.see(tk.END)

    def dictionary_attack(self, username, wordlist_file):
        self.log("[*] Starting dictionary attack...")
        try:
            with open(wordlist_file, "r") as f:
                for line in f:
                    pwd = line.strip()
                    self.log(f"Trying password: {pwd}")
                    self.output_box.update()
                    if login(username, pwd):
                        self.log(f"[+] Password found: {pwd}")
                        messagebox.showinfo("Success", f"Password found: {pwd}")
                        return
            self.log("[-] Password not found in dictionary.")
        except Exception as e:
            self.log(f"[x] Error: {e}")

    def brute_force_attack(self, username, max_len=4):
        self.log("[*] Starting brute force attack...")
        chars = string.ascii_lowercase + string.digits
        for length in range(1, max_len + 1):
            for guess in itertools.product(chars, repeat=length):
                pwd = ''.join(guess)
                self.log(f"Trying password: {pwd}")
                self.output_box.update()
                if login(username, pwd):
                    self.log(f"[+] Password found: {pwd}")
                    messagebox.showinfo("Success", f"Password found: {pwd}")
                    return
        self.log("[-] Password not found with brute force.")

    def start_dictionary_attack(self):
        username = self.username_entry.get().strip()
        wordlist = self.wordlist_path.get().strip()
        if not username or not wordlist:
            messagebox.showwarning("Input Error", "Please enter username and select a wordlist file.")
            return
        threading.Thread(target=self.dictionary_attack, args=(username, wordlist), daemon=True).start()

    def start_brute_force_attack(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Please enter username.")
            return
        threading.Thread(target=self.brute_force_attack, args=(username,), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackerGUI(root)
    root.mainloop()
