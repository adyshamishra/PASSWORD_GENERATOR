import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
import database, security, generator, pyperclip
from generator import generate_strong_password

class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Vault v1.0")
        self.root.geometry("500x700")
        self.master_session_password = "" 
        
        database.initialize_db()
        
        if database.master_exists():
            self.show_login_screen()
        else:
            self.show_setup_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_setup_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Vault Setup", font=("Arial", 14, "bold")).pack(pady=20)
        tk.Label(self.root, text="Master Password:").pack()
        self.pass_entry = tk.Entry(self.root, show="*", width=30); self.pass_entry.pack()
        tk.Label(self.root, text="Confirm Master Password:").pack()
        self.confirm_entry = tk.Entry(self.root, show="*", width=30); self.confirm_entry.pack(pady=5)
        tk.Button(self.root, text="Lock Vault", command=self.handle_setup, bg="#2ecc71", fg="white").pack(pady=20)

    def handle_setup(self):
        p1, p2 = self.pass_entry.get(), self.confirm_entry.get()
        if p1 == p2 and len(p1) >= 8:
            salt, hashed_key = security.hash_master_password(p1)
            conn = sqlite3.connect("vault.db")
            conn.execute("INSERT INTO master_key (salt, hashed_key) VALUES (?, ?)", (salt, hashed_key))
            conn.commit()
            conn.close()
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Passwords must match and be 8+ characters.")

    def show_login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Login to Vault", font=("Arial", 14, "bold"), fg="#e74c3c").pack(pady=20)
        self.login_entry = tk.Entry(self.root, show="*", width=30); self.login_entry.pack(pady=10)
        tk.Button(self.root, text="Unlock", command=self.handle_login, bg="#3498db", fg="white", width=15).pack(pady=10)

    def handle_login(self):
        password = self.login_entry.get()
        creds = database.get_master_credentials()
        if creds and security.verify_master_password(password, creds[0], creds[1]):
            self.master_session_password = password 
            self.show_dashboard()
        else:
            messagebox.showerror("Denied", "Incorrect Master Password!")

    def show_dashboard(self):
        self.clear_screen()
        tk.Label(self.root, text="Secure Generator", font=("Arial", 16, "bold")).pack(pady=10)
        self.status_label = tk.Label(self.root, text="Ready", fg="blue"); self.status_label.pack()

        self.length_slider = tk.Scale(self.root, from_=8, to_=32, orient="horizontal", length=250)
        self.length_slider.set(16); self.length_slider.pack()
        # Checkbox: Exclude ambiguous characters
        self.exclude_ambiguous_var = tk.BooleanVar()

        self.ambiguous_checkbox = tk.Checkbutton(
            self.root,
            text="Exclude ambiguous characters (i, l, 1, O, 0)",
            variable=self.exclude_ambiguous_var
        )

        self.ambiguous_checkbox.pack(pady=5)

        self.result_entry = tk.Entry(self.root, font=("Courier", 14), width=25, justify="center")
        self.result_entry.pack(pady=15)

        tk.Button(self.root, text="Generate New Password", command=self.handle_gen, bg="#8e44ad", fg="white", width=30).pack(pady=5)
        tk.Button(self.root, text="Check Security Level", command=self.handle_check, bg="#2980b9", fg="white", width=30).pack(pady=5)
        
        tk.Label(self.root, text="Vault Actions", font=("Arial", 10, "bold")).pack(pady=(20, 0))
        tk.Button(self.root, text="Save to Vault", command=self.handle_save, bg="#27ae60", fg="white", width=30).pack(pady=5)
        tk.Button(self.root, text="View Saved Passwords", command=self.show_vault, bg="#95a5a6", fg="white", width=30).pack(pady=5)
        tk.Button(self.root, text="Logout", command=self.show_login_screen, fg="grey", bd=0).pack(side="bottom", pady=10)

    def handle_gen(self):
        pwd = generator.generate_strong_password(
            self.length_slider.get(),
            exclude_ambiguous=self.exclude_ambiguous_var.get()
        )

        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(0, pwd)

        self.status_label.config(text="Strong Password Generated!", fg="#27ae60")

    def handle_check(self):
        pwd = self.result_entry.get()
        is_secure, missing = generator.check_security(pwd)
        if is_secure:
            self.status_label.config(text="Security Verified: STRONG", fg="#27ae60")
            messagebox.showinfo("Security", "This password is secure!")
        else:
            self.status_label.config(text="Security Warning: WEAK", fg="#e74c3c")
            messagebox.showwarning("Security Fail", f"Needs: {', '.join(missing)}")

    def handle_save(self):
        pwd = self.result_entry.get()
        is_secure, missing = generator.check_security(pwd)

        # NEW: enforce ambiguous character rule if checkbox is ON
        if self.exclude_ambiguous_var.get():
            if any(c in "il1Lo0O" for c in pwd):
                messagebox.showerror(
                    "Invalid Password",
                    "Password contains ambiguous characters!"
                )
                return
        if not is_secure:
            messagebox.showerror("Insecure", f"Cannot save! Needs: {', '.join(missing)}")
            return

        service = simpledialog.askstring("Input", "Website Name:")
        user = simpledialog.askstring("Input", "Username:")
        if service and user:
            creds = database.get_master_credentials()
            enc_pwd = security.encrypt_password(pwd, self.master_session_password, creds[0])
            database.save_password(service, user, enc_pwd)
            messagebox.showinfo("Success", "Saved to Vault!")

    def show_vault(self):
        self.clear_screen()
        tk.Label(self.root, text="Your Vault", font=("Arial", 14, "bold")).pack(pady=10)
        container = tk.Frame(self.root); container.pack(fill="both", expand=True, padx=20)
        
        creds = database.get_master_credentials()
        for item in database.fetch_all_passwords():
            frame = tk.Frame(container, bd=1, relief="groove")
            frame.pack(fill="x", pady=2)
            tk.Label(frame, text=f"{item[1]} ({item[2]})", width=30, anchor="w").pack(side="left", padx=5)
            def copy_val(c_text=item[3]):
                d_text = security.decrypt_password(c_text, self.master_session_password, creds[0])
                pyperclip.copy(d_text); messagebox.showinfo("Vault", "Decrypted & Copied!")
            tk.Button(frame, text="Copy", command=copy_val).pack(side="right")
        tk.Button(self.root, text="Back", command=self.show_dashboard).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk(); app = PasswordApp(root); root.mainloop()