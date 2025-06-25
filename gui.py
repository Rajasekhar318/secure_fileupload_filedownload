import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import requests
import os

API_BASE = "http://localhost:5000/api"

class FileSharingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Sharing System")
        self.token = None
        self.role = None
        self.login_frame()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login_frame(self):
        self.clear_window()
        tk.Label(self.root, text="Email").pack()
        self.email_entry = tk.Entry(self.root, width=30)
        self.email_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
        tk.Button(self.root, text="Sign Up", command=self.signup_frame).pack()

    def signup_frame(self):
        self.clear_window()
        tk.Label(self.root, text="Email").pack()
        self.signup_email = tk.Entry(self.root, width=30)
        self.signup_email.pack()

        tk.Label(self.root, text="Password").pack()
        self.signup_password = tk.Entry(self.root, show="*", width=30)
        self.signup_password.pack()

        tk.Label(self.root, text="Role (Client or Ops)").pack()
        self.signup_role = tk.Entry(self.root, width=30)
        self.signup_role.pack()

        tk.Button(self.root, text="Sign Up", command=self.signup).pack(pady=5)
        tk.Button(self.root, text="Back to Login", command=self.login_frame).pack()

    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        try:
            res = requests.post(f"{API_BASE}/login", json={"email": email, "password": password})
            if res.status_code == 200:
                data = res.json()
                self.token = data['token']
                self.role = data['role']
                self.main_menu()
            else:
                messagebox.showerror("Login Failed", res.json().get("message", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def signup(self):
        email = self.signup_email.get()
        password = self.signup_password.get()
        role = self.signup_role.get().capitalize()
        try:
            res = requests.post(f"{API_BASE}/signup", json={"email": email, "password": password, "role": role})
            if res.status_code == 201:
                messagebox.showinfo("Success", "Check your email to verify your account.")
                self.login_frame()
            else:
                messagebox.showerror("Signup Failed", res.json().get("message", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def main_menu(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome, {self.role}", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.root, text="List Files", command=self.list_files).pack(pady=5)

        if self.role == "Ops":
            tk.Button(self.root, text="Upload File", command=self.upload_file).pack(pady=5)
        else:
            tk.Button(self.root, text="Download File", command=self.download_file_prompt).pack(pady=5)

        tk.Button(self.root, text="Logout", command=self.logout).pack(pady=10)

    def list_files(self):
        try:
            res = requests.get(f"{API_BASE}/files", headers={"Authorization": f"Bearer {self.token}"})
            if res.status_code == 200:
                self.show_files_window(res.json())
            else:
                messagebox.showerror("Error", res.json().get("message", "Could not list files"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_files_window(self, files):
        win = tk.Toplevel(self.root)
        win.title("Files")
        text = scrolledtext.ScrolledText(win, width=80, height=20)
        text.pack()
        for f in files:
            text.insert(tk.END, f"{f['filename']}\n{API_BASE}{f['download_link']}\n\n")

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        try:
            headers = {
                "Authorization": f"Bearer {self.token}",
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                res = requests.post(
                    f"{API_BASE}/upload",
                    files=files,
                    headers=headers,
                )
            
            if res.status_code == 201:
                messagebox.showinfo("Success", "File uploaded successfully")
            else:
                messagebox.showerror("Failed", f"Error {res.status_code}: {res.json().get('message', 'Unknown error')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def download_file_prompt(self):
        token = simpledialog.askstring("Download", "Enter encrypted download token:")
        if not token:
            return
        try:
            res = requests.get(f"{API_BASE}/download/{token}", headers={"Authorization": f"Bearer {self.token}"}, stream=True)
            if res.status_code == 200:
                filename = filedialog.asksaveasfilename()
                if filename:
                    with open(filename, 'wb') as f:
                        for chunk in res.iter_content(chunk_size=8192):
                            f.write(chunk)
                    messagebox.showinfo("Success", "File downloaded")
            else:
                messagebox.showerror("Error", res.json().get("message", "Download failed"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def logout(self):
        try:
            requests.post(f"{API_BASE}/logout", headers={"Authorization": f"Bearer {self.token}"})
        except:
            pass
        self.token = None
        self.role = None
        self.login_frame()

if __name__ == '__main__':
    root = tk.Tk()
    app = FileSharingApp(root)
    root.mainloop()
