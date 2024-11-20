from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, filedialog
import csv
import re

def pad_key(key):
    return hashlib.sha256(key.encode()).digest()

def encrypt_aes_256(key, plaintext):
    key_bytes = pad_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

def decrypt_aes_256(key, ciphertext, iv):
    key_bytes = pad_key(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Initialize Database
def init_db():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Create users table with salt and password_hash
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')

    # Create credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            site_username TEXT NOT NULL,
            site_password TEXT NOT NULL,
            site_iv TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS check_duplicate_site
        BEFORE INSERT ON credentials
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN (SELECT COUNT(*) FROM credentials WHERE site = New.site) > 0
                THEN RAISE (ABORT, 'Already an account for that site')
            END;
        END;
                   ''')
    conn.commit()
    conn.close()

# Password Hashing with SHA-256
def hash_password(password):
    salt = os.urandom(16)  # Generate a 16-byte random salt
    password_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex(), password_hash

# Verify Password
def verify_password(stored_salt, stored_password_hash, entered_password):
    salt = bytes.fromhex(stored_salt)  # Convert salt back to bytes
    entered_hash = hashlib.sha256(salt + entered_password.encode('utf-8')).hexdigest()
    return entered_hash == stored_password_hash

# Register a User
def register_user(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Hash password
    salt, password_hash = hash_password(password)

    try:
        cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', (username, password_hash, salt))
        conn.commit()
        messagebox.showinfo("Success", "Registration successful!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")
    finally:
        conn.close()

# Login a User
def login_user(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Fetch user data
    cursor.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        user_id, stored_password_hash, stored_salt = user
        if verify_password(stored_salt, stored_password_hash, password):
            return user_id  # Successful login
    messagebox.showerror("Error", "Invalid username or password.")
    return None

# Add a Credential
def add_credential(key, user_id, site, site_username, site_password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Hash the site password
    encrypted_site_password, iv = encrypt_aes_256(key, site_password)
    try:
        cursor.execute('''
            INSERT INTO credentials (user_id, site, site_username, site_password, site_iv)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, site, site_username, encrypted_site_password, iv))
        conn.commit()
        messagebox.showinfo("Success", "Credential saved successfully!")
    except sqlite3.DatabaseError:
        messagebox.showerror("Error", "Username already exists.")
    finally:
        cursor.close()
        conn.close()

# View Credentials
def view_credentials(key, user_id):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    cursor.execute('SELECT site, site_username, site_password, site_iv FROM credentials WHERE user_id = ?', (user_id,))
    credentials = cursor.fetchall()
    conn.close()

    if credentials:
        result = ""
        for site, username, password, iv in credentials:
            result = result + f"Site: {site}, Username: {username}, Password: {decrypt_aes_256(key, password, iv)}\n"
        messagebox.showinfo("Your Credentials", result)
    else:
        messagebox.showinfo("Your Credentials", "No credentials stored.")

def delete_credential(user_id, site):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Delete the specified credential
    cursor.execute('DELETE FROM credentials WHERE user_id = ? AND site = ?', (user_id, site))
    conn.commit()
    conn.close()

    if cursor.rowcount > 0:
        messagebox.showinfo("Success", f"Credential for site '{site}' deleted successfully!")
    else:
        messagebox.showerror("Error", f"No credential found for site '{site}'.")

# Add a method to update a credential
def update_credential(key, user_id, site, new_username, new_password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Hash the new password
    encrypted_site_password, iv = encrypt_aes_256(key, new_password)

    # Update the specified credential
    cursor.execute('''
        UPDATE credentials
        SET site_username = ?, site_password = ?, site_iv = ?
        WHERE user_id = ? AND site = ?
    ''', (new_username, encrypted_site_password, iv, user_id, site))
    conn.commit()
    conn.close()

    if cursor.rowcount > 0:
        messagebox.showinfo("Success", f"Credential for site '{site}' updated successfully!")
    else:
        messagebox.showerror("Error", f"No credential found for site '{site}'.")

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return "Password must contain at least one number."
    return None


# Tkinter Application
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.user_id = None
        self.root.title("Password Manager")
        self.root.geometry("400x300")
        self.show_main_menu()
        self.key = None

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_main_menu(self):
        self.clear_frame()

        tk.Label(self.root, text="Password Manager", font=("Arial", 20)).pack(pady=10)
        tk.Button(self.root, text="Register", width=20, command=self.show_register).pack(pady=5)
        tk.Button(self.root, text="Login", width=20, command=self.show_login).pack(pady=5)
        tk.Button(self.root, text="Quit", width=20, command=self.root.quit).pack(pady=5)

    def show_register(self):
        self.clear_frame()

        tk.Label(self.root, text="Register", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.root, text="Username:").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="Password:").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()


        def submit():
            username = username_entry.get()
            password = password_entry.get()
            if username and password:
                register_user(username, password)
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "All fields are required.")

        tk.Button(self.root, text="Submit", command=submit).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack()

    def show_login(self):
        self.clear_frame()

        tk.Label(self.root, text="Login", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.root, text="Username:").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="Password:").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        def submit():
            username = username_entry.get()
            password = password_entry.get()
            if username and password:
                user_id = login_user(username, password)
                if user_id:
                    self.user_id = user_id
                    self.key = password
                    self.show_dashboard()
            else:
                messagebox.showerror("Error", "All fields are required.")

        tk.Button(self.root, text="Submit", command=submit).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack()

    def show_dashboard(self):
        self.clear_frame()

        tk.Label(self.root, text="Dashboard", font=("Arial", 16)).pack(pady=10)
        tk.Button(self.root, text="Add Credential", width=20, command=self.show_add_credential).pack(pady=5)
        tk.Button(self.root, text="View Credentials", width=20, command=lambda: view_credentials(self.key, self.user_id)).pack(pady=5)
        tk.Button(self.root, text="Delete Credential", width=20, command=self.show_delete_credential).pack(pady=5)
        tk.Button(self.root, text="Update Credential", width=20, command=self.show_update_credential).pack(pady=5)
        tk.Button(self.root, text="Logout", width=20, command=self.logout).pack(pady=5)

    def show_delete_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Delete Credential", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.root, text="Website:").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()

        def submit():
            site = site_entry.get()
            if site:
                delete_credential(self.user_id, site)
                self.show_dashboard()
            else:
                messagebox.showerror("Error", "Please enter a website.")

        tk.Button(self.root, text="Delete", command=submit).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard).pack()

    def show_update_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Update Credential", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.root, text="Website:").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()
        tk.Label(self.root, text="New Username:").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="New Password:").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        def submit():
            site = site_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            if site and new_username and new_password:
                update_credential(self.key, self.user_id, site, new_username, new_password)
                self.show_dashboard()
            else:
                messagebox.showerror("Error", "All fields are required.")

        tk.Button(self.root, text="Update", command=submit).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard).pack()


    def show_add_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Add Credential", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.root, text="Website:").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()
        tk.Label(self.root, text="Username:").pack()
        site_username_entry = tk.Entry(self.root)
        site_username_entry.pack()
        tk.Label(self.root, text="Password:").pack()
        site_password_entry = tk.Entry(self.root, show="*")
        site_password_entry.pack()

        def submit():
            site = site_entry.get()
            site_username = site_username_entry.get()
            site_password = site_password_entry.get()
            validation_error = validate_password(site_password)
            if validation_error:
                messagebox.showerror("Error", validation_error)
            elif site and site_username and site_password:
                add_credential(self.key, self.user_id, site, site_username, site_password)
                self.show_dashboard()
            else:
                messagebox.showerror("Error", "All fields are required.")

        tk.Button(self.root, text="Submit", command=submit).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard).pack()

    def logout(self):
        self.user_id = None
        self.key = None
        self.show_main_menu()

def export_users_and_credentials_to_csv():
    # Connect to the existing database
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Query to fetch all users and their credentials
    cursor.execute('''
        SELECT 
            u.username AS "User",
            IFNULL(c.site, 'No site') AS "Website",
            IFNULL(c.site_username, 'No username') AS "Site Username",
            IFNULL(c.site_password, 'No password') AS "Hashed Password"
        FROM users u
        LEFT JOIN credentials c ON u.id = c.user_id
    ''')

    # Fetch all rows
    rows = cursor.fetchall()

    # Define the CSV file path
    current_directory = "./password-manager/"
    file_name = "users_and_credentials.csv"
    csv_file_path = os.path.join(current_directory, file_name)

    os.makedirs(current_directory, exist_ok=True)
    # Write to CSV
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["User", "Website", "Site Username", "Hashed Password"])  # Write the header
        writer.writerows(rows)  # Write the data rows

    conn.close()
    return csv_file_path

# Call the export function and get the path
csv_path = export_users_and_credentials_to_csv()
print(f"CSV file created at: {csv_path}")

# Main Program
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
