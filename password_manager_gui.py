from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, filedialog
import csv
import re
import base64

# Key derivation using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes_256(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Return ciphertext, IV, and tag separately
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')
    encoded_tag = base64.b64encode(encryptor.tag).decode('utf-8')

    print(f"Ciphertext (raw): {ciphertext}")
    print(f"IV (raw): {iv}")
    print(f"Tag (raw): {encryptor.tag}")
    print(f"Base64-encoded ciphertext: {encoded_ciphertext}")
    print(f"Base64-encoded IV: {encoded_iv}")
    print(f"Base64-encoded Tag: {encoded_tag}")

    return encoded_ciphertext, encoded_iv, encoded_tag

def decrypt_aes_256(key, encoded_ciphertext, encoded_iv, encoded_tag):
    # Decode Base64 back to binary
    ciphertext = base64.b64decode(encoded_ciphertext)
    iv = base64.b64decode(encoded_iv)
    tag = base64.b64decode(encoded_tag)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

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
            site_tag TEXT NOT NULL,  -- Add this column
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Trigger for duplicate entries
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS check_duplicate_site
        BEFORE INSERT ON credentials
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN (SELECT COUNT(*) FROM credentials WHERE site = NEW.site AND site_username = NEW.site_username) > 0
                THEN RAISE (ABORT, 'Already an account with that username for that site')
            END;
        END;
    ''')
    conn.commit()
    conn.close()

# Password Hashing with Salt
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
        export_users_and_credentials_to_csv()
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
            derived_key = derive_key(password, bytes.fromhex(stored_salt))  # Ensure derived_key is bytes
            return user_id, derived_key  # Successful login
    # Handle invalid credentials
    messagebox.showerror("Error", "Invalid username or password.")
    return None, None

# Add a Credential
def add_credential(key, user_id, site, site_username, site_password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    try:
        # Encrypt the site password
        encoded_password, encoded_iv, encoded_tag = encrypt_aes_256(key, site_password)

        # Insert into the table with the tag
        cursor.execute('''
            INSERT INTO credentials (user_id, site, site_username, site_password, site_iv, site_tag)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, site, site_username, encoded_password, encoded_iv, encoded_tag))
        conn.commit()

        messagebox.showinfo("Success", "Credential saved successfully!")
        export_users_and_credentials_to_csv()
    except sqlite3.DatabaseError as e:
        conn.rollback()
        messagebox.showerror("Error", f"Failed to add credential: {e}")
    finally:
        cursor.close()
        conn.close()



# View Credentials
def view_credentials(key, user_id):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    cursor.execute('SELECT site, site_username, site_password, site_iv, site_tag FROM credentials WHERE user_id = ?', (user_id,))
    credentials = cursor.fetchall()
    conn.close()

    if credentials:
        result = ""
        for site, username, encoded_password, encoded_iv, encoded_tag in credentials:
            try:
                # Decode and decrypt the password
                plaintext_password = decrypt_aes_256(key, encoded_password, encoded_iv, encoded_tag)
            except Exception as e:
                plaintext_password = "[Decryption Failed]"
                print(f"Decryption error: {e}")  # Debug the error

            result += f"Site: {site}, Username: {username}, Password: {plaintext_password}\n"

        messagebox.showinfo("Your Credentials", result)
    else:
        messagebox.showinfo("Your Credentials", "No credentials stored.")


def delete_credential(user_id, site, site_username):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    try:
        # Delete the specified credential
        cursor.execute('DELETE FROM credentials WHERE user_id = ? AND site = ? AND site_username = ?', (user_id, site, site_username))
        conn.commit()

        if cursor.rowcount > 0:
            messagebox.showinfo("Success", f"Credential for username {site_username} site '{site}' deleted successfully!")
            export_users_and_credentials_to_csv()
        else:
            messagebox.showerror("Error", f"No credential found for username {site_username} from site '{site}'.")
    
    except sqlite3.DatabaseError:
        # Catches errors and ensures the transaction rolls back
        conn.rollback()
        messagebox.showerror("Error", f"An error occured while deleting the credential.")

    finally:
        cursor.close()
        conn.close()

# Add a method to update a credential
def update_credential(key, user_id, site, new_username, new_password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    try:
        # Encrypt the new password
        encoded_password, encoded_iv, encoded_tag = encrypt_aes_256(key, new_password)

        # Update the credential in the database
        cursor.execute('''
            UPDATE credentials
            SET site_username = ?, site_password = ?, site_iv = ?, site_tag = ?
            WHERE user_id = ? AND site = ?
        ''', (new_username, encoded_password, encoded_iv, encoded_tag, user_id, site))
        conn.commit()

        if cursor.rowcount > 0:
            messagebox.showinfo("Success", f"Credential for site '{site}' updated successfully!")
            export_users_and_credentials_to_csv()
        else:
            messagebox.showerror("Error", f"No credential found for site '{site}'.")
    except sqlite3.DatabaseError as e:
        conn.rollback()
        messagebox.showerror("Error", f"An error occurred: {e}")
    finally:
        cursor.close()
        conn.close()


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
        self.key = None
        self.root.title("Password Manager")
        self.root.geometry("400x300")
        self.root.configure(bg='lightblue')
        self.show_main_menu()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_main_menu(self):
        self.clear_frame()

        tk.Label(self.root, text="Password Manager", font=("Arial", 20), bg='lightblue').pack(pady=10)
        tk.Button(self.root, text="Register", width=20, command=self.show_register, bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="Login", width=20, command=self.show_login, bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="Quit", width=20, command=self.root.quit, bd=0, padx=20, pady=10).pack(pady=5)

    def show_register(self):
        self.clear_frame()

        tk.Label(self.root, text="Register", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Label(self.root, text="Username:", bg='lightblue').pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="Password:", bg='lightblue').pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        def submit():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "All fields are required.")
                return

            validation_error = validate_password(password)
            if validation_error:
                messagebox.showerror("Error", validation_error)
                return

            register_user(username, password)
            self.show_main_menu()

        tk.Button(self.root, text="Submit", command=submit, bd=0, padx=20, pady=10).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu, bd=0, padx=20, pady=10).pack()

        self.root.update_idletasks()

    def show_login(self):
        self.clear_frame()

        tk.Label(self.root, text="Login", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Label(self.root, text="Username:", bg='lightblue').pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="Password:", bg='lightblue').pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        def submit():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "All fields are required.")
                return

            user_id, derived_key = login_user(username, password)
            if user_id:
                self.user_id = user_id
                self.key = derived_key  # Derived key in bytes
                self.show_dashboard()
            else:
                messagebox.showerror("Error", "Invalid username or password.")

        tk.Button(self.root, text="Submit", command=submit, bd=0, padx=20, pady=10).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu, bd=0, padx=20, pady=10).pack()

        self.root.update_idletasks()

    def show_dashboard(self):
        self.clear_frame()

        tk.Label(self.root, text="Dashboard", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Button(self.root, text="Add Credential", width=20, command=self.show_add_credential, bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="View Credentials", width=20, command=lambda: view_credentials(self.key, self.user_id), bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="Delete Credential", width=20, command=self.show_delete_credential, bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="Update Credential", width=20, command=self.show_update_credential, bd=0, padx=20, pady=10).pack(pady=5)
        tk.Button(self.root, text="Logout", width=20, command=self.logout, bd=0, padx=20, pady=10).pack(pady=5)

    def show_add_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Add Credential", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Label(self.root, text="Website:", bg='lightblue').pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()
        tk.Label(self.root, text="Username:", bg='lightblue').pack()
        site_username_entry = tk.Entry(self.root)
        site_username_entry.pack()
        tk.Label(self.root, text="Password:", bg='lightblue').pack()
        site_password_entry = tk.Entry(self.root, show="*")
        site_password_entry.pack()

        def submit():
            site = site_entry.get().strip()
            site_username = site_username_entry.get().strip()
            site_password = site_password_entry.get().strip()
            if not site or not site_username or not site_password:
                messagebox.showerror("Error", "All fields are required.")
                return

            validation_error = validate_password(site_password)
            if validation_error:
                messagebox.showerror("Error", validation_error)
                return

            try:
                add_credential(self.key, self.user_id, site, site_username, site_password)
                self.show_dashboard()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add credential: {e}")

        tk.Button(self.root, text="Submit", command=submit, bd=0, padx=20, pady=10).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard, bd=0, padx=20, pady=10).pack()

        self.root.update_idletasks()

    def show_delete_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Delete Credential", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Label(self.root, text="Website:", bg='lightblue').pack()
        website_entry = tk.Entry(self.root)
        website_entry.pack()
        tk.Label(self.root, text="Username:", bg='lightblue').pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()

        def submit():
            site = website_entry.get().strip()
            username = username_entry.get().strip()
            if not site:
                messagebox.showerror("Error", "Website field is required.")
                return

            delete_credential(self.user_id, site, username)
            self.show_dashboard()

        tk.Button(self.root, text="Delete", command=submit, bd=0, padx=20, pady=10).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard, bd=0, padx=20, pady=10).pack()

        self.root.update_idletasks()

    def show_update_credential(self):
        self.clear_frame()

        tk.Label(self.root, text="Update Credential", font=("Arial", 16), bg='lightblue').pack(pady=10)
        tk.Label(self.root, text="Website:", bg='lightblue').pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()
        tk.Label(self.root, text="New Username:", bg='lightblue').pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="New Password:", bg='lightblue').pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        def submit():
            site = site_entry.get().strip()
            new_username = username_entry.get().strip()
            new_password = password_entry.get().strip()
            if not site or not new_username or not new_password:
                messagebox.showerror("Error", "All fields are required.")
                return

            update_credential(self.key, self.user_id, site, new_username, new_password)
            self.show_dashboard()

        tk.Button(self.root, text="Update", command=submit, bd=0, padx=20, pady=10).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_dashboard, bd=0, padx=20, pady=10).pack()

        self.root.update_idletasks()

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
            IFNULL(c.site_password, 'No password') AS "Encrypted Password",
            IFNULL(c.site_iv, 'No IV') AS "IV",
            IFNULL(c.site_tag, 'No Tag') AS "Tag"
        FROM users u
        LEFT JOIN credentials c ON u.id = c.user_id
    ''')

    # Fetch all rows
    rows = cursor.fetchall()

    # Define the CSV file path
    current_directory = "./password-manager/"
    file_name = "users_and_credentials.csv"
    csv_file_path = os.path.join(current_directory, file_name)

    # Ensure directory exists
    os.makedirs(current_directory, exist_ok=True)

    # Write to CSV
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["User", "Website", "Site Username", "Encrypted Password", "IV", "Tag"])  # Add headers
        for row in rows:
            writer.writerow(row)  # Write each row to the CSV

    conn.close()
    return csv_file_path


# Call the export function and get the path
#csv_path = export_users_and_credentials_to_csv()
#print(f"CSV file created at: {csv_path}")

# Main Program
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
