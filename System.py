import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib
import sqlite3
from getpass import getpass

class SecureFileManager:
    def __init__(self):
        self.db_conn = sqlite3.connect('secure_files.db')
        self._init_db()
        self.current_user = None
        
    def _init_db(self):
        """Initialize database tables"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                role TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                filepath TEXT,
                owner_id INTEGER,
                encrypted_key TEXT,
                iv TEXT,
                hash TEXT,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                file_id INTEGER,
                user_id INTEGER,
                can_read INTEGER,
                can_write INTEGER,
                can_share INTEGER,
                PRIMARY KEY(file_id, user_id),
                FOREIGN KEY(file_id) REFERENCES files(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                action TEXT,
                file_id INTEGER,
                details TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(file_id) REFERENCES files(id)
            )
        ''')
        self.db_conn.commit()

    def register_user(self, username, password, role='user'):
        """Register a new user with password hashing"""
        salt = get_random_bytes(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, role)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, salt, role))
        self.db_conn.commit()
        return cursor.lastrowid

    def authenticate(self, username, password):
        """Authenticate user"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        if not result:
            return False
            
        user_id, stored_hash, salt = result
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        if input_hash == stored_hash:
            self.current_user = user_id
            self._log_action(user_id, 'LOGIN', None, 'Successful login')
            return True
        else:
            self._log_action(user_id, 'LOGIN_FAIL', None, 'Failed login attempt')
            return False

    def encrypt_file(self, filepath):
        """Encrypt a file with AES-256"""
        if not self.current_user:
            raise PermissionError("Not authenticated")
            
        # Generate encryption key and IV
        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Read and encrypt file
        with open(filepath, 'rb') as f:
            plaintext = f.read()
            
        # Pad the plaintext
        pad_len = AES.block_size - (len(plaintext) % AES.block_size)
        plaintext += bytes([pad_len]) * pad_len
        
        ciphertext = cipher.encrypt(plaintext)
        
        # Generate file hash
        file_hash = hashlib.sha256(plaintext).digest()
        
        # Store encrypted file
        encrypted_path = filepath + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)
            
        # Store file metadata in DB
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO files (filename, filepath, owner_id, encrypted_key, iv, hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (os.path.basename(filepath), encrypted_path, self.current_user, key, iv, file_hash))
        
        file_id = cursor.lastrowid
        
        # Set default permissions (owner has full access)
        cursor.execute('''
            INSERT INTO permissions (file_id, user_id, can_read, can_write, can_share)
            VALUES (?, ?, 1, 1, 1)
        ''', (file_id, self.current_user))
        
        self.db_conn.commit()
        self._log_action(self.current_user, 'ENCRYPT', file_id, f'Encrypted file {filepath}')
        
        return encrypted_path

    def decrypt_file(self, file_id, output_path=None):
        """Decrypt a file"""
        if not self.current_user:
            raise PermissionError("Not authenticated")
            
        # Check permissions
        cursor = self.db_conn.cursor()
        cursor.execute('''
            SELECT f.filepath, f.encrypted_key, f.iv, f.hash, p.can_read
            FROM files f
            LEFT JOIN permissions p ON f.id = p.file_id AND p.user_id = ?
            WHERE f.id = ?
        ''', (self.current_user, file_id))
        
        result = cursor.fetchone()
        if not result or not result[4]:
            self._log_action(self.current_user, 'DECRYPT_DENIED', file_id, 'Permission denied')
            raise PermissionError("Access denied")
            
        filepath, key, iv, expected_hash, _ = result
        
        # Decrypt the file
        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
            
        plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
        
        # Verify integrity
        actual_hash = hashlib.sha256(plaintext).digest()
        if actual_hash != expected_hash:
            self._log_action(self.current_user, 'INTEGRITY_FAIL', file_id, 'File integrity check failed')
            raise ValueError("File integrity check failed")
            
        # Write decrypted file
        if not output_path:
            output_path = filepath[:-4] if filepath.endswith('.enc') else filepath + '.dec'
            
        with open(output_path, 'wb') as f:
            f.write(plaintext)
            
        self._log_action(self.current_user, 'DECRYPT', file_id, f'Decrypted to {output_path}')
        return output_path

    def _log_action(self, user_id, action, file_id, details):
        """Log an action to the audit log"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, file_id, details)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, file_id, details))
        self.db_conn.commit()

if __name__ == "__main__":
    print("🔒 Secure File Management System 🔒")
    manager = SecureFileManager()
    
    # Example usage
    print("\n1. Register new user")
    username = input("Username: ")
    password = getpass("Password: ")
    manager.register_user(username, password)
    
    print("\n2. Authenticate")
    if manager.authenticate(username, password):
        print("✅ Authentication successful")
        
        print("\n3. Encrypt file")
        filepath = input("Enter file path to encrypt: ")
        encrypted_path = manager.encrypt_file(filepath)
        print(f"✅ File encrypted: {encrypted_path}")
        
        print("\n4. Decrypt file")
        decrypted_path = manager.decrypt_file(1)  # Using file_id 1
        print(f"✅ File decrypted: {decrypted_path}")
    else:
        print("❌ Authentication failed")
