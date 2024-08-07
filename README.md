# Applied Cryptography Projects

Welcome to my GitHub repository focused on applied cryptography. Here, 
you'll find a collection of projects and examples showcasing my knowledge 
and skills in the field of cryptography. These projects demonstrate the 
practical application of cryptographic principles and techniques to solve 
real-world problems and enhance security.

## Projects

### 1. Secure Messaging App

# Applied Cryptography Projects

Welcome to my GitHub repository focused on applied cryptography. Here, 
you'll find a collection of projects and examples showcasing my knowledge 
and skills in the field of cryptography. These projects demonstrate the 
practical application of cryptographic principles and techniques to solve 
real-world problems and enhance security.

## Projects

### 1. Secure Messaging App

#### Prerequisites
- Python 3.x
- `cryptography` library (`pip install cryptography`)

#### Steps
1. **Setup and Initialization**
    ```python
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
    from cryptography.hazmat.backends import default_backend
    import os
    ```

2. **Generate RSA Keys for Users**
    ```python
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    ```

3. **Encrypt and Decrypt Messages**
    ```python
    def encrypt_message(public_key, message):
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_message(private_key, encrypted_message):
        decrypted = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    ```

4. **Test the Implementation**
    ```python
    if __name__ == "__main__":
        private_key, public_key = generate_rsa_keys()
        message = "Hello, this is a secure message."
        encrypted_message = encrypt_message(public_key, message)
        print("Encrypted:", encrypted_message)
        decrypted_message = decrypt_message(private_key, 
encrypted_message)
        print("Decrypted:", decrypted_message)
    ```

### 2. Encrypted File Storage

#### Prerequisites
- Python 3.x
- `cryptography` library (`pip install cryptography`)

#### Steps
1. **Setup and Initialization**
    ```python
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import os
    ```

2. **Generate Encryption Key**
    ```python
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key
    ```

3. **Encrypt and Decrypt Files**
    ```python
    def encrypt_file(key, filename):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), 
backend=default_backend())
        encryptor = cipher.encryptor()
        with open(filename, 'rb') as f:
            data = f.read()
        encrypted = iv + encryptor.update(data) + encryptor.finalize()
        with open(filename + '.enc', 'wb') as f:
            f.write(encrypted)

    def decrypt_file(key, filename):
        with open(filename, 'rb') as f:
            iv = f.read(16)
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), 
backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        with open(filename[:-4], 'wb') as f:
            f.write(decrypted)
    ```

4. **Test the Implementation**
    ```python
    if __name__ == "__main__":
        password = "securepassword"
        salt = os.urandom(16)
        key = generate_key(password, salt)
        filename = "test.txt"
        
        encrypt_file(key, filename)
        decrypt_file(key, filename + '.enc')
    ```

### 3. Password Manager

#### Prerequisites
- Python 3.x
- `cryptography` library (`pip install cryptography`)
- `sqlite3` library (part of the standard library)

#### Steps
1. **Setup and Initialization**
    ```python
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import os
    import sqlite3
    ```

2. **Database Setup**
    ```python
    def setup_database():
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    ```

3. **Generate Encryption Key**
    ```python
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key
    ```

4. **Encrypt and Decrypt Passwords**
    ```python
    def encrypt_password(key, password):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), 
backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = iv + encryptor.update(password.encode()) + 
encryptor.finalize()
        return encrypted

    def decrypt_password(key, encrypted_password):
        iv = encrypted_password[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), 
backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_password[16:]) + 
decryptor.finalize()
        return decrypted.decode()
    ```

5. **Store and Retrieve Passwords**
    ```python
    def store_password(site, username, password, key):
        encrypted_password = encrypt_password(key, password)
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('INSERT INTO passwords (site, username, password) VALUES 
(?, ?, ?)', (site, username, encrypted_password))
        conn.commit()
        conn.close()

    def retrieve_password(site, username, key):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('SELECT password FROM passwords WHERE site=? AND 
username=?', (site, username))
        result = c.fetchone()
        conn.close()
        if result:
            encrypted_password = result[0]
            return decrypt_password(key, encrypted_password)
        return None
    ```

6. **Test the Implementation**
    ```python
    if __name__ == "__main__":
        setup_database()
        master_password = "securepassword"
        salt = os.urandom(16)
        key = generate_key(master_password, salt)
        
        store_password("example.com", "user1", "mypassword123", key)
        retrieved_password = retrieve_password("example.com", "user1", 
key)
        print("Retrieved Password:", retrieved_password)
    ```
