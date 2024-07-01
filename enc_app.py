import os
import random
import string
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Global variables to store key pair
private_key = None
public_key = None

def generate_key_pair():
    global private_key, public_key
    # Generate a RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

def encrypt_file():
    global public_key, private_key
    
    input_file_path = filedialog.askopenfilename(title="Choose file for encrypting")
    if input_file_path:
        # Generate a random password
        length = 3
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        messagebox.showinfo("note",f"this is your password if you want to decrypt file: {password} please keep it secretly!")
        # Encrypt the password with public key
        encrypted_password = public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
       
        
        # Save the encrypted password to a file (you may want to store securely)
        password_file_path = input_file_path + ".password"
        with open(password_file_path, "wb") as password_file:
            password_file.write(encrypted_password)
        messagebox.showinfo("note!",f"this is your password file path: '{password_file_path}', you need it to decrypt file, please keep it secretly!")
        
        # Use the password to derive a key for symmetric encryption (e.g., AES)
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Encrypt the file content using the derived key
        with open(input_file_path, "rb") as input_file:
            data = input_file.read()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        
        # Save the encrypted data to a file
        output_file_path = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".bin")
        if output_file_path:
            with open(output_file_path, "wb") as output_file:
                output_file.write(salt + iv + ct)
            messagebox.showinfo("Success!", f"File encrypted and saved at {output_file_path}")

def decrypt_file():
    global private_key
    
    input_file_path = filedialog.askopenfilename(title="Choose file for decrypting")
    if input_file_path:
        # Load the encrypted password from the password file
        messagebox.showinfo("message","Please choose your password file.")
        input_pass_path = filedialog.askopenfilename(title="Choose your password")
        password_file_path = input_pass_path
        try: 
         with open(password_file_path, "rb") as password_file:
            encrypted_password = password_file.read()
        except:
            messagebox.showerror('it is not a file password!')
        
        # Decrypt the password using the private key
        decrypted_password = private_key.decrypt(
            encrypted_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        
        # Ask user to enter password securely
        password = simpledialog.askstring("Enter Password", "Enter password to decrypt:", show='*')
        if not password:
            messagebox.showerror("Error", "Please enter password.")
            return
        
        # Check if the entered password matches the decrypted password
        if password != decrypted_password:
            messagebox.showerror("Error", "Incorrect password.")
            return
        
        # Decrypt the file content using the password
        with open(input_file_path, "rb") as input_file:
            encrypted_data = input_file.read()
        
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ct = encrypted_data[32:]
        
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(ct) + decryptor.finalize()
        
        # Ask user where to save the decrypted file
        output_file_path = filedialog.asksaveasfilename(title="Save decrypted file", defaultextension=".txt")
        if output_file_path:
            with open(output_file_path, "wb") as output_file:
                output_file.write(data)
            messagebox.showinfo("Success", f"Decrypted file saved at {output_file_path}")

def main():
    # Generate key pair at the start of the application
    generate_key_pair()
    
    root = tk.Tk()
    root.title("Encryption/Decryption Tool")
    
    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_file)
    encrypt_button.pack(pady=10)
    
    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_file)
    decrypt_button.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    main()
