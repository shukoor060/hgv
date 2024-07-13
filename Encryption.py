import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

ENCRYPTED_FILE_EXTENSION = ".enc"  # Extension for encrypted files
SALT_FILE_EXTENSION = ".salt"  # Extension for salt files

def generate_key_from_passphrase(passphrase, salt=None):
    """
    Generate a key from the given passphrase and salt using PBKDF2.
    If no salt is provided, generate a new random salt.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a new random salt
    
    # Create a key derivation function (KDF) instance
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    # Derive the key using the passphrase and KDF
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt

def secure_delete(file_path):
    """
    Securely delete a file by overwriting it with random data before deletion.
    """
    if not os.path.exists(file_path):
        return

    # Get the file size
    file_size = os.path.getsize(file_path)
    
    # Overwrite the file with random data
    with open(file_path, "wb") as f:
        f.write(os.urandom(file_size))
    
    # Delete the file
    os.remove(file_path)

def encrypt_file(passphrase, file_path):
    """
    Encrypt the specified file using a passphrase. 
    Securely delete the original file after encryption.
    """
    try:
        # Generate a key from the passphrase
        key, salt = generate_key_from_passphrase(passphrase)
        
        # Create a Fernet instance for encryption
        fernet = Fernet(key)
        
        # Read the file content
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Encrypt the data
        encrypted_data = fernet.encrypt(file_data)
        
        # Write the encrypted data to a new file
        encrypted_file_path = file_path + ENCRYPTED_FILE_EXTENSION
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        # Store the salt in a separate file
        salt_file_path = file_path + SALT_FILE_EXTENSION
        with open(salt_file_path, 'wb') as salt_file:
            salt_file.write(salt)
        
        # Securely delete the original file
        secure_delete(file_path)
        
        print(f"File '{file_path}' encrypted successfully and original securely deleted.")
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except PermissionError:
        print(f"Error: Permission denied when trying to access '{file_path}'.")
    except IsADirectoryError:
        print(f"Error: Expected a file but found a directory: '{file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def decrypt_file(passphrase, encrypted_file_path):
    """
    Decrypt the encrypted file using the provided passphrase.
    Securely delete the encrypted file and salt file after decryption.
    """
    try:
        # Read the salt from the salt file
        salt_file_path = encrypted_file_path.replace(ENCRYPTED_FILE_EXTENSION, SALT_FILE_EXTENSION)
        with open(salt_file_path, 'rb') as salt_file:
            salt = salt_file.read()
        
        # Generate the key from the passphrase and salt
        key, _ = generate_key_from_passphrase(passphrase, salt)
        
        # Create a Fernet instance for decryption
        fernet = Fernet(key)
        
        # Read the encrypted data from the file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        try:
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken:
            print("Incorrect passphrase.")
            return
        
        # Write the decrypted data back to the original file
        original_file_path = encrypted_file_path.replace(ENCRYPTED_FILE_EXTENSION, "")
        with open(original_file_path, 'wb') as file:
            file.write(decrypted_data)
        
        # Securely delete the encrypted file and salt file
        secure_delete(encrypted_file_path)
        secure_delete(salt_file_path)
        
        print(f"File '{original_file_path}' decrypted successfully and encrypted version securely deleted.")
    except FileNotFoundError:
        print(f"Error: The encrypted file or salt file was not found.")
    except PermissionError:
        print(f"Error: Permission denied when trying to access the files.")
    except IsADirectoryError:
        print(f"Error: Expected a file but found a directory: '{encrypted_file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def encrypt_folder(passphrase, folder_path):
    """
    Encrypt all files in the specified folder using a passphrase. 
    Securely delete the original files after encryption.
    """
    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(passphrase, file_path)
        print(f"Folder '{folder_path}' encrypted successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def decrypt_folder(passphrase, encrypted_folder_path):
    """
    Decrypt all files in the specified encrypted folder using the provided passphrase.
    Securely delete the encrypted files and salt files after decryption.
    """
    try:
        for root, _, files in os.walk(encrypted_folder_path):
            for file in files:
                if file.endswith(ENCRYPTED_FILE_EXTENSION):
                    encrypted_file_path = os.path.join(root, file)
                    decrypt_file(passphrase, encrypted_file_path)
        print(f"Folder '{encrypted_folder_path}' decrypted successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def main():
    """
    Main function to handle user input for encrypting or decrypting a file or folder.
    """
    while True:
        # Prompt the user to choose an action
        action = input("Enter 'e' to encrypt, 'd' to decrypt, or 'q' to quit: ").lower()
        
        if action == 'q':
            break
        elif action in ['e', 'd']:
            passphrase = input("Enter the passphrase: ")
            path = input("Enter the path to the file or folder: ")
            
            if action == 'e':
                if os.path.isdir(path):
                    encrypt_folder(passphrase, path)
                else:
                    encrypt_file(passphrase, path)
            else:
                if os.path.isdir(path):
                    decrypt_folder(passphrase, path)
                else:
                    decrypt_file(passphrase, path)
        else:
            print("Invalid action. Please try again.")

if __name__ == "__main__":
    main()
