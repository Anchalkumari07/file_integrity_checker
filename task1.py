import hashlib
import os
import json

HASH_RECORD_FILE = "file_hashes.json"

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None

def load_hashes():
    if os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    with open(HASH_RECORD_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)

def add_file(file_path):
    hash_val = calculate_hash(file_path)
    if hash_val:
        hashes = load_hashes()
        hashes[file_path] = hash_val
        save_hashes(hashes)
        print(f"[INFO] File added with hash: {hash_val}")

def check_integrity(file_path):
    current_hash = calculate_hash(file_path)
    if current_hash:
        hashes = load_hashes()
        original_hash = hashes.get(file_path)
        if not original_hash:
            print("[WARNING] File not tracked.")
        elif current_hash == original_hash:
            print("[OK] File is unchanged.")
        else:
            print("[ALERT] File integrity compromised!")

def menu():
    while True:
        print("\n--- File Integrity Checker ---")
        print("1. Add file to monitor")
        print("2. Check file integrity")
        print("3. Exit")
        choice = input("Enter choice (1/2/3): ")

        if choice == '1':
            path = input("Enter full file path: ").strip()
            add_file(path)
        elif choice == '2':
            path = input("Enter full file path: ").strip()
            check_integrity(path)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    menu()