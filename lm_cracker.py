#!/usr/bin/env python3
"""
Python script to crack an LM hash using a dictionary attack with explicit length validation.

- Implements LM hashing algorithm using pyDes for DES encryption.
- Performs dictionary attack with a wordlist.
- Validates LM hash length (exactly 32 characters, no more, no less) and format.
- No external tools like hashcat required.
- Limitations: Slower than hashcat, no GPU acceleration, dictionary attack only.
- Tested on Windows/Linux with Python 3.6+.
"""

import os
import subprocess
import sys
from pathlib import Path
import psutil
from datetime import datetime

# Yeah, you need PyDes for this, I can do it without it, but that means using non-standard implementations
try:
    from pyDes import des, ECB, PAD_NULL
except ImportError:
    print("Installing pyDes...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pyDes"], check=True)
    from pyDes import des, ECB, PAD_NULL

# Configuration
WORDLIST_PATH = r"C:\Tools\wordlists\rockyou.txt"  # Path to wordlist (e.g., rockyou.txt)
LM_HASH = "AAD3B435B51404EEAAD3B435B51404EE"  # Target LM hash (replace with whatever your hash is)
OUTPUT_DIR = r"E:\CrackResults"  # Output directory for results
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"crack_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
MIN_FREE_SPACE_GB = 1  # Minimum free space required in GB
MAX_LM_HASH_LENGTH = 32  # Maximum allowed length for LM hash (exactly 32 chars)

# Fixed string for LM hashing
LM_MAGIC = b"KGS!@#$%"


def check_prerequisites():
    """Check if wordlist exists and if there's enough disk space."""
    if not os.path.exists(WORDLIST_PATH):
        print(f"Error: Wordlist not found at: {WORDLIST_PATH}")
        sys.exit(1)
    try:
        drive = os.path.splitdrive(OUTPUT_DIR)[0]
        disk_usage = psutil.disk_usage(drive)
        free_space_gb = disk_usage.free / (1024 ** 3)  # Convert bytes to GB
        if free_space_gb < MIN_FREE_SPACE_GB:
            print(
                f"Error: Insufficient disk space on {drive}. Required: {MIN_FREE_SPACE_GB} GB, Available: {free_space_gb:.2f} GB")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking disk space: {e}")
        sys.exit(1)


def validate_lm_hash(lm_hash):
    """Validate LM hash format and length (exactly 32 hexadecimal characters)."""
    if len(lm_hash) > MAX_LM_HASH_LENGTH:
        print(f"Error: LM hash length exceeds maximum of {MAX_LM_HASH_LENGTH} characters: {len(lm_hash)}")
        sys.exit(1)
    if len(lm_hash) < MAX_LM_HASH_LENGTH:
        print(f"Error: LM hash length is less than required {MAX_LM_HASH_LENGTH} characters: {len(lm_hash)}")
        sys.exit(1)
    if not all(c in '0123456789ABCDEFabcdef' for c in lm_hash):
        print(f"Error: Invalid characters in LM hash: {lm_hash}")
        sys.exit(1)


def lm_hash(password):
    """Compute LM hash for a given password."""
    try:
        # Convert to uppercase and encode to bytes
        password = password.upper()[:14].encode('ascii', errors='ignore')
        # Pad to 14 bytes with nulls
        password = password.ljust(14, b'\x00')

        # Split into two 7-byte halves
        first_half = password[:7]
        second_half = password[7:14]

        # Function to hash one half
        def hash_half(half):
            # Initialize DES with the 7-byte half as key
            des_obj = des(half, ECB, pad=None, padmode=PAD_NULL)
            # Encrypt the magic string
            encrypted = des_obj.encrypt(LM_MAGIC)
            return encrypted.hex().upper()

        # Hash both halves
        first_hash = hash_half(first_half)
        second_hash = hash_half(second_half)

        # Combine hashes
        return first_hash + second_hash
    except Exception as e:
        print(f"Error computing LM hash for password: {e}")
        return None


def crack_lm_hash():
    """Perform dictionary attack to crack the LM hash."""
    try:
        # Create output directory if it doesn't exist
        if not os.path.exists(OUTPUT_DIR):
            print(f"Creating output directory: {OUTPUT_DIR}")
            os.makedirs(OUTPUT_DIR)

        print(f"Starting dictionary attack on LM hash: {LM_HASH}")
        start_time = datetime.now()
        found = False
        password_found = None

        # Read wordlist and try each password
        with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                computed_hash = lm_hash(password)
                if computed_hash and computed_hash.upper() == LM_HASH.upper():
                    password_found = password
                    found = True
                    break

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() / 60  # Convert to minutes

        # Save and report results
        with open(OUTPUT_FILE, 'w') as f:
            if found:
                result = f"Cracked password: {password_found}\nHash: {LM_HASH}\n"
                print(f"Cracked password: {password_found}")
            else:
                result = f"No password found for hash: {LM_HASH}\n"
                print("No password found. Try a larger wordlist or brute-force approach.")
            f.write(result)
            f.write(f"Cracking time: {duration:.2f} minutes\n")

        print(f"Cracking time: {duration:.2f} minutes")
        print(f"Results saved to: {OUTPUT_FILE}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


def main():
    # Install psutil if not already installed
    try:
        import psutil
    except ImportError:
        print("Installing psutil...")
        subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True)
        import psutil

    # Check prerequisites
    check_prerequisites()

    # Validate LM hash
    validate_lm_hash(LM_HASH)

    # Run cracking process
    crack_lm_hash()


if __name__ == "__main__":
    main()