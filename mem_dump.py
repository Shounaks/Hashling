#!/usr/bin/env python3
"""
Python script for partial memory acquisition on Windows by reading accessible process memory regions.

- Captures memory from user-accessible processes using Windows API.
- Saves output to an external or network location.
- Requires Administrator privileges.
- Limitations: Cannot access kernel memory, protected processes, or full physical RAM.
"""

import ctypes
import os
import sys
from ctypes import wintypes
from datetime import datetime

import psutil

# Configuration
OUTPUT_DIR = r"E:\MemoryDumps"  # External USB or network share path
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"PartialMemoryDump-{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin")
MIN_FREE_SPACE_GB = 16  # Minimum free space required in GB (adjust based on needs)

# Windows API setup
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04


def is_admin():
    """Check if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def check_disk_space(path, min_space_gb):
    """Check if the output location has enough free space."""
    try:
        drive = os.path.splitdrive(path)[0]
        disk_usage = psutil.disk_usage(drive)
        free_space_gb = disk_usage.free / (1024 ** 3)  # Convert bytes to GB
        if free_space_gb < min_space_gb:
            print(
                f"Error: Insufficient disk space on {drive}. Required: {min_space_gb} GB, Available: {free_space_gb:.2f} GB")
            return False
        return True
    except Exception as e:
        print(f"Error checking disk space: {e}")
        return False


def get_system_ram():
    """Get total system RAM in GB."""
    return round(psutil.virtual_memory().total / (1024 ** 3), 2)


def read_process_memory(pid):
    """Read accessible memory regions of a process."""
    try:
        # Open process with all access
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            print(f"Failed to open process PID {pid}: {ctypes.get_last_error()}")
            return None

        # Buffer to store memory
        buffer = ctypes.create_string_buffer(4096)  # 4KB buffer
        memory_data = bytearray()

        # Enumerate memory regions (simplified, assumes sequential regions)
        address = 0
        while True:
            mbi = wintypes.MEMORY_BASIC_INFORMATION()
            if not kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if mbi.State == 0x1000 and mbi.Protect & PAGE_READWRITE:  # Committed and readable/writable
                bytes_read = ctypes.c_size_t(0)
                if ReadProcessMemory(h_process, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                    memory_data.extend(buffer.raw[:bytes_read.value])
            address += mbi.RegionSize

        CloseHandle(h_process)
        return memory_data if memory_data else None
    except Exception as e:
        print(f"Error reading memory for PID {pid}: {e}")
        return None


def main():
    try:
        # Check for Administrator privileges
        if not is_admin():
            print("Error: This script must be run as Administrator.")
            sys.exit(1)

        # Verify output directory exists, create if it doesn't
        if not os.path.exists(OUTPUT_DIR):
            print(f"Warning: Output directory {OUTPUT_DIR} does not exist. Creating it...")
            os.makedirs(OUTPUT_DIR)

        # Check disk space
        if not check_disk_space(OUTPUT_DIR, MIN_FREE_SPACE_GB):
            sys.exit(1)

        # Log system information
        total_ram = get_system_ram()
        print(f"System RAM: {total_ram} GB")
        print(f"Capturing partial memory to: {OUTPUT_FILE}")

        # Start memory acquisition
        print("Starting partial memory acquisition...")
        start_time = time.time()
        total_size = 0

        # Open output file
        with open(OUTPUT_FILE, 'wb') as f:
            # Iterate through all processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    print(f"Reading memory from process: {name} (PID: {pid})")
                    memory_data = read_process_memory(pid)
                    if memory_data:
                        f.write(memory_data)
                        total_size += len(memory_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f"Skipping process {name} (PID: {pid}): Access denied or process terminated")
                    continue

        end_time = time.time()
        duration = (end_time - start_time) / 60  # Convert to minutes
        file_size_gb = total_size / (1024 ** 3)  # Convert bytes to GB

        # Verify output file
        if os.path.exists(OUTPUT_FILE) and total_size > 0:
            print(f"Partial memory dump created at: {OUTPUT_FILE}")
            print(f"File size: {file_size_gb:.2f} GB")
            print(f"Acquisition time: {duration:.2f} minutes")
        else:
            print(f"Error: Failed to create memory dump at: {OUTPUT_FILE}")
            sys.exit(1)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    print("Partial memory acquisition completed successfully.")


if __name__ == "__main__":
    main()
