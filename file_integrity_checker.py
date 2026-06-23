import hashlib
import os
import time


def calculate_file_hash(file_path):
    # Create an empty SHA-256 hashing object
    sha256_hash = hashlib.sha256()
    
    try:
        # Open the file in Read-Binary ('rb') mode securely
        with open(file_path, "rb") as f:
            # Read the file in small chunks to protect computer memory
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        # Return the final hexadecimal string fingerprint
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        # Return None if the file doesn't exist on the system
        return None


# Create a dictionary directory to store our baseline tracking data
file_hashes_directory = {}

# Define the path of the specific folder we want to monitor for breaches
TARGET_DIR = "./" 

print(f"[*] Initializing File Integrity Checker Baseline Tracker...")
print(f"[*] Scanning directory: {TARGET_DIR} for file fingerprints...\n")

# Loop through all files in target directory to establish the baseline records
for file_name in os.listdir(TARGET_DIR):
    file_path = os.path.join(TARGET_DIR, file_name)
    
    # We are only fingerprinting physical files (ignoring sub-folders)
    if os.path.isfile(file_path):
        current_hash = calculate_file_hash(file_path)
        if current_hash:
            # Save the file path and its clean hash into our baseline index registry
            file_hashes_directory[file_path] = current_hash
            print(f"[SUCCESS] Registered Baseline File: {file_name}")
            print(f"-> SHA-256 Hash Record: {current_hash}\n")

print("[*] Baseline Registry fully established. Monitoring engine armed.")


print("\n[!] Continuous monitoring loop engaged. Scanning for anomalies every 3 seconds...\n")

try:
    # Run an infinite loop to simulate a real-time background security service
    while True:
        # Pause the script for 3 seconds before the next sweep to protect system resources
        time.sleep(3)
        
        # Check for modified files or deleted files
        for file_path, baseline_hash in list(file_hashes_directory.items()):
            # If a previously registered file vanishes, it means it was deleted
            if not os.path.exists(file_path):
                print(f"[ALERT!!!] File DELETED by user or attacker: {file_path}")
                del file_hashes_directory[file_path] # Remove it from baseline registry
                continue
                
            # Re-calculate the fingerprint to see if anything changed
            current_hash = calculate_file_hash(file_path)
            
            # If the new fingerprint doesn't match the baseline, trigger an alarm!
            if current_hash != baseline_hash:
                print(f"[CRITICAL ALERT!!!] File ALTERED / TAMPERED WITH: {file_path}")
                print(f"-> Original Baseline: {baseline_hash}")
                print(f"-> New Malicious Hash: {current_hash}\n")
                # Update the database record with the new state so it stops alerting repeatedly
                file_hashes_directory[file_path] = current_hash

except KeyboardInterrupt:
    # Stop the live security scanner when you press Ctrl+C in the terminal
    print("\n[*] File Integrity Monitor safely disarmed. Exiting security service.")
