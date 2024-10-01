import sys
import time
from clipboard_manager import ClipboardManager

def print_help():
    help_text = """
    Clipboard Manager Help:
    - start: Start the clipboard manager
    - load_history <password>: Load history with the provided password "ola123"
    - verify_signature: Verify the current clipboard history signature
    - verify_entry <entry>: Verify if the entry exists in the clipboard history using hashes
    - clear_history: Clear the clipboard history and related data
    - help: Print this help message
    """
    print(help_text)

def main():
    if len(sys.argv) < 2:
        print_help()
        return
    
    command = sys.argv[1]
    user_id = "default_user"
    cm = ClipboardManager(user_id=user_id)

    if command == "start":
        print("Clipboard monitoring started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping clipboard manager...")
            cm.stop()
            print("Clipboard manager stopped.")
    elif command == "load_history":
        if len(sys.argv) != 3:
            print("Usage: load_history <password>")
        else:
            password = sys.argv[2]
            if password == "ola123":
                cm.load_history(password)
                for entry in cm.history:
                    print(entry)
            else:
                print("Incorrect password. Please provide the correct password.")
    elif command == "verify_signature":
        result = cm.verify_current_signature()
        print(f"Signature valid: {result}")
    elif command == "clear_history":
        cm.clear_history()
    elif command == "help":
        print_help()
    elif command == "verify_entry":
        if len(sys.argv) != 3:
            print("Usage: verify_entry <entry_hash>")
        else:
            entry_hash = sys.argv[2]
            result = cm.verify_entry_hash(entry_hash)
            if result:
                print("Entry hash found in the last encrypted history file.")
            else:
                print("Entry hash not found in the last encrypted history file.")
    else:
        print("Unknown command")
        print_help()

if __name__ == "__main__":
    main()
