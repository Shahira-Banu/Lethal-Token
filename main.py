import sys
import time
import os
from notifier import AlertNotifier
from honey_tripwire import start_honey_tripwire
from quishing_inspector import inspect_qr_or_url

def print_banner():
    print("""
    =======================================================
               LETHALTOKEN SECURITY DEFENDER
    [Digital Bait Tripwire + Anti-Quishing Link Inspector]
    =======================================================
    """)

def main():
    print_banner()

    webhook_url = input("[?] Enter Discord/Telegram Webhook URL (press Enter to skip): ").strip()
    notifier = AlertNotifier(webhook_url=webhook_url if webhook_url else None)

    print("\nSelect Operating Mode:")
    print("1. Start Honey-Credential Tripwire (Background File Guard)")
    print("2. Inspect QR Code Image (Anti-Quishing)")
    print("3. Inspect Shortened Link / URL")
    print("4. Exit")

    choice = input("\nEnter choice (1-4): ").strip()

    if choice == "1":
        watch_dir = input("[?] Directory to place trap file (default: './trap_folder'): ").strip()
        if not watch_dir:
            watch_dir = "./trap_folder"

        observer, trap_path = start_honey_tripwire(watch_dir, notifier=notifier)
        print("\n[+] Guard is running. Press Ctrl+C to stop monitoring.\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\n[*] Stopping file guard observer...")
        observer.join()

    elif choice == "2":
        img_path = input("[?] Enter path to QR code image file: ").strip()
        if os.path.exists(img_path):
            try:
                inspect_qr_or_url(img_path, is_image=True, notifier=notifier)
            except Exception as e:
                print(f"[-] Error processing QR code: {e}")
        else:
            print("[-] Image file not found.")

    elif choice == "3":
        url_input = input("[?] Enter URL to inspect: ").strip()
        if url_input:
            inspect_qr_or_url(url_input, is_image=False, notifier=notifier)
        else:
            print("[-] Invalid URL.")

    elif choice == "4":
        print("[*] Exiting LethalToken.")
        sys.exit(0)

    else:
        print("[-] Invalid selection.")

if __name__ == "__main__":
    main()