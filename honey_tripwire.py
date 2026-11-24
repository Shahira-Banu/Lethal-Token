import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from notifier import AlertNotifier

DEFAULT_TRAP_CONTENT = """# DATABASE CREDENTIALS - DO NOT SHARE
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=admin_backup
DB_PASS=prod_secret_892314781
AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
"""

def inspect_file_access_processes(target_path: str):
    abs_target = os.path.abspath(target_path)
    accessing_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            for open_file in proc.open_files():
                if os.path.abspath(open_file.path) == abs_target:
                    accessing_processes.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "user": proc.info['username'] or "Unknown"
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return accessing_processes

class TripwireHandler(FileSystemEventHandler):
    def __init__(self, trap_path: str, notifier: AlertNotifier):
        self.trap_path = os.path.abspath(trap_path)
        self.notifier = notifier
        self.last_alert_time = 0

    def on_accessed(self, event):
        self._process_event(event, event_type="FILE READ / OPENED")

    def on_modified(self, event):
        self._process_event(event, event_type="FILE MODIFIED")

    def _process_event(self, event, event_type: str):
        if os.path.abspath(event.src_path) == self.trap_path:
            if time.time() - self.last_alert_time < 2:
                return
            self.last_alert_time = time.time()

            procs = inspect_file_access_processes(self.trap_path)
            pid_str = ", ".join([str(p['pid']) for p in procs]) if procs else "Unknown (Transient Process)"
            name_str = ", ".join([p['name'] for p in procs]) if procs else "Unknown Execution Context"
            user_str = ", ".join([p['user'] for p in procs]) if procs else "Unknown"

            self.notifier.send_alert(
                title="Decoy Honey-File Accessed!",
                description="Unauthorized file access detected on decoy credential trap.",
                fields={
                    "Trap File": os.path.basename(self.trap_path),
                    "Event Type": event_type,
                    "Process Name": name_str,
                    "PID": pid_str,
                    "User Context": user_str
                },
                severity="HIGH"
            )

def start_honey_tripwire(watch_directory: str, filename: str = "db_passwords.env", notifier: AlertNotifier = None):
    if not os.path.exists(watch_directory):
        os.makedirs(watch_directory, exist_ok=True)

    trap_file_path = os.path.join(watch_directory, filename)

    if not os.path.exists(trap_file_path):
        with open(trap_file_path, "w") as f:
            f.write(DEFAULT_TRAP_CONTENT)
        print(f"[+] Seeded honey-file trap at: {trap_file_path}")
    else:
        print(f"[*] Honey-file trap ready at: {trap_file_path}")

    event_handler = TripwireHandler(trap_file_path, notifier)
    observer = Observer()
    observer.schedule(event_handler, path=watch_directory, recursive=False)
    observer.start()

    print(f"[*] Tripwire active. Monitoring '{filename}' in real-time...")
    return observer, trap_file_path