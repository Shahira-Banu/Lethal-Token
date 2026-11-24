import requests
import json
from datetime import datetime

class AlertNotifier:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def send_alert(self, title: str, description: str, fields: dict, severity: str = "HIGH"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_code = 15158332 if severity == "HIGH" else 3066993

        embed_fields = [{"name": k, "value": str(v), "inline": True} for k, v in fields.items()]

        payload = {
            "embeds": [
                {
                    "title": f"🚨 [LethalToken Alert] {title}",
                    "description": description,
                    "color": color_code,
                    "fields": embed_fields,
                    "footer": {"text": f"LethalToken Defense System • {timestamp}"}
                }
            ]
        }

        print(f"\n[!] ALERT TRIGGERED: {title}")
        for k, v in fields.items():
            print(f"    - {k}: {v}")

        if self.webhook_url:
            try:
                response = requests.post(
                    self.webhook_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                if response.status_code in (200, 204):
                    print("[+] Webhook notification delivered successfully.")
                else:
                    print(f"[-] Webhook delivery failed with status: {response.status_code}")
            except Exception as e:
                print(f"[-] Failed to deliver webhook: {e}")