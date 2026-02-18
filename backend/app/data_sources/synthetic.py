import random

ATTACK_TEMPLATES = [
    "failed login attempt for admin from {ip}",
    "sql injection detected: ' OR 1=1 --",
    "leaked api key: sk_live_{rand}",
    "exposed jwt token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{rand}",
    "aws key found: AKIA{rand}",
    "database creds exposed user=admin password={rand}",
]

IPS = ["8.8.8.8", "1.1.1.1", "185.23.44.1"]

def gen_synthetic_logs(n=10):
    data = []

    for _ in range(n):
        template = random.choice(ATTACK_TEMPLATES)

        text = template.format(
            ip=random.choice(IPS),
            rand=random.randint(100000, 999999)
        )

        data.append({
            "source": "synthetic_logs",
            "title": "simulated attack",
            "text": text,
            "url": "synthetic://log"
        })

    return data
