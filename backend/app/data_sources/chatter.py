import random

CHATTER = [
    "selling telecom database access full dump",
    "planning ddos on banking servers tonight",
    "got root access to payment gateway",
    "who has 0day for apache?",
    "leaking customer data soon",
    "anyone want creds for airline system?",
]

def gen_chatter(n=10):
    return [
        {
            "source": "chatter_sim",
            "title": "forum post",
            "text": random.choice(CHATTER),
            "url": "chatter://forum"
        }
        for _ in range(n)
    ]
