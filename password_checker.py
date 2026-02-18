import math
import re
import requests
import hashlib

COMMON_WORDS = ["password", "admin", "welcome", "letmein", "qwerty"]

def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def dictionary_check(password: str):
    return [w for w in COMMON_WORDS if w in password.lower()]

def hibp_check(password: str):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    for line in res.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return True, int(count)
    return False, 0

def score_password(password: str):
    entropy = calculate_entropy(password)
    dictionary_hits = dictionary_check(password)
    pwned, count = hibp_check(password)
    policy_issues = policy_check(password)

    score = 0
    reasons = []

    if entropy >= 40:
        score += 1
    else:
        reasons.append("Low entropy")

    if not dictionary_hits:
        score += 1
    else:
        reasons.append(f"Contains dictionary word(s): {dictionary_hits}")

    if not pwned:
        score += 1
    else:
        reasons.append(f"Found in data breaches ({count} times)")

    strength = ["Weak", "Medium", "Strong"][min(score, 2)]

    return {
        "entropy": entropy,
        "strength": strength,
        "reasons": reasons if reasons else ["Good password practices detected"],
        "policy_issues": policy_issues
    }

def policy_check(password: str):
    issues = []

    if len(password) < 12:
        issues.append("At least 12 characters required")
    if not re.search(r"[A-Z]", password):
        issues.append("At least one uppercase letter required")
    if not re.search(r"[a-z]", password):
        issues.append("At least one lowercase letter required")
    if not re.search(r"[0-9]", password):
        issues.append("At least one digit required")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("At least one special character required")

    return issues

