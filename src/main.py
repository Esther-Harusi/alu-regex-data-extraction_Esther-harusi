#!/usr/bin/env/python3
import re
import json
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE = os.path.join(BASE_DIR, "input", "raw-text.txt")
OUTPUT_FILE = os.path.join(BASE_DIR, "output", "sample-output.json")

#error messages validation
ERR_CARD_WRONG_LENGTH = "Invalid card length"
ERR_CARD_BAD_FORMAT = "Invalid card format"
ERR_CARD_LUHN_FAIL = "Failed Luhn check"
ERR_CARD_TEST_NUMBER = "Test card not allowed"
ERR_CARD_DUPLICATE = "Duplicate card"

ERR_EMAIL_DOUBLE_AT = "Malformed email (double @)"
ERR_EMAIL_MISSING_DOMAIN = "Malformed email (missing domain)"
ERR_EMAIL_DUPLICATE = "Duplicate email"

ERR_PHONE_TOO_SHORT = "Phone number too short"
ERR_PHONE_DUPLICATE = "Duplicate phone number"

#Regex patterns
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

ALU_SI = re.compile(r'^[A-Za-z0-9._%+\-]+@si\.alueducation\.com$')
ALU_ALUMNI = re.compile(r'^[A-Za-z0-9._%+\-]+@alumni\.alueducation\.com$')
ALU_OFFICIAL = re.compile(r'^[A-Za-z0-9._%+\-]+@alueducation\.com$')

PHONE_PATTERN = re.compile(
    r'(?:\+\d{1,3}[\s\-.]?)?'
    r'(?:\(0?\d{1,4}\)[\s\-.]?)?'
    r'\d{3,5}[\s\-.]\d{3,4}'
    r'(?:[\s\-.]?\d{3,4})?'
)

CARD_BROAD = re.compile(r'\b\d{4}[\s\-]\d{4,6}[\s\-]\d{4,6}(?:[\s\-]\d{1,4})?\b')

CARD_AME = re.compile(r'^\d{4}[\s\-]\d{6}[\s\-]\d{5}$')
CARD_16 = re.compile(r'^\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}$')

URL_PATTERN = re.compile(r'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+')

HTML_PATTERN = re.compile(r'</?[A-Za-z][A-Za-z0-9]*(?:\s+[^>]*)?\s*/?>')

HASHTAG_PATTERN = re.compile(r'#[A-Za-z]\w+')

CURRENCY_PATTERN = re.compile(
    r'(?:KES|USD|EUR|GBP)\s*[+\-]?[$€£]?\s*\d{1,3}(?:,\d{3})*\.\d{2}'
    r'|[+\-]?[$€£]\s*\d{1,3}(?:,\d{3})*\.\d{2}'
)

TIME_PATTERN = re.compile(
    r'\b(?:'
    r'(?:1[0-2]|0?[1-9]):[0-5]\d\s?[AP]M'
    r'|(?:[01]\d|2[0-3]):[0-5]\d'
    r')\b',
    re.IGNORECASE
)

#Helpers
def mask_card(card: str) -> str:
    digits = re.sub(r'[\s\-]', '', card)
    if len(digits) < 6:
        return card
    return f"{digits[:3]} {'*' * (len(digits) - 6)} {digits[-3:]}"


def normalize(card: str) -> str:
    return re.sub(r'[\s\-]', '', card)


def luhn(card: str) -> bool:
    digits = [int(d) for d in normalize(card)][::-1]
    return sum(
        d if i % 2 == 0 else d * 2 - 9 * (d * 2 > 9)
        for i, d in enumerate(digits)
    ) % 10 == 0


def is_test_card(card: str) -> bool:
    return normalize(card) in {
        "0000000000000000",
        "9999999999999999",
        "1234567890123456",
        "4111111111111111",
    }


def classify_alu(email: str):
    if ALU_SI.fullmatch(email): return "alu_si"
    if ALU_ALUMNI.fullmatch(email): return "alu_alumni"
    if ALU_OFFICIAL.fullmatch(email): return "alu_official"
    return None


def is_card_shaped(text: str) -> bool:
    return bool(CARD_BROAD.fullmatch(text.strip()))
#security scan
UNSAFE = [
    (re.compile(r'<script[\s\S]*?>[\s\S]*?</script>', re.I), "XSS"),
    (re.compile(r'javascript\s*:', re.I), "JS injection"),
    (re.compile(r'\bDROP\s+TABLE\b', re.I), "SQLi"),
]


def scan(text: str):
    return [
        {"type": label, "snippet": m.group()[:120], "pos": m.start()}
        for pattern, label in UNSAFE
        for m in pattern.finditer(text)
    ]
#Extraction
def extract(text: str):
    result = {}

    flags = scan(text)
    result["input_flagged"] = bool(flags)
    result["security_flags"] = flags

    # Emails
    emails = {"valid": [], "alu": [], "rejected": []}
    seen = set()

    for e in EMAIL_PATTERN.findall(text):
        e = e.strip().lower()

        if e in seen:
            emails["rejected"].append({"value": e, "error": ERR_EMAIL_DUPLICATE})
            continue

        seen.add(e)
        cat = classify_alu(e)

        if cat:
            emails["alu"].append({"address": e, "category": cat})
        else:
            emails["valid"].append(e)

    result["emails"] = emails

    # Phones
    phones = {"valid": [], "rejected": []}
    seen = set()

    for p in PHONE_PATTERN.findall(text):
        digits = re.sub(r'\D', '', p)

        if is_card_shaped(p):
            continue

        if len(digits) < 7:
            phones["rejected"].append({"value": p, "error": ERR_PHONE_TOO_SHORT})
            continue

        if digits in seen:
            phones["rejected"].append({"value": p, "error": ERR_PHONE_DUPLICATE})
            continue

        seen.add(digits)
        phones["valid"].append(p)

    result["phone_numbers"] = phones

    # Cards
    cards = {"valid": [], "rejected": []}
    seen = set()

    for c in CARD_BROAD.findall(text):
        norm = normalize(c)

        if norm in seen:
            cards["rejected"].append({"raw_masked": mask_card(c), "error": ERR_CARD_DUPLICATE})
            continue

        seen.add(norm)

        if is_test_card(c):
            cards["rejected"].append({"raw_masked": mask_card(c), "error": ERR_CARD_TEST_NUMBER})
            continue

        if not (CARD_AME.match(c) or CARD_16.match(c)):
            cards["rejected"].append({"raw_masked": mask_card(c), "error": ERR_CARD_BAD_FORMAT})
            continue

        if not luhn(c):
            cards["rejected"].append({"raw_masked": mask_card(c), "error": ERR_CARD_LUHN_FAIL})
            continue

        cards["valid"].append({
            "raw_masked": mask_card(c),
            "luhn_valid": True
        })

    result["credit_cards"] = cards

    # Simple extractions
    result["urls"] = list(set(URL_PATTERN.findall(text)))
    result["html_tags"] = list(set(HTML_PATTERN.findall(text)))
    result["hashtags"] = list(set(HASHTAG_PATTERN.findall(text)))
    result["currency_amounts"] = list(set(CURRENCY_PATTERN.findall(text)))
    result["times"] = list(set(TIME_PATTERN.findall(text)))

    return result
#Output
def run():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        text = f.read()

    output = extract(text)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("Done. Output saved.")


if __name__ == "__main__":
    run()
