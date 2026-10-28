import re
import sys
from email import message_from_binary_file
from email.utils import parseaddr


def parse_email(file_path):
    with open(file_path, "rb") as f:
        return message_from_binary_file(f)


def get_domain(address):
    addr = parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def parse_received_headers(received_headers):
    hops = []
    for header in received_headers:
        header = " ".join(header.split())
        from_match = re.search(r"\bfrom\s+(\S+)", header)
        by_match = re.search(r"\bby\s+(\S+)", header)
        date = header.rsplit(";", 1)[-1].strip() if ";" in header else ""
        hops.append({
            "from": from_match.group(1) if from_match else "?",
            "by": by_match.group(1) if by_match else "?",
            "date": date,
        })
    hops.reverse()  # headers are listed newest first; show oldest first
    return hops


def get_auth_results(msg):
    results = {"spf": "not found", "dkim": "not found", "dmarc": "not found"}
    for header in msg.get_all("Authentication-Results", []):
        for name in results:
            m = re.search(rf"\b{name}=(\w+)", header, re.IGNORECASE)
            if m:
                results[name] = m.group(1).lower()
    return results


def find_red_flags(msg, auth):
    flags = []
    from_d = get_domain(msg.get("From"))
    return_d = get_domain(msg.get("Return-Path"))
    reply_d = get_domain(msg.get("Reply-To"))
    if from_d and return_d and from_d != return_d:
        flags.append(f"From domain ({from_d}) differs from Return-Path domain ({return_d})")
    if from_d and reply_d and from_d != reply_d:
        flags.append(f"From domain ({from_d}) differs from Reply-To domain ({reply_d})")
    for name, result in auth.items():
        if result != "pass":
            flags.append(f"{name.upper()} result: {result}")
    return flags


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyzer.py <file.eml>")
        sys.exit(1)
    try:
        msg = parse_email(sys.argv[1])
    except OSError as err:
        print(f"Could not read file: {err}")
        sys.exit(1)

    print(f"From:        {msg.get('From')}")
    print(f"Return-Path: {msg.get('Return-Path')}")
    print(f"Reply-To:    {msg.get('Reply-To')}")
    print(f"Subject:     {msg.get('Subject')}")

    hops = parse_received_headers(msg.get_all("Received", []))
    print("\nRoute (oldest first):")
    if not hops:
        print("  No Received headers found.")
    for i, hop in enumerate(hops, 1):
        print(f"  {i}. from {hop['from']} -> by {hop['by']} | {hop['date']}")

    auth = get_auth_results(msg)
    print("\nAuthentication:")
    for name, result in auth.items():
        print(f"  {name.upper()}: {result}")

    flags = find_red_flags(msg, auth)
    print("\nRed flags:")
    if flags:
        for flag in flags:
            print(f"  - {flag}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
