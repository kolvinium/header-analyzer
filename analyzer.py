import sys
import email

def parse_email_header(file_path):
    with open(file_path, 'r') as file:
        email_content = file.read()
    msg = email.message_from_string(email_content)
    return {
        'From': msg.get('From'),
        'Return-Path': msg.get('Return-Path'),
        'Reply-To': msg.get('Reply-To'),
        'Subject': msg.get('Subject'),
        'Received': msg.get_all('Received', [])
    }

def parse_received_headers(received_headers):
    if not received_headers:
        print("No Received headers found.")
        return []
    hops = []
    for header in received_headers:
        parts = header.split()
        date_part = parts[1] if len(parts) > 1 else ''
        date = date_part.split(';')[0].strip()
        hop = {
            'date': date,
            'by': parts[2] if len(parts) > 2 else ''
        }
        hops.append(hop)
    return hops

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <eml_file_path>")
        sys,exit(1)
    file_path = sys.argv[1]
    headers = parse_email_header(file_path)
    received_headers = headers['Received']
    hops = parse_received_headers(received_headers)
    print("Received Headers:")
    for hop in hops:
        print(f"Date: {hop['date']}, By: {hop['by']}")
