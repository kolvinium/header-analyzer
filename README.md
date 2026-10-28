# Email Header Analyzer

A small Python command-line tool that reads a saved email (.eml) and summarizes
its route, authentication results, and sender mismatches. It helps spot
possible spoofing by checking the headers.

## Usage
    python3 analyzer.py samples/spoofed.eml

## What it checks
- The Received route, shown oldest hop first
- SPF, DKIM, and DMARC results from the Authentication-Results header
- Whether the From, Return-Path, and Reply-To domains match

## Example output
```
From:        IT Support <support@example.com>
Return-Path: <bounce@mailer.example.org>
Reply-To:    helpdesk@example.net
Subject:     Urgent: verify your account

Route (oldest first):
  1. from unknown -> by mx.example.net | Tue, 27 Oct 2026 09:10:09 -0500

Authentication:
  SPF: fail
  DKIM: none
  DMARC: fail

Red flags:
  - From domain (example.com) differs from Return-Path domain (mailer.example.org)
  - From domain (example.com) differs from Reply-To domain (example.net)
  - SPF result: fail
  - DKIM result: none
  - DMARC result: fail
```

## Running the tests
    python3 -m unittest discover -s tests -v

## Limitations
- It does not verify DKIM signatures or query DNS. It only reads results
  already written into the headers.
- It does not detect display-name tricks or look-alike domains.
- Samples use fake data (example.com and documentation IP ranges).

## What I learned
- Early on the script crashed on emails with no Received header, because
  `msg.get()` style lookups return None. Using `get_all('Received', [])`
  returns an empty list, so the code handles it.
- The first version of the hop parser split the header on spaces and read
  the wrong fields, so I rewrote it with regular expressions.
- SPF checks which servers may send for a domain, DKIM checks a signature,
  and DMARC ties both to the From domain.
- Next I would verify DKIM signatures and look up DNS records.
