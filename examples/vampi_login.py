"""Prepare a local VAmPI instance: reset its DB, register two users, print their tokens.

Usage (VAmPI running on localhost:5000):
    python examples/vampi_login.py            # prints shell-ready export lines

Only ever point this at a VAmPI instance you started yourself.
"""

from __future__ import annotations

import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
USERS = [("apisec_a", "pass_a1"), ("apisec_b", "pass_b1")]


def main() -> int:
    if "127.0.0.1" not in BASE and "localhost" not in BASE:
        print("refusing: this helper only targets localhost", file=sys.stderr)
        return 2
    requests.get(f"{BASE}/createdb", timeout=10)
    tokens = []
    for name, password in USERS:
        requests.post(
            f"{BASE}/users/v1/register",
            json={"username": name, "password": password, "email": f"{name}@example.test"},
            timeout=10,
        )
        r = requests.post(
            f"{BASE}/users/v1/login", json={"username": name, "password": password}, timeout=10
        )
        r.raise_for_status()
        tokens.append(r.json()["auth_token"])
    # Each user also creates a book so there is an owned object to test BOLA against.
    for tok, title in zip(tokens, ["book_of_a", "book_of_b"], strict=True):
        requests.post(
            f"{BASE}/books/v1",
            json={"book_title": title, "secret": f"secret-of-{title}"},
            headers={"Authorization": f"Bearer {tok}"},
            timeout=10,
        )
    print(f"export APISEC_TOKEN_A={tokens[0]}")
    print(f"export APISEC_TOKEN_B={tokens[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
