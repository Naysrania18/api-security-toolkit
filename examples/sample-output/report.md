# API Security Scan Report

- **Target:** `http://127.0.0.1:5000`
- **Tool:** api-security-toolkit 0.1.0
- **Findings:** 4

> Only test systems you own or are authorized to test.

## 1. [HIGH] Broken Object Level Authorization

- **Endpoint:** `GET /books/v1/{book_title}`
- **OWASP:** API1:2023
- **Confidence:** low
- **Description:** User 'user_b' could read object 'bookTitle41' that was discovered through user 'user_a'.
- **Evidence:** `GET /books/v1/bookTitle41 -> 200 for both users (body 83 bytes)`
- **Remediation:** Enforce object-level authorization on every request: compare the authenticated user to the object's owner before returning data.

## 2. [HIGH] Broken Object Level Authorization

- **Endpoint:** `GET /users/v1/{username}`
- **OWASP:** API1:2023
- **Confidence:** low
- **Description:** User 'user_b' could read object 'name1' that was discovered through user 'user_a'.
- **Evidence:** `GET /users/v1/name1 -> 200 for both users (body 48 bytes)`
- **Remediation:** Enforce object-level authorization on every request: compare the authenticated user to the object's owner before returning data.

## 3. [MEDIUM] Excessive data exposure

- **Endpoint:** `GET /users/v1/_debug`
- **OWASP:** API3:2023
- **Confidence:** medium
- **Description:** Response contains fields that look sensitive: users[].password
- **Evidence:** `GET /users/v1/_debug -> 200, fields: ['users[].password']`
- **Remediation:** Return only the fields the client needs (explicit response schemas / DTOs) and never expose secrets or password hashes.

## 4. [MEDIUM] Possible SQL/NoSQL injection

- **Endpoint:** `GET /users/v1/{username}`
- **OWASP:** API8:2023
- **Confidence:** low
- **Description:** Parameter 'username' (path) triggered server error 500 (baseline 404) when sent the payload "'".
- **Evidence:** `payload="'" -> HTTP 500`
- **Remediation:** Use parameterized queries / an ORM, validate input types, and never return raw database errors to clients.
