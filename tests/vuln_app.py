"""A tiny, deliberately vulnerable Flask API used ONLY as a local test target.

Planted weaknesses (each has a safe counterpart so the checks can be tested for false positives):
  * GET /api/notes/<id>          - BOLA: no ownership check
  * GET /api/safe-notes/<id>     - correct ownership check (negative control)
  * GET /api/admin/stats         - broken auth: declared secured but never checks the token
  * GET /api/me                  - correct auth (negative control)
  * GET /api/search?q=           - leaks a SQL error on a quote character
  * GET /api/profile             - returns password_hash (excessive data exposure)
Never deploy this. It binds to localhost in tests.
"""

from __future__ import annotations

from flask import Flask, jsonify, request

TOKENS = {"token-alice": "alice", "token-bob": "bob"}
NOTES = {
    "1": {"id": "1", "owner": "alice", "text": "alice private note"},
    "2": {"id": "2", "owner": "alice", "text": "alice second note"},
    "3": {"id": "3", "owner": "bob", "text": "bob private note"},
}


def current_user() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return TOKENS.get(header[7:])
    return None


def create_app() -> Flask:
    app = Flask(__name__)

    def own_notes(user: str) -> list[dict]:
        return [n for n in NOTES.values() if n["owner"] == user]

    @app.get("/api/notes")
    def list_notes():
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        return jsonify(notes=own_notes(user))

    @app.get("/api/notes/<note_id>")
    def get_note(note_id):  # VULNERABLE: BOLA
        if not current_user():
            return jsonify(error="unauthorized"), 401
        note = NOTES.get(note_id)
        return (jsonify(note), 200) if note else (jsonify(error="not found"), 404)

    @app.get("/api/safe-notes")
    def list_safe_notes():
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        return jsonify(notes=own_notes(user))

    @app.get("/api/safe-notes/<note_id>")
    def get_safe_note(note_id):  # SAFE: checks owner
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        note = NOTES.get(note_id)
        if not note or note["owner"] != user:
            return jsonify(error="not found"), 404
        return jsonify(note)

    @app.get("/api/admin/stats")
    def admin_stats():  # VULNERABLE: broken authentication
        return jsonify(users=2, notes=len(NOTES))

    @app.get("/api/me")
    def me():  # SAFE
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        return jsonify(username=user)

    @app.get("/api/search")
    def search():  # VULNERABLE: SQL error leak
        q = request.args.get("q", "")
        if "'" in q:
            return (
                jsonify(error='sqlite3.OperationalError: unrecognized token: "\'"'),
                500,
            )
        return jsonify(results=[])

    @app.get("/api/profile")
    def profile():  # VULNERABLE: excessive data exposure
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        return jsonify(
            username=user, email=f"{user}@example.test", password_hash="5f4dcc3b5aa765d6"
        )

    return app
