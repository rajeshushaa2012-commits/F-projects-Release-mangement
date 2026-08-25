import hashlib
import hmac
import secrets

# The fixed permission catalog. Admin implicitly has all of these; a normal
# user has exactly the ones an admin has explicitly granted them.
PERMISSIONS = [
    ("view_releases", "View releases"),
    ("create_release", "Create release"),
    ("edit_release", "Edit release"),
    ("delete_release", "Delete release"),
    ("view_conflicts", "View Conflict Tracker"),
    ("create_conflict", "Create conflict"),
    ("edit_conflict", "Edit conflict"),
    ("delete_conflict", "Delete conflict"),
    ("upload_files", "Upload files"),
    ("download_files", "Download files"),
    ("manage_users", "Manage users"),
    ("manage_settings", "Manage settings"),
]
PERMISSION_KEYS = {k for k, _ in PERMISSIONS}

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Returns (salt_hex, hash_hex). Uses PBKDF2-HMAC-SHA256 (stdlib only,
    no compiled dependency, unlike bcrypt — important for a slim Docker build)."""
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), derived.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, derived_hex = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(derived_hex, hash_hex)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)
