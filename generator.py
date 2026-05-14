import secrets
import string

def generate_strong_password(length):
    """Generates a high-entropy password using all character sets."""
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()"
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        if check_security(password)[0]:
            break
    return password

def check_security(password):
    """Returns (True/False, List of Missing Requirements)."""
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_num = any(c.isdigit() for c in password)
    has_sym = any(c in "!@#$%^&*()" for c in password)
    is_long = len(password) >= 8

    is_secure = all([has_upper, has_lower, has_num, has_sym, is_long])
    
    missing = []
    if not is_long: missing.append("at least 8 characters")
    if not has_upper: missing.append("uppercase")
    if not has_num: missing.append("numbers")
    if not has_sym: missing.append("symbols")
    
    return is_secure, missing