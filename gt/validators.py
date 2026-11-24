from django.core.exceptions import ValidationError

SQLITE_MAX_INT = (1 << 63) - 1


def is_valid_sqlite_id(value):
    """Return True if value is a plain int within signed 64-bit positive ID bounds."""
    return type(value) is int and 1 <= value <= SQLITE_MAX_INT


def parse_sqlite_id(raw, *, min_value=1):
    """Parse an ASCII digit string within signed 64-bit SQLite integer bounds, or return None."""
    if isinstance(raw, str) and raw.isascii() and raw.isdigit():
        value = int(raw)
        if min_value <= value <= SQLITE_MAX_INT:
            return value
    return None


def validate_no_invisible_characters(value):
    if any(ord(char) in range(0, 32) for char in value):
        raise ValidationError("不得包含空格、回车等不可见字符")
