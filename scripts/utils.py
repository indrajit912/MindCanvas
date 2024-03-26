# Some utility functions
#
# Author: Indrajit Ghosh
#
# Date: Mar 24, 2024
#
import hashlib
from datetime import datetime, timedelta, timezone

def sha256_hash(raw_text:str):
    """Hash the given text using SHA-256 algorithm.

    Args:
        raw_text (str): The input text to be hashed.

    Returns:
        str: The hexadecimal representation of the hashed value.

    Example:
        >>> sha256_hash('my_secret_password')
        'e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4'
    """
    hashed = hashlib.sha256(raw_text.encode()).hexdigest()
    return hashed


def utcnow():
    """
    Get the current UTC datetime.

    Returns:
        datetime: A datetime object representing the current UTC time.
    """
    return datetime.now(timezone.utc)


def convert_utc_to_ist_str(dt):
    """
    Convert a datetime object with timezone information UTC to a string representation in IST format.

    Args:
        dt (datetime.datetime): A datetime object with timezone information UTC.

    Returns:
        str: A string representation of the datetime object in IST format (e.g., "Tue, 26 Mar 2024 07:51:18 PM (IST)").
    """
    # Add 5 hours and 30 minutes to the datetime object
    dt_ist = dt + timedelta(hours=5, minutes=30)
    
    # Format the datetime object
    ist_format = dt_ist.strftime("%a, %d %b %Y %I:%M %p (IST)")
    
    return ist_format
