# Some utility functions
#
# Author: Indrajit Ghosh
#
# Date: Mar 24, 2024
#
import hashlib
from datetime import datetime, timedelta, timezone

def count_words(text):
    """
    Count the number of words in a given text.
    """
    if text:
        return len(text.split())
    else:
        return 0


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


def convert_utc_to_ist_str(dt, show_time: bool = True, weekday: bool = True):
    """
    Convert a datetime object with timezone information UTC to a string representation in IST format.

    Args:
        dt (datetime.datetime): A datetime object with timezone information UTC.
        show_time (bool, optional): Whether to include the time in the output string. Defaults to True.
        weekday (bool, optional): Whether to include the weekday in the output string. Defaults to True.

    Returns:
        str: A string representation of the datetime object in IST format (e.g., "Tue, 26 Mar 2024 07:51:18 PM (IST)").
    """
    # Add 5 hours and 30 minutes to the datetime object
    dt_ist = dt + timedelta(hours=5, minutes=30)

    # Format the datetime object
    ist_format = ""
    if weekday:
        ist_format += dt_ist.strftime("%a, ")
    ist_format += dt_ist.strftime("%d %b %Y")
    if show_time:
        ist_format += dt_ist.strftime(" %I:%M %p (IST)")

    return ist_format


def format_years_ago(date):
    """
    Format the given date into a human-readable string indicating how many years ago it occurred.

    Args:
        date (datetime.datetime): The date to format.

    Returns:
        str: A human-readable string indicating how many years ago the date occurred.
    """
    current_year = datetime.now().year
    date_year = date.year

    year_difference = current_year - date_year

    if year_difference == 1:
        return "Last year"
    elif year_difference > 1:
        return f"{year_difference} years ago"
    else:
        return "This year"
