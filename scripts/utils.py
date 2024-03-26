# Some utility functions
#
# Author: Indrajit Ghosh
#
# Date: Mar 24, 2024
#
import hashlib
from datetime import datetime, timedelta, timezone
import pytz


def utcnow():
    """
    Get the current UTC datetime.

    Returns:
        datetime: A datetime object representing the current UTC time.
    """
    return datetime.now(timezone.utc)

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


def convert_utc_to_ist_old(utc_datetime_str:str):
    """
    Convert a UTC datetime string to Indian Standard Time (IST) format.

    Args:
        utc_datetime_str (str): A string representing a UTC datetime in the format '%Y-%m-%d %H:%M:%S'.

    Returns:
        str: A string representing the datetime in IST format, e.g., 'Dec 13, 2023 07:06 AM IST'.

    Example:
        >>> convert_utc_to_ist('2023-12-13 07:06:16')
        'Dec 13, 2023 07:06 AM IST'
    """
    # Convert string to datetime object
    utc_datetime = datetime.strptime(utc_datetime_str, "%Y-%m-%d %H:%M:%S")

    # Define UTC and IST timezones
    utc_timezone = timezone.utc
    ist_timezone = timezone(timedelta(hours=5, minutes=30))

    # Convert UTC datetime to IST
    ist_datetime = utc_datetime.replace(tzinfo=utc_timezone).astimezone(ist_timezone)

    # Format datetime in the desired string format
    formatted_datetime = ist_datetime.strftime("%b %d, %Y %I:%M %p IST")

    return formatted_datetime

def convert_utc_to_ist(utc_datetime):
    """
    Convert a UTC datetime object to Indian Standard Time (IST).

    Args:
        utc_datetime (datetime): A datetime object in UTC timezone.

    Returns:
        datetime: A datetime object converted to IST timezone.
    """
    return utc_datetime.astimezone(tz=pytz.timezone('Asia/Kolkata'))


def format_datetime_with_timezone(dt):
    """
    Convert a timezone-aware datetime object into a string in the format '%b %d, %Y %I:%M %p [TIMEZONE]'.

    Args:
        dt (datetime): A timezone-aware datetime object.

    Returns:
        str: A string representing the datetime in the specified format with timezone.
    """
    # Format the datetime string
    formatted_datetime = dt.strftime("%b %d, %Y %I:%M %p") + " [" + dt.tzname() + "]"

    return formatted_datetime


if __name__ == '__main__':

    print(convert_utc_to_ist(utcnow()))

    conv_time = utcnow().astimezone(tz=pytz.timezone('Asia/Kolkata'))

    print(conv_time)

    print(format_datetime_with_timezone(conv_time))