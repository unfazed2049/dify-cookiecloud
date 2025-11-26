import json
import requests
from typing import Dict, Any


def fetch_cookiecloud_data(url: str, uuid: str) -> Dict[str, Any]:
    """
    Fetch encrypted data from CookieCloud server.

    Args:
        url: CookieCloud server base URL (without trailing slash)
        uuid: CookieCloud UUID

    Returns:
        Response data from server containing encrypted cookie data

    Raises:
        requests.RequestException: If API call fails
        json.JSONDecodeError: If response is not valid JSON
        Exception: If no encrypted data found in response
    """
    fetch_url = f"{url}/get/{uuid}"

    response = requests.get(fetch_url, timeout=10)
    response.raise_for_status()
    data = response.json()

    # Check if encrypted data exists
    if 'encrypted' not in data:
        raise Exception("No encrypted data found in server response.")

    return data
