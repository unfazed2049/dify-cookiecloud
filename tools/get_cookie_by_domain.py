from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from utils.cookiecloud_client import fetch_cookiecloud_data, decrypt_cookie


class GetCookieByDomainTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        try:
            # Get credentials from runtime (configured at provider level)
            url = self.runtime.credentials.get("url", "").rstrip('/')
            uuid = self.runtime.credentials.get("uuid", "")
            password = self.runtime.credentials.get("password", "")

            # Get tool parameters
            domain = tool_parameters.get("domain", "").strip()
            keys_str = tool_parameters.get("keys", "").strip()

            # Validate credentials
            if not url or not uuid or not password:
                yield self.create_text_message("Error: CookieCloud credentials not configured properly.")
                return

            # Validate parameters
            if not domain:
                yield self.create_text_message("Error: Domain is required.")
                return
            if not keys_str:
                yield self.create_text_message("Error: Cookie keys are required.")
                return

            # Parse keys (comma-separated)
            keys = [key.strip() for key in keys_str.split(",") if key.strip()]
            if not keys:
                yield self.create_text_message("Error: No valid cookie keys provided.")
                return

            # Step 1: Fetch encrypted data from CookieCloud server
            try:
                data = fetch_cookiecloud_data(url, uuid)
            except Exception as e:
                yield self.create_text_message(f"Error fetching data from server: {str(e)}")
                return

            # Step 2: Decrypt the data
            try:
                decrypted_data = decrypt_cookie(data['encrypted'], uuid, password)
            except Exception as e:
                yield self.create_text_message(f"Error decrypting data: {str(e)}")
                return

            # Step 3: Filter by domain and extract specified keys
            try:
                # CookieCloud data structure typically has a 'cookie_data' field with domain-based cookies
                cookie_data = decrypted_data.get("cookie_data", {})

                # Find matching domain cookies
                domain_cookies = None
                for stored_domain, cookies in cookie_data.items():
                    # Check if the stored domain matches or is a subdomain of the requested domain
                    if domain in stored_domain or stored_domain in domain:
                        domain_cookies = cookies
                        break

                if domain_cookies is None:
                    yield self.create_text_message(f"Error: No cookies found for domain '{domain}'.")
                    return

                # Extract specified keys
                result = {}
                missing_keys = []

                # Handle both list and dict formats
                if isinstance(domain_cookies, list):
                    # Convert list of cookies to a lookup dict
                    cookies_dict = {cookie.get("name"): cookie.get("value") for cookie in domain_cookies if isinstance(cookie, dict) and "name" in cookie}
                    for key in keys:
                        if key in cookies_dict:
                            result[key] = cookies_dict[key]
                        else:
                            missing_keys.append(key)
                elif isinstance(domain_cookies, dict):
                    for key in keys:
                        if key in domain_cookies:
                            result[key] = domain_cookies[key]
                        else:
                            missing_keys.append(key)
                else:
                    yield self.create_text_message(f"Error: Unexpected cookie data format for domain '{domain}'.")
                    return

                # Build response
                if result:
                    yield self.create_json_message(result)
                    message = f"Successfully retrieved {len(result)} cookie(s) from domain '{domain}'."
                    if missing_keys:
                        message += f" Missing keys: {', '.join(missing_keys)}"
                    yield self.create_text_message(message)
                else:
                    yield self.create_text_message(f"Error: None of the specified keys were found in domain '{domain}'. Available cookies: {list(cookies_dict.keys() if isinstance(domain_cookies, list) else domain_cookies.keys())}")

            except Exception as e:
                yield self.create_text_message(f"Error filtering cookies: {str(e)}")
                return

        except Exception as e:
            yield self.create_text_message(f"Unexpected error: {str(e)}")
