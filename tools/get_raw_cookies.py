from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from utils.cookiecloud_client import fetch_cookiecloud_data, decrypt_cookie


class GetRawCookiesTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        try:
            # Get credentials from runtime (configured at provider level)
            url = self.runtime.credentials.get("url", "").rstrip('/')
            uuid = self.runtime.credentials.get("uuid", "")
            password = self.runtime.credentials.get("password", "")

            # Validate credentials (should always be present if provider validation passed)
            if not url or not uuid or not password:
                yield self.create_text_message("Error: CookieCloud credentials not configured properly.")
                return

            # Step 1: Fetch encrypted data from CookieCloud server using helper function
            try:
                data = fetch_cookiecloud_data(url, uuid)
            except Exception as e:
                yield self.create_text_message(f"Error fetching data from server: {str(e)}")
                return

            # Step 2: Decrypt the data using helper function
            try:
                decrypted_data = decrypt_cookie(data['encrypted'], uuid, password)
                cookie_data = decrypted_data.get("cookie_data", {})

                # Return the decrypted data
                yield self.create_json_message(cookie_data)
                yield self.create_text_message("Successfully decrypted CookieCloud data.")

            except Exception as e:
                yield self.create_text_message(f"Error decrypting data: {str(e)}")
                return

        except Exception as e:
            yield self.create_text_message(f"Unexpected error: {str(e)}")
