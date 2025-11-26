from collections.abc import Generator
from typing import Any
import hashlib
import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from utils.cookiecloud_client import fetch_cookiecloud_data


class CookiecloudTool(Tool):
    def _decrypt_cookie(self, ciphertext: str, uuid: str, password: str) -> dict:
        """
        Decrypt CookieCloud encrypted data.

        Args:
            ciphertext: Base64 encoded encrypted data
            uuid: CookieCloud UUID
            password: CookieCloud password

        Returns:
            Decrypted cookie data as dictionary

        Raises:
            Exception: If decryption fails
        """
        # Generate decryption key (first 16 chars of MD5(uuid + '-' + password))
        hash_str = hashlib.md5(f"{uuid}-{password}".encode()).hexdigest()
        key = hash_str[:16].encode()

        # Parse encrypted text
        encrypted = b64decode(ciphertext)
        salt = encrypted[8:16]
        ct = encrypted[16:]

        # Use OpenSSL EVP_BytesToKey derivation method
        key_iv = b""
        prev = b""
        while len(key_iv) < 48:
            prev = hashlib.md5(prev + key + salt).digest()
            key_iv += prev

        _key = key_iv[:32]
        _iv = key_iv[32:48]

        # Create cipher and decrypt
        cipher = AES.new(_key, AES.MODE_CBC, _iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return json.loads(pt.decode('utf-8'))

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

            # Step 2: Decrypt the data
            try:
                decrypted_data = self._decrypt_cookie(data['encrypted'], uuid, password)

                # Return the decrypted data
                yield self.create_json_message(decrypted_data)
                yield self.create_text_message("Successfully decrypted CookieCloud data.")

            except Exception as e:
                yield self.create_text_message(f"Error decrypting data: {str(e)}")
                return

        except Exception as e:
            yield self.create_text_message(f"Unexpected error: {str(e)}")
