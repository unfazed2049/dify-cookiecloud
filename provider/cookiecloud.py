from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from utils.cookiecloud_client import fetch_cookiecloud_data


class CookiecloudProvider(ToolProvider):

    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            # Get credentials
            url = credentials.get("url", "").rstrip('/')
            uuid = credentials.get("uuid", "")
            password = credentials.get("password", "")

            # Validate required parameters
            if not url:
                raise ToolProviderCredentialValidationError("CookieCloud server URL is required.")
            if not uuid:
                raise ToolProviderCredentialValidationError("UUID is required.")
            if not password:
                raise ToolProviderCredentialValidationError("Password is required.")

            # Try to fetch data to validate credentials (only check if API call succeeds)
            try:
                fetch_cookiecloud_data(url, uuid)
            except Exception as e:
                raise ToolProviderCredentialValidationError(f"Error fetching data from server: {str(e)}")

        except ToolProviderCredentialValidationError:
            raise
        except Exception as e:
            raise ToolProviderCredentialValidationError(str(e))

    #########################################################################################
    # If OAuth is supported, uncomment the following functions.
    # Warning: please make sure that the sdk version is 0.4.2 or higher.
    #########################################################################################
    # def _oauth_get_authorization_url(self, redirect_uri: str, system_credentials: Mapping[str, Any]) -> str:
    #     """
    #     Generate the authorization URL for cookiecloud OAuth.
    #     """
    #     try:
    #         """
    #         IMPLEMENT YOUR AUTHORIZATION URL GENERATION HERE
    #         """
    #     except Exception as e:
    #         raise ToolProviderOAuthError(str(e))
    #     return ""
        
    # def _oauth_get_credentials(
    #     self, redirect_uri: str, system_credentials: Mapping[str, Any], request: Request
    # ) -> Mapping[str, Any]:
    #     """
    #     Exchange code for access_token.
    #     """
    #     try:
    #         """
    #         IMPLEMENT YOUR CREDENTIALS EXCHANGE HERE
    #         """
    #     except Exception as e:
    #         raise ToolProviderOAuthError(str(e))
    #     return dict()

    # def _oauth_refresh_credentials(
    #     self, redirect_uri: str, system_credentials: Mapping[str, Any], credentials: Mapping[str, Any]
    # ) -> OAuthCredentials:
    #     """
    #     Refresh the credentials
    #     """
    #     return OAuthCredentials(credentials=credentials, expires_at=-1)
