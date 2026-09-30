import os
import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
DEFAULT_DEV_KEY = "tf_dev_secret_key_2026"

def get_configured_api_key() -> str:
    return os.getenv("THREATFORGE_API_KEY", DEFAULT_DEV_KEY)

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    expected_key = get_configured_api_key()
    # In production or when key is set, require match
    if api_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid or missing X-API-Key header."
        )
    return api_key

# --- 1MB Payload Size Limit Middleware ---
class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_size_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Payload Too Large: Maximum allowed architecture payload is 1MB."}
                    )
            except ValueError:
                pass
        return await call_next(request)

# --- SSRF Validator for Webhooks ---
ALLOWED_WEBHOOK_DOMAINS = [
    "hooks.slack.com",
    "discord.com",
    "api.telegram.org"
]

def validate_webhook_url(url: str, allow_custom_https: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("SSRF Protection: Webhooks must use HTTPS protocol only.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("SSRF Protection: Invalid URL hostname.")

    # 1. Whitelist Check
    is_whitelisted = any(hostname == domain or hostname.endswith("." + domain) for domain in ALLOWED_WEBHOOK_DOMAINS)
    if not is_whitelisted and not allow_custom_https:
        raise ValueError(
            f"SSRF Protection: Target domain '{hostname}' is not in allowed webhook providers (hooks.slack.com, discord.com, api.telegram.org)."
        )

    # 2. DNS Resolution & Private IP Block
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Block private, loopback, link-local, and cloud metadata (169.254.169.254)
            if (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_reserved or
                ip_str == "169.254.169.254"
            ):
                raise ValueError(f"SSRF Protection: Domain resolves to private or metadata IP '{ip_str}'.")
    except socket.gaierror:
        raise ValueError("SSRF Protection: Could not resolve hostname.")

    return url
