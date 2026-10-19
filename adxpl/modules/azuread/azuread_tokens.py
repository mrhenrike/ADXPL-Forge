"""Azure AD token abuse — PRT, refresh tokens, JWT manipulation."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.azuread.azuread_tokens.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["token_theft", "authentication_abuse"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1528"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    print("[*] Azure AD Token Abuse")
    print("[*] Domain: {}".format(cred.domain))

    print("\n[*] Token types:")
    print("  - PRT (Primary Refresh Token): SSO token, cached on device")
    print("  - Refresh Token: long-lived, can generate new access tokens")
    print("  - Access Token (JWT): short-lived, used for API calls")

    print("\n[*] Tools:")
    print("  - ROADtools: roadtx interactiveauth / roadtx gettokens")
    print("  - TokenTactics: Invoke-RefreshToMSGraphToken")
    print("  - AADInternals: Get-AADIntAccessToken")

    import subprocess
    import shutil
    roadtx = shutil.which("roadtx")
    if roadtx:
        print("\n[*] ROADtx available. Use:")
        print("  roadtx interactiveauth -u {}@{}".format(cred.username or "user", cred.domain))
        print("  roadtx gettokens --refresh-token <RT>")

    return 0
