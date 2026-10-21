"""Reset de senha via ForceChangePassword right

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


from typing import Any

MANIFEST: dict[str, Any] = {
    "capability_id": "ad.acl.force_change_pwd",
    "safety_class": "active_exploit",
    "requires_authorization": True,
    "side_effects": ['password_change'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1098"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential

    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None) or getattr(args, "dc", None)
    if not target:
        print("[!] --target ou --dc obrigatório")
        return 1

    print("[*] Reset de senha via ForceChangePassword right ...")
    print(f"[*] Alvo: {target}, Usuário: {cred.username}")
    print("[!] Implementação pendente  -  stub de integração")
    return 0
