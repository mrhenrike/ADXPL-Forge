"""Captura TGTs de hosts com unconstrained delegation

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


from typing import Any

MANIFEST: dict[str, Any] = {
    "capability_id": "ad.attack.unconstrained_deleg",
    "safety_class": "active_exploit",
    "requires_authorization": True,
    "side_effects": ['kerberos_capture'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential

    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None) or getattr(args, "dc", None)
    if not target:
        print("[!] --target ou --dc obrigatório")
        return 1

    print("[*] Captura TGTs de hosts com unconstrained delegation ...")
    print(f"[*] Alvo: {target}, Usuário: {cred.username}")
    print("[!] Implementação pendente  -  stub de integração")
    return 0
