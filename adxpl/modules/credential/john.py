"""John the Ripper: dialeto de regras para conversão; referência para compatibilidade de regras wlf."""

MANIFEST = {
    "capability_id": "adxpl.credential.john.v1",
    "safety_class": "RECON",
    "requires_authorization": True,
    "side_effects": ["information_disclosure"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1190"],
    "cve": [],
    "source": "https://github.com/openwall/john",
    "src_id": "SRC-123",
}


def run(args):
    """Stub: implement based on https://github.com/openwall/john"""
    raise NotImplementedError("SRC-123: stub module, implementation pending")
