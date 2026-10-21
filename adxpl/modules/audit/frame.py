"""FRAME: acoplar análise estática/solver/LLM para validação estruturada de findings."""

MANIFEST = {
    "capability_id": "adxpl.audit.frame.v1",
    "safety_class": "RECON",
    "requires_authorization": True,
    "side_effects": ["information_disclosure"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1190"],
    "cve": [],
    "source": "https://github.com/lambdasec/frame",
    "src_id": "SRC-016",
}


def run(args):
    """Stub: implement based on https://github.com/lambdasec/frame"""
    raise NotImplementedError("SRC-016: stub module, implementation pending")
