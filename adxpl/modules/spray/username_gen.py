"""Username generation from names  -  firstname.lastname patterns."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.spray.username_gen.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": False,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1589.002"],
}


def run(args: Any) -> int:
    names_file = getattr(args, "users_file", None)
    output = getattr(args, "output", ".")

    print("[*] Username Generator: name permutation patterns")

    if not names_file:
        print("[!] --users-file required (one 'Firstname Lastname' per line)")
        return 1

    import os
    patterns = [
        lambda f, l: f"{f}.{l}",
        lambda f, l: f"{f[0]}{l}",
        lambda f, l: f"{f}{l[0]}",
        lambda f, l: f"{f}{l}",
        lambda f, l: f"{f}_{l}",
        lambda f, l: f"{l}",
        lambda f, l: f"{f}-{l}",
        lambda f, l: f"{f[:3]}{l[:3]}",
    ]

    usernames = []
    with open(names_file) as fh:
        for line in fh:
            parts = line.strip().split()
            if len(parts) >= 2:
                first = parts[0].lower()
                last = parts[-1].lower()
                for pat in patterns:
                    usernames.append(pat(first, last))

    out_path = os.path.join(output, "generated_usernames.txt")
    with open(out_path, "w") as fh:
        fh.write("\n".join(sorted(set(usernames))) + "\n")

    print(f"[+] Generated {len(set(usernames))} unique usernames -> {out_path}")
    return 0
