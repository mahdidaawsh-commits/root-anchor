"""Validate a RootAnchor checkpoint with dnspython and OpenSSL-backed cryptography."""
import json
import sys

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.RRSIG import RRSIG


ANCHOR = '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16'
ROOT = dns.name.root
IN = dns.rdataclass.IN
DNSKEY = dns.rdatatype.DNSKEY
DS = dns.rdatatype.DS


def rrset(name, ttl, kind, data):
    records = [dns.rdata.from_wire(IN, kind, wire, 0, len(wire)) for wire in data]
    return dns.rrset.from_rdata_list(name, ttl, records)


def signature(value, kind):
    return RRSIG(IN, dns.rdatatype.RRSIG, kind, value['algorithm'], value['labels'],
                 value['original_ttl'], value['expires'], value['inception'], value['key_tag'],
                 ROOT, bytes.fromhex(value['signature']))


def verify(checkpoint):
    now = checkpoint['observed_at']
    root_sig = signature(checkpoint['root_signature'], DNSKEY)
    ds_sig = signature(checkpoint['ds_signature'], DS)
    root_set = rrset(ROOT, root_sig.original_ttl, DNSKEY,
                    [bytes.fromhex(wire) for wire in checkpoint['root_dnskeys']])
    trusted = [key for key in root_set if dns.dnssec.key_id(key) == 38696
               and dns.dnssec.make_ds(ROOT, key, 'SHA256').digest.hex() == ANCHOR]
    assert len(trusted) == 1 and checkpoint['trust_tag'] == 38696 and checkpoint['trust_digest'] == ANCHOR
    assert len(root_set) == len(checkpoint['root_dnskeys'])
    anchor_set = dns.rrset.from_rdata_list(ROOT, root_sig.original_ttl, trusted)
    dns.dnssec.validate_rrsig(root_set, root_sig, {ROOT: anchor_set}, now=now)

    signer = rrset(ROOT, root_sig.original_ttl, DNSKEY, [bytes.fromhex(checkpoint['ds_signer'])])
    assert signer[0] in root_set and dns.dnssec.key_id(signer[0]) == ds_sig.key_tag
    domain = dns.name.from_text(checkpoint['name'])
    values = [dns.rdata.from_text(IN, DS, f"{row['key_tag']} {row['algorithm']} {row['digest_type']} {row['digest']}")
              for row in checkpoint['ds']]
    delegation = dns.rrset.from_rdata_list(domain, ds_sig.original_ttl, values)
    assert len(delegation) == len(values)
    dns.dnssec.validate_rrsig(delegation, ds_sig, {ROOT: signer}, now=now)
    assert checkpoint['expires'] == min(root_sig.expiration, ds_sig.expiration)
    assert root_sig.inception <= now < root_sig.expiration and ds_sig.inception <= now < ds_sig.expiration


if __name__ == '__main__':
    checkpoints = json.load(sys.stdin)
    for checkpoint in checkpoints:
        verify(checkpoint)
    print(json.dumps({'verified': [checkpoint['name'] for checkpoint in checkpoints]}))
