# RootAnchor — DNSSEC delegation verifier

**Category** Builder → Intelligent Contracts

RootAnchor verifies positive DNSSEC delegation signer (DS) records from the DNS root. The leader and validators independently fetch live DNSKEY and DS responses, reconstruct canonical DNS wire records, and verify both RSA/SHA-256 signatures against IANA KSK-2024. Consensus compares the full authenticated records and signatures. Anyone can refresh a delegation, and the active view honors joint signature expiry. Older observations cannot overwrite newer records. StudioNet verified .com and .org, reproduced both chains with dnspython, and rejected a repeat observation and a query with no signed DS answer. The repo includes 11 direct tests and five finalized MAJORITY_AGREE receipts. The scope is positive top-level DS records and the pinned root key.

- [GenLayer contract](contracts/root_anchor.py)
- [StudioNet deployment](https://explorer-studio.genlayer.com/tx/0xb3ca95c7963bcf9dd2a40fc5b22c86d2ce54a5a8e58c2f6e980179f7c9b58c2d)
- [Live .com delegation](https://explorer-studio.genlayer.com/tx/0x844b43a9203e35d469d87e8e8587360acf0a78e4fae040de8130edd8b94f38c2)
- [Live .org delegation](https://explorer-studio.genlayer.com/tx/0xc7df569ad1ea5103cb88a9eb97f271bcce616d1edea52ebae85b42bff8c115c6)
- [Receipts and authenticated records](proofs/README.md)
