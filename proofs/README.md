# StudioNet proofs

Contract address 0x082711f02D2BD3678744d1c5f6beDe42ea84407F

StudioNet validated the root DNSKEY signature against IANA KSK-2024 and verified each delegation signature with the authenticated signing key. A separate dnspython/OpenSSL implementation verified both onchain signature chains again.

[Workflow](https://github.com/mahdidaawsh-commits/root-anchor/actions/runs/44167378293) · [Verified snapshots and signed records](verified.json)

| Outcome | Explorer | Receipt | Agree / disagree / idle |
| --- | --- | --- | --- |
| Deployed the verifier | [Transaction](https://explorer-studio.genlayer.com/tx/0xb3ca95c7963bcf9dd2a40fc5b22c86d2ce54a5a8e58c2f6e980179f7c9b58c2d) | [JSON](deploy-receipt.json) | 3 / 0 / 2 |
| Verified the signed .com DS set | [Transaction](https://explorer-studio.genlayer.com/tx/0x844b43a9203e35d469d87e8e8587360acf0a78e4fae040de8130edd8b94f38c2) | [JSON](com-receipt.json) | 3 / 1 / 1 |
| Rejected repeat observation with no newer evidence | [Transaction](https://explorer-studio.genlayer.com/tx/0xc3f7c6aa106d592ee099748e00a1e9bdb4b03a7807eafa05564cf9c80c16283b) | [JSON](replay-receipt.json) | 3 / 0 / 2 |
| Verified the signed .org DS set | [Transaction](https://explorer-studio.genlayer.com/tx/0xc7df569ad1ea5103cb88a9eb97f271bcce616d1edea52ebae85b42bff8c115c6) | [JSON](org-receipt.json) | 3 / 1 / 1 |
| Rejected a DNS answer without a positive signed DS set | [Transaction](https://explorer-studio.genlayer.com/tx/0x2d2e8b5544a2eee02de698ee18892fd981f9ac8ebabf3b723765f0ada9c19d87) | [JSON](invalid-receipt.json) | 3 / 0 / 2 |

All five receipts finalized with MAJORITY_AGREE. Both rejection cases preserved checkpoint state.

| Delegation | DS key tags | Joint signature expiry (UTC) |
| --- | --- | --- |
| .com | 19718 | 2026-11-30T05:00:00.000Z |
| .org | 725 | 2026-11-30T05:00:00.000Z |

Source revision 38a9a8e5bf9fba13c8fe3ea2a231662cb22a795c

Contract SHA-256 a86653903227996ebf7f881acf95085b241a4d3e82c6d8c07f33a3b2f6b6358c
