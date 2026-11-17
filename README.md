# RootAnchor

RootAnchor is a permissionless GenLayer verifier for positive DNSSEC delegation signer (DS) records published by the DNS root. Consumers can read an authenticated, unexpired DS set for a top-level domain. Each checkpoint includes the records, root DNSKEY set, both signatures and the key that signed the delegation.

Deploy without constructor arguments. Call `refresh(tld)` with one lowercase DNS label, such as `com`. The leader and each validator fetch the root DNSKEY set and the requested DS set through DNS over HTTPS. Each node matches the IANA KSK-2024 trust-anchor digest and authenticates the root DNSKEY set. It then verifies the DS signature using an authenticated root key. Verification reconstructs the canonical DNS wire bytes, checks RRSIG time bounds against the transaction clock, and verifies RSA/SHA-256 signatures. Validators compare the normalized authenticated records and signatures. Resolver AD flags, cached TTLs, and answer ordering are outside the consensus comparison.

`get_active(tld)` returns the checkpoint only during its joint signature validity window. `get_checkpoint(tld)` retains the last observation for audit. An older DS signature cannot replace a newer checkpoint. If the inception is unchanged, the DS set must match and the joint expiry must advance. A nonpositive or unsigned answer leaves the checkpoint untouched.

The root key is pinned to KSK-2024 (tag 38696). A future root trust-anchor rollover requires deploying updated code. A valid checkpoint proves the signed DS RRset existed within the signature validity window. Resolver caching can retain a signed RRset until its expiry. The implementation covers positive top-level DS records, RSA/SHA-256 root signatures, and ordinary 32-bit Unix signature times. Applications requiring child-zone validation or authenticated denial must extend the verification chain.

[IANA root trust anchors](https://www.iana.org/dnssec/files) · [RFC 9718](https://www.rfc-editor.org/rfc/rfc9718.html) · [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) · [RFC 5702](https://www.rfc-editor.org/rfc/rfc5702.html) · [Google DoH JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)

## Verification

```sh
pip install -r requirements-dev.txt
genvm-lint download --version v0.2.16
genvm-lint check contracts/root_anchor.py
python -m pytest tests/direct -q
npm ci
node --test tests/rpc-preflight.test.cjs
```

Direct tests use signed DNS fixtures with a fixed clock. They cover signature mutation, owner substitution, anchor removal, expiry, and duplicate observations. The StudioNet verifier separately fetches the live DS sets, verifies the onchain signatures again with dnspython, checks decoded signed calldata, and reads checkpoint state after each transaction. Generic CLI transport is reused under MIT.

[StudioNet proofs](proofs/README.md) · [Submission text](SUBMISSION.md).
