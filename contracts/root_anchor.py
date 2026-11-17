# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from base64 import b64decode
from datetime import datetime, timezone
from hashlib import sha256
import json
import re


SOURCE = 'https://dns.google/resolve'
TRUST_TAG = 38696
TRUST_DIGEST = '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16'
SHA256_DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')
TYPES = {'DS': 43, 'DNSKEY': 48}


def fail(message):
    raise gl.vm.UserError(message)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def label(tld):
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', tld):
        fail('Expected one lowercase DNS label')
    return tld + '.'


def now_seconds():
    elapsed = datetime.now(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return elapsed.days * 86400 + elapsed.seconds


def wire_name(name):
    data = name[:-1].encode('ascii')
    return (bytes([len(data)]) + data if data else b'') + b'\0'


def pack(value, width):
    return value.to_bytes(width, 'big')


def uint(text, width):
    if not re.fullmatch(r'[0-9]{1,10}', text) or int(text) >= 1 << (8 * width):
        fail('Invalid DNS numeric record field')
    return int(text)


def base64_bytes(text):
    if not 1 <= len(text) <= 700:
        fail('Invalid DNS base64 field')
    try:
        return b64decode(text, validate=True)
    except ValueError:
        fail('Invalid DNS base64 field')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate response field')
        result[key] = value
    return result


def query(name, rrtype):
    url = f'{SOURCE}?name={name}&type={rrtype}&do=1&cd=1'
    reply = gl.nondet.web.get(url)
    if reply.status != 200 or not 1 <= len(reply.body) <= 24576:
        fail('DNS evidence unavailable')
    try:
        raw = json.loads(reply.body.decode('utf-8'), object_pairs_hook=unique_object)
    except ValueError:
        fail('Invalid DNS response')
    if not isinstance(raw, dict) or raw.get('Question') != [{'name': name, 'type': TYPES[rrtype]}] or raw.get('TC') is not False:
        fail('Unexpected DNS question or truncated response')
    entries = raw.get('Answer', [])
    if raw.get('Status') != 0 or entries == []:
        fail('No positive signed DNS answer')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 24:
        fail('Invalid DNS answer size')
    data, signatures = [], []
    for answer in entries:
        if (not isinstance(answer, dict) or answer.get('name') != name
                or not isinstance(answer.get('data'), str)):
            fail('Unexpected DNS answer owner')
        fields = answer['data'].split()
        if answer.get('type') == TYPES[rrtype]:
            data.append(rdata(fields, rrtype))
        elif answer.get('type') == 46:
            signatures.append(rrsig(fields, rrtype))
        else:
            fail('Unexpected DNS answer type')
    if not data or not signatures or len(set(data)) != len(data):
        fail('Missing or duplicate signed records')
    return sorted(data), signatures


def rdata(fields, rrtype):
    if not 4 <= len(fields) <= 16:
        fail('Invalid signed record data')
    first, second, third = (uint(value, width) for value, width in zip(fields[:3], (2, 1, 1)))
    content = ''.join(fields[3:])
    if rrtype == 'DS':
        lengths = {1: 40, 2: 64, 4: 96}
        if third not in lengths or len(content) != lengths[third] or not re.fullmatch(r'[0-9a-fA-F]+', content):
            fail('Unsupported delegation digest')
        payload = bytes.fromhex(content)
    else:
        if second != 3:
            fail('Invalid DNSKEY protocol')
        payload = base64_bytes(content)
    return pack(first, 2) + bytes([second, third]) + payload


def rrsig(fields, rrtype):
    if (not 9 <= len(fields) <= 24 or fields[0].upper() != rrtype or fields[7] != '.'):
        fail('Invalid root signature fields')
    algorithm, labels, ttl, expiry, inception, tag = (
        uint(value, width) for value, width in zip(fields[1:7], (1, 1, 4, 4, 4, 2))
    )
    return {'algorithm': algorithm, 'labels': labels, 'original_ttl': ttl, 'expires': expiry,
            'inception': inception, 'key_tag': tag, 'signature': base64_bytes(''.join(fields[8:])).hex()}


def key_tag(key):
    accumulator = sum(value << (8 if i % 2 == 0 else 0) for i, value in enumerate(key))
    return (accumulator + (accumulator >> 16)) & 65535


def rsa_verify(key, signature, digest):
    if not 132 <= len(key) <= 530 or key[2:4] != b'\x03\x08':
        return False
    public = key[4:]
    offset, size = (1, public[0]) if public[0] else (3, int.from_bytes(public[1:3], 'big'))
    if not 1 <= size <= 4:
        return False
    exponent = int.from_bytes(public[offset:offset + size], 'big')
    modulus_bytes = public[offset + size:]
    if not 128 <= len(modulus_bytes) <= 512 or modulus_bytes[0] == 0 or len(signature) != len(modulus_bytes):
        return False
    modulus = int.from_bytes(modulus_bytes, 'big')
    sig = int.from_bytes(signature, 'big')
    if exponent < 3 or exponent % 2 == 0 or modulus % 2 == 0 or sig >= modulus:
        return False
    tail = SHA256_DIGEST_INFO + digest
    expected = b'\x00\x01' + b'\xff' * (len(signature) - len(tail) - 3) + b'\x00' + tail
    return pack(pow(sig, exponent, modulus), len(signature)) == expected


def signed_digest(name, rrtype, data, record):
    kind = pack(TYPES[rrtype], 2)
    ttl = pack(record['original_ttl'], 4)
    prefix = (kind + bytes([record['algorithm'], record['labels']]) + ttl + pack(record['expires'], 4)
              + pack(record['inception'], 4) + pack(record['key_tag'], 2) + b'\0')
    common = wire_name(name) + kind + b'\x00\x01' + ttl
    return sha256(prefix + b''.join(common + pack(len(row), 2) + row for row in data)).digest()


def authenticate(name, rrtype, data, signatures, keys, now):
    valid = []
    for record in signatures:
        if (record['algorithm'] != 8 or record['labels'] != (0 if name == '.' else 1)
                or not record['inception'] <= now < record['expires']):
            continue
        digest = signed_digest(name, rrtype, data, record)
        signature = bytes.fromhex(record['signature'])
        for key in keys:
            if key_tag(key) == record['key_tag'] and rsa_verify(key, signature, digest):
                valid.append((record, key))
    if not valid:
        fail('No valid ' + rrtype + ' signature')
    return min(valid, key=lambda pair: (-pair[0]['inception'], -pair[0]['expires'],
                                        pair[0]['key_tag'], pair[0]['signature'], pair[1]))


def capture(name, now):
    data, signatures = query(name, 'DS')
    keys, root_signatures = query('.', 'DNSKEY')
    trusted = [key for key in keys
               if key[:4] == b'\x01\x01\x03\x08' and key_tag(key) == TRUST_TAG
               and sha256(b'\0' + key).hexdigest() == TRUST_DIGEST]
    if len(trusted) != 1:
        fail('Pinned root trust anchor missing')
    root_signature, _ = authenticate('.', 'DNSKEY', keys, root_signatures, trusted, now)
    usable = [key for key in keys if key[:2] in (b'\x01\x00', b'\x01\x01')]
    ds_signature, signer = authenticate(name, 'DS', data, signatures, usable, now)
    return {
        'name': name, 'trust_tag': TRUST_TAG, 'trust_digest': TRUST_DIGEST,
        'root_dnskeys': [key.hex() for key in keys], 'root_signature': root_signature,
        'ds': [{'key_tag': int.from_bytes(row[:2], 'big'), 'algorithm': row[2],
                'digest_type': row[3], 'digest': row[4:].hex()} for row in data],
        'ds_signature': ds_signature, 'ds_signer': signer.hex(),
        'expires': min(root_signature['expires'], ds_signature['expires'])
    }


def observe(name, now):
    def fetch():
        return capture(name, now)

    def verify(proposal):
        try:
            independent = fetch()
        except gl.vm.UserError as error:
            return not isinstance(proposal, gl.vm.Return) and getattr(proposal, 'message', None) == error.message
        except Exception:
            return False
        return isinstance(proposal, gl.vm.Return) and encode(proposal.calldata) == encode(independent)

    return gl.vm.run_nondet_unsafe(fetch, verify)


class RootAnchor(gl.Contract):
    checkpoints: TreeMap[str, str]

    def __init__(self):
        pass

    @gl.public.write
    def refresh(self, tld: str) -> None:
        name = label(tld)
        now = now_seconds()
        candidate = observe(name, now)
        if name in self.checkpoints:
            previous = json.loads(self.checkpoints[name])
            if candidate['ds_signature']['inception'] < previous['ds_signature']['inception']:
                fail('Older delegation signature')
            if candidate['ds_signature']['inception'] == previous['ds_signature']['inception']:
                if candidate['ds'] != previous['ds']:
                    fail('Conflicting delegation at same inception')
                if candidate['expires'] <= previous['expires']:
                    fail('No newer delegation evidence')
        candidate['observed_at'] = now
        self.checkpoints[name] = encode(candidate)

    @gl.public.view
    def get_checkpoint(self, tld: str) -> dict:
        name = label(tld)
        return json.loads(self.checkpoints[name]) if name in self.checkpoints else {}

    @gl.public.view
    def get_active(self, tld: str) -> dict:
        record = self.get_checkpoint(tld)
        return record if record and record['observed_at'] <= now_seconds() < record['expires'] else {}
