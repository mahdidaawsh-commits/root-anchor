from datetime import datetime, timezone
import json
from pathlib import Path
import re

import pytest

from scripts.verify_dnssec import verify


SOURCE = 'https://dns.google/resolve'
NOW = 1794840000


def fixtures(name):
    return json.loads(Path('fixtures/' + name + '.json').read_bytes())


def mock(vm, ds=None, root=None, name='com'):
    vm.clear_mocks()
    for query, answer in [
        (f'{SOURCE}?name={name}.&type=DS&do=1&cd=1', fixtures(name) if ds is None else ds),
        (f'{SOURCE}?name=.&type=DNSKEY&do=1&cd=1', fixtures('root') if root is None else root)
    ]:
        vm.mock_web(re.escape(query), {'status': 200, 'body': json.dumps(answer).encode()})


def warp(vm, timestamp):
    vm.warp(datetime.fromtimestamp(timestamp, timezone.utc).isoformat())


def deploy(vm, direct_deploy):
    warp(vm, NOW)
    return direct_deploy('contracts/root_anchor.py', sdk_version='v0.2.16')


@pytest.mark.parametrize(('name', 'key_tag', 'algorithm'), [('com',19718,13), ('org',725,8)])
def test_actual_signed_chain_is_verified_and_expires(direct_vm, direct_deploy, direct_bob, name, key_tag, algorithm):
    contract = deploy(direct_vm, direct_deploy)
    assert contract.get_active(name) == {}
    direct_vm.sender = direct_bob
    mock(direct_vm, name=name)
    contract.refresh(name)
    record = contract.get_checkpoint(name)
    assert record['observed_at'] == NOW
    assert record['name'] == name + '.' and record['trust_tag'] == record['root_signature']['key_tag'] == 38696
    assert record['ds'][0]['key_tag'] == key_tag and record['ds'][0]['algorithm'] == algorithm
    assert record['expires'] == min(record['root_signature']['expires'], record['ds_signature']['expires'])
    verify(record)
    assert contract.get_active(name) == record and direct_vm.run_validator() is True
    warp(direct_vm, record['expires'] - 1)
    assert contract.get_active(name) == record
    warp(direct_vm, record['expires'])
    assert contract.get_active(name) == {} and contract.get_checkpoint(name) == record


def test_cache_fields_and_answer_order_do_not_change_consensus(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    mock(direct_vm)
    contract.refresh('com')
    record = contract.get_checkpoint('com')
    root, com = fixtures('root'), fixtures('com')
    for document in (root, com):
        document['Answer'].reverse()
        for item in document['Answer']:
            item['TTL'] = 1
        document['AD'] = True
    mock(direct_vm, com, root)
    assert direct_vm.run_validator() is True
    forged = {key: value for key, value in record.items() if key != 'observed_at'}
    forged['ds'][0]['digest'] = 'aa' * 32
    assert direct_vm.run_validator(leader_result=forged) is False
    with direct_vm.expect_revert('No newer delegation evidence'):
        contract.refresh('com')
    assert contract.get_checkpoint('com') == record


@pytest.mark.parametrize(('mutation','error'), [
    ('ds', 'No valid DS signature'),
    ('root-signature', 'No valid DNSKEY signature'),
    ('remove-root-key', 'No valid DNSKEY signature'),
    ('remove-anchor', 'Pinned root trust anchor missing'),
    ('other-owner', 'No valid DS signature'),
    ('missing-rrsig', 'Missing or duplicate signed records'),
])
def test_resolver_cannot_forge_authenticated_records(direct_vm, direct_deploy, mutation, error):
    contract = deploy(direct_vm, direct_deploy)
    root, com = fixtures('root'), fixtures('com')
    com['AD'] = True
    if mutation == 'ds':
        row = next(item for item in com['Answer'] if item['type']==43)
        row['data'] = row['data'][:-1] + ('1' if row['data'][-1]=='0' else '0')
    elif mutation == 'root-signature':
        row = next(item for item in root['Answer'] if item['type']==46)
        position = row['data'].rfind(' ') + 1
        row['data'] = row['data'][:position] + ('A' if row['data'][position] != 'A' else 'B') + row['data'][position+1:]
    elif mutation == 'remove-root-key':
        root['Answer'].remove(next(item for item in root['Answer'] if item['type']==48 and item['data'].startswith('256 ')))
    elif mutation == 'remove-anchor':
        root['Answer'].remove(next(item for item in root['Answer'] if 'AwEAAa96' in item['data']))
    elif mutation == 'other-owner':
        com = fixtures('org')
        com['Question'][0]['name'] = 'com.'
        for row in com['Answer']:
            row['name'] = 'com.'
    else:
        com['Answer'] = [item for item in com['Answer'] if item['type']!=46]
    mock(direct_vm, com, root)
    with direct_vm.expect_revert(error):
        contract.refresh('com')
    assert contract.get_checkpoint('com') == {}
    mock(direct_vm)
    contract.refresh('com')
    assert contract.get_active('com')


def test_unavailable_or_nonpositive_records_never_become_checkpoints(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    mock(direct_vm, name='invalid')
    with direct_vm.expect_revert('No positive signed DNS answer'):
        contract.refresh('invalid')
    with direct_vm.expect_revert('Expected one lowercase DNS label'):
        contract.refresh('example.com')
    assert contract.get_checkpoint('invalid') == {}


def test_signed_records_outside_the_validity_window_are_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    mock(direct_vm)
    warp(direct_vm, 1794355200)
    with direct_vm.expect_revert('No valid DS signature'):
        contract.refresh('com')
    assert contract.get_checkpoint('com') == {}
