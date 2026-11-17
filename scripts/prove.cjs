const fs = require('node:fs');
const {execFileSync} = require('node:child_process');
const {assert, equal, sourceHash, invoke, read, rpc, receipt, receiptSummary, save, delay} = require('./transport.cjs');
const {decodeReceipt} = require('./receipt-calldata.cjs');

const labels = ['com', 'org', 'invalid'];
const source = 'https://dns.google/resolve';

async function readDelegation(name) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(source + '?name=' + name + '.&type=DS&do=1&cd=1',
        {signal: AbortSignal.timeout(20000)});
      assert(response.ok, 'Independent DNS HTTP ' + response.status);
      const raw = await response.json();
      assert(equal(raw.Question, [{name: name + '.', type: 43}]) && !raw.TC, 'Unexpected DNS question');
      if (name === 'invalid') {
        assert(raw.Status === 3 && !raw.Answer?.length, 'Expected no positive DS answer');
        return [];
      }
      assert(raw.Status === 0, 'Could not fetch DS records');
      return raw.Answer.filter(row => row.type === 43).map(({data}) => {
        const [tag, algorithm, type, ...pieces] = data.trim().split(/\s+/);
        return {key_tag: Number(tag), algorithm: Number(algorithm), digest_type: Number(type),
          digest: pieces.join('').toLowerCase()};
      }).sort((a, b) => a.key_tag - b.key_tag || a.algorithm - b.algorithm || a.digest_type - b.digest_type
        || a.digest.localeCompare(b.digest));
    } catch (error) {
      if (attempt === 2) throw error;
      await delay(3000);
    }
  }
}

async function main() {
  const wallets = JSON.parse(process.env.ANCHOR_ACCOUNTS || '[]');
  assert(wallets.length === 2 && wallets[0].address !== wallets[1].address, 'Two wallets required');
  const reference = Object.fromEntries(await Promise.all(labels.map(async name => [name, await readDelegation(name)])));
  assert(reference.com.length && reference.org.length && !equal(reference.com, reference.org), 'Expected distinct DS sets');
  assert(await rpc('eth_chainId', []) === '0xf22f', 'StudioNet only');
  const code = fs.readFileSync('contracts/root_anchor.py');
  process.env.ANCHOR_ACCOUNT = wallets[0].name;
  const deployment = await invoke('deploy', ['deploy', '--contract', 'contracts/root_anchor.py']);
  const deployed = await receipt('deploy', deployment, true);
  const contract = deployed.to_address || deployed.recipient;
  assert(/^0x[0-9a-f]{40}$/i.test(contract) && code.equals(Buffer.from(deployed.data.contract_code, 'base64')), 'Deployed code mismatch');
  const report = {contract, deployment, revision: process.env.GITHUB_SHA, source_sha256: sourceHash,
    independent_reference: reference, checkpoints: {}, trace: []};

  async function verify(label, raw, actor, args, error) {
    assert((raw.from_address || raw.sender).toLowerCase() === wallets[actor].address
      && (raw.to_address || raw.recipient).toLowerCase() === contract.toLowerCase(), 'Wrong receipt addresses');
    assert(equal(await decodeReceipt(raw), args), 'Wrong signed calldata');
    if (error) {
      const payload = Buffer.from(raw.consensus_data.leader_receipt[0].result, 'base64');
      assert(payload[0] === 1 && payload.subarray(1).toString() === error, 'Wrong expected rejection');
    }
    const snapshots = {};
    for (const name of labels) {
      const stored = await read(label + '-' + name, ['call', contract, 'get_checkpoint', '--args', name]);
      assert(equal(stored, report.checkpoints[name] || {}), 'Unexpected checkpoint at ' + label + ' for ' + name);
      snapshots[name] = stored;
    }
    report.trace.push({label, ...receiptSummary(raw), signer: wallets[actor].address, args, error: error || null, snapshots});
    save('progress', report);
  }

  async function refresh(label, name, actor, error) {
    process.env.ANCHOR_ACCOUNT = wallets[actor].name;
    const hash = await invoke(label, ['write', contract, 'refresh', '--args', name]);
    const raw = await receipt(label, hash, !error);
    if (!error) {
      const candidate = await read(label + '-new', ['call', contract, 'get_active', '--args', name]);
      assert(candidate.name === name + '.' && equal(candidate.ds, reference[name]), 'DS set differs from fresh DNS response');
      report.checkpoints[name] = candidate;
    }
    await verify(label, raw, actor, {method: 'refresh', args: [name]}, error);
  }

  await verify('deploy', deployed, 0, {args: []});
  await refresh('com', 'com', 1);
  await refresh('replay', 'com', 0, 'No newer delegation evidence');
  await refresh('org', 'org', 0);
  await refresh('invalid', 'invalid', 1, 'No positive signed DNS answer');
  const checks = execFileSync('python', ['scripts/verify_dnssec.py'],
    {input: JSON.stringify(Object.values(report.checkpoints))});
  report.independent_signatures = JSON.parse(checks);
  assert(equal(report.independent_signatures.verified, ['com.', 'org.']), 'Independent signature check incomplete');
  assert(code.equals(Buffer.from(await rpc('gen_getContractCode', [contract]), 'base64')), 'Fresh code differs');
  save('verified', report);
  console.log(JSON.stringify({contract, deployment, receipts: report.trace.length, verified: report.independent_signatures.verified}));
}

main().catch(error => { console.error(error); process.exitCode = 1; });
