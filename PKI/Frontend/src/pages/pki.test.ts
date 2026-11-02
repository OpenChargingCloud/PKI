/**
 * The PKI page drawn, in a document of happy-dom, against a stand-in PKI:
 * the list and its filter by the common name, the details of a certificate
 * opened from its row, a root CA made from its form and opened in the list,
 * and the forms left out for an account that may sign nothing - and the
 * passwords of keys: optional where a key is made, asked for where the CA
 * chosen to sign has one, and given, changed or taken away in the details.
 */

import { asked, field, open, submit, until, type Asked } from '../../test/pki.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

const { pkiPage } = await import('./pki.ts');


const everything = [ 'authorities:read', 'authorities:edit', 'issuance:read', 'issuance:edit' ];

function certificate(id: string, commonName: string, profile: string, issuerId: string | null, keyEncrypted = false): Record<string, unknown> {
    return { id, profile, commonName, subject: `CN=${commonName}`, issuer: 'CN=Root', issuerId, serialNumber: '01',
             notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z', keyAlgorithm: 'ecc-p384',
             subjectAlternativeNames: [], pathLength: null, hasPrivateKey: true, keyEncrypted, fromCSR: false,
             createdAt: '2026-01-01T00:00:00Z', createdBy: 'alice', status: 'valid' };
}

/** What the details of a certificate add to what its list says. */
function detailed(found: Record<string, unknown>): Record<string, unknown> {
    return { ...found, pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', chainPem: '',
             chain: [ { id: found['id'], commonName: found['commonName'], profile: found['profile'] } ],
             issuedCount: 0, belowCount: 0, mayDownloadPrivateKey: false,
             transparency: { index: 0, loggedAt: '2026-01-01T00:00:00Z',
                             sct: { sct_version: 0, id: 'bG9n', timestamp: 0, extensions: '', signature: 'c2ln' } } };
}

/** The entries of the stand-in log: what the PKI signed, one of them deleted since. */
const logged = [
    { index: 0, timestamp: 0, loggedAt: '2026-01-01T00:00:00Z', id: 'aa', commonName: 'OCC Root CA', subject: 'CN=OCC Root CA', issuer: 'CN=OCC Root CA',
      profile: 'rootCA', notAfter: '2036-01-01T00:00:00Z', inPKI: true },
    { index: 1, timestamp: 0, loggedAt: '2026-01-02T00:00:00Z', id: 'ee', commonName: 'CS-0009',     subject: 'CN=CS-0009',     issuer: 'CN=OCC Root CA',
      profile: 'client', notAfter: '2027-01-01T00:00:00Z', inPKI: false }
];

let certificates: Record<string, unknown>[] = [];

function pki({ method, path, body }: Asked): unknown {

    if (method === 'GET' && path === '/pki/certificates')
        return { certificates, total: certificates.length, directory: '/srv/pki', maxValidityDays: 36500, minKeyPasswordLength: 8,
                 keyAlgorithms: [ 'ecc-p256', 'ecc-p384', 'ecc-p521', 'rsa-2048', 'rsa-3072', 'rsa-4096' ] };

    if (method === 'GET' && path === '/pki/transparency')
        return { logId: 'bG9nIGlk', publicKey: '-----BEGIN PUBLIC KEY-----\nMFk\n-----END PUBLIC KEY-----\n', treeSize: logged.length,
                 sth: { tree_size: logged.length, timestamp: 0, sha256_root_hash: 'cm9vdA==', tree_head_signature: 'c2ln' },
                 signedAt: '2026-01-02T00:00:00Z', maximumMergeDelay: 0, broken: false, problems: [], directory: '/srv/pki/transparency' };

    if (method === 'GET' && path.startsWith('/pki/transparency/entries'))
        return { treeSize: logged.length, entries: logged };

    const one = /^\/pki\/certificates\/([0-9a-f]+)$/.exec(path);

    if (method === 'GET' && one !== null) {
        const found = certificates.find(certificate => certificate['id'] === one[1]);
        return found === undefined ? undefined : detailed(found);
    }

    const password = /^\/pki\/certificates\/([0-9a-f]+)\/key\/password$/.exec(path);

    if (method === 'POST' && password !== null) {
        const found = certificates.find(certificate => certificate['id'] === password[1])!;
        found['keyEncrypted'] = (body as { newPassword: string | null }).newPassword !== null;
        return detailed(found);
    }

    if (method === 'POST' && path === '/pki/certificates') {
        const made = certificate('dd', (body as { subject: { commonName: string } }).subject.commonName, 'client', 'aa');
        certificates = [ made, ...certificates ];
        return detailed(made);
    }

    if (method === 'POST' && path === '/pki/rootCAs') {
        const made = certificate('cc', (body as { subject: { commonName: string } }).subject.commonName, 'rootCA', null);
        certificates = [ made, ...certificates ];
        return { ...made, pem: '', chainPem: '', chain: [], issuedCount: 0, belowCount: 0, mayDownloadPrivateKey: false };
    }

    return undefined;

}


describe('the PKI page', () => {

    it('lists the certificates and narrows them by their common name', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null),
                         certificate('bb', 'CS-0001',     'client', 'aa') ];

        const root = await open(pkiPage, '/pki', everything, pki, root => root.querySelector('table.pki-list') !== null);

        assert.equal(root.querySelectorAll('table.pki-list tbody tr').length, 2);
        assert.match(root.querySelector('tr[data-id="bb"]')!.textContent!, /OCC Root CA/, 'the issuer is named by its common name');

        const narrow = root.querySelector<HTMLInputElement>('#pki-narrow')!;
        narrow.value = 'cs-00';
        narrow.dispatchEvent(new Event('input', { bubbles: true }));

        await until(() => root.querySelectorAll('table.pki-list tbody tr').length === 1, 'the filter let through what it should not');

        assert.ok(root.querySelector('tr[data-id="bb"]'));
        assert.match(root.querySelector('#pki-count')!.textContent!, /1 of 2/);

    });

    it('opens the details of a certificate from its row', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki', everything, pki, root => root.querySelector('table.pki-list') !== null);

        root.querySelector<HTMLElement>('tr[data-id="aa"]')!.click();

        await until(() => root.querySelector('#pki-details pre.pem') !== null, 'the details were not drawn');

        assert.ok(asked.some(one => one.method === 'GET' && one.path === '/pki/certificates/aa'));
        assert.match(root.querySelector('#pki-details')!.textContent!, /BEGIN CERTIFICATE/);
        assert.ok(root.querySelector('#pki-delete'), 'an account that may make CAs may delete one');
        assert.equal(root.querySelector('#pki-download-key'), null, 'the key of a CA is never offered');

    });

    it('makes a root CA from its form and opens it in the list', async () => {

        certificates = [];

        const root = await open(pkiPage, '/pki?tab=root-ca', everything, pki, root => root.querySelector('#root-ca-form') !== null);

        field(root, '#root-ca-form', 'commonName').value    = 'New Root';
        field(root, '#root-ca-form', 'country').value       = 'de';
        field(root, '#root-ca-form', 'pathLength').value    = '';

        submit(root, '#root-ca-form');

        await until(() => root.querySelector('#pki-made') !== null, 'nothing said the root CA was made');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/rootCAs')!.body as Record<string, unknown>;

        assert.deepEqual(sent['subject'], { commonName: 'New Root', country: 'DE' });
        assert.equal(sent['keyAlgorithm'], 'ecc-p384');
        assert.equal(sent['validDays'], 3650);
        assert.equal(sent['pathLength'], null, 'an emptied path length is none, and not 0');

        assert.ok(root.querySelector('tr[data-id="cc"]'), 'the new root CA is not in the list');
        assert.equal(root.querySelector('#panel-certificates')!.hasAttribute('hidden'), false, 'the list is not shown');

    });

    it('gives a new root CA the password typed twice, and sends nothing where the two differ', async () => {

        certificates = [];

        const root = await open(pkiPage, '/pki?tab=root-ca', everything, pki, root => root.querySelector('#root-ca-form') !== null);

        field(root, '#root-ca-form', 'commonName').value        = 'Locked Root';
        field(root, '#root-ca-form', 'newPassword').value       = 'correct horse battery staple';
        field(root, '#root-ca-form', 'newPasswordAgain').value  = 'correct horse battery stable';

        submit(root, '#root-ca-form');

        await until(() => root.querySelector('#root-ca-error')!.textContent !== '', 'the two passwords were not compared');

        assert.match(root.querySelector('#root-ca-error')!.textContent!, /not the same/);
        assert.equal(asked.some(one => one.method === 'POST' && one.path === '/pki/rootCAs'), false, 'sent with two passwords that differ');

        field(root, '#root-ca-form', 'newPasswordAgain').value  = 'correct horse battery staple';

        submit(root, '#root-ca-form');

        await until(() => root.querySelector('#pki-made') !== null, 'nothing said the root CA was made');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/rootCAs')!.body as Record<string, unknown>;

        assert.equal(sent['keyPassword'], 'correct horse battery staple');
        assert.equal('newPasswordAgain' in sent, false);

    });

    it('sends a key made without a password as having none', async () => {

        certificates = [];

        const root = await open(pkiPage, '/pki?tab=root-ca', everything, pki, root => root.querySelector('#root-ca-form') !== null);

        field(root, '#root-ca-form', 'commonName').value = 'Open Root';

        submit(root, '#root-ca-form');

        await until(() => root.querySelector('#pki-made') !== null, 'nothing said the root CA was made');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/rootCAs')!.body as Record<string, unknown>;

        assert.equal(sent['keyPassword'], null);

    });

    it('asks for the password of a CA only where the CA chosen to sign has one', async () => {

        certificates = [ certificate('aa', 'Open Root',   'rootCA', null),
                         certificate('ab', 'Locked Root', 'rootCA', null, true) ];

        const root = await open(pkiPage, '/pki?tab=issue', everything, pki, root => root.querySelector('#issue-form') !== null);

        const passwordOf = () => root.querySelector<HTMLLabelElement>('#issue-form .issuer-key-password')!;

        assert.equal(passwordOf().hidden, true, 'asked for the password of a CA whose key has none');
        assert.equal(field(root, '#issue-form', 'issuerKeyPassword').disabled, true);

        const issuer = root.querySelector<HTMLSelectElement>('#issue-form select[name="issuer"]')!;
        issuer.value = 'ab';
        issuer.dispatchEvent(new Event('change', { bubbles: true }));

        await until(() => !passwordOf().hidden, 'the password of the CA chosen was not asked for');

        field(root, '#issue-form', 'commonName').value         = 'CS-0001';
        field(root, '#issue-form', 'issuerKeyPassword').value  = 'correct horse battery staple';

        submit(root, '#issue-form');

        await until(() => root.querySelector('#pki-made') !== null, 'nothing said the certificate was made');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/certificates')!.body as Record<string, unknown>;

        assert.equal(sent['issuer'],             'ab');
        assert.equal(sent['issuerKeyPassword'],  'correct horse battery staple');
        assert.equal(sent['keyPassword'],        null);

    });

    it('gives the key of a certificate a password from its details', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki', everything, pki, root => root.querySelector('table.pki-list') !== null);

        root.querySelector<HTMLElement>('tr[data-id="aa"]')!.click();

        await until(() => root.querySelector('#key-password-form') !== null, 'the details offered no password for the key');

        assert.equal(root.querySelector('#key-password-form input[name="password"]'), null, 'asked for a password the key does not have');

        field(root, '#key-password-form', 'newPassword').value       = 'correct horse battery staple';
        field(root, '#key-password-form', 'newPasswordAgain').value  = 'correct horse battery staple';

        submit(root, '#key-password-form');

        await until(() => root.querySelector('#pki-made') !== null, 'nothing said the key has a password now');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/certificates/aa/key/password')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { password: null, newPassword: 'correct horse battery staple' });
        assert.match(root.querySelector('#pki-made')!.textContent!, /has a password now/);

        await until(() => root.querySelector('#key-password-form input[name="password"]') !== null, 'the details do not ask for the password the key has now');

    });

    it('lists the transparency log, the newest first and a deleted certificate still in it', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki?tab=transparency', [ 'issuance:read' ], pki,
                                root => root.querySelector('table.pki-log') !== null);

        const rows = [ ...root.querySelectorAll<HTMLElement>('table.pki-log tbody tr') ];

        assert.deepEqual(rows.map(row => row.dataset['index']), [ '1', '0' ], 'the newest first');
        assert.match(rows[0]!.textContent!, /CS-0009/);
        assert.match(rows[0]!.textContent!, /deleted/);
        assert.match(root.querySelector('#pki-transparency-address')!.textContent!, /\/api\/v1\/pki\/transparency$/);
        assert.match(root.querySelector('#pki-transparency')!.textContent!, /cm9vdA==/);
        assert.ok(asked.some(one => one.method === 'GET' && one.path === '/pki/transparency/entries' &&
                                    one.query.get('start') === '0' && one.query.get('end') === '1'), 'every entry there is, and no more');

        // A row of a certificate the PKI still has opens it in the list.
        rows[1]!.click();

        await until(() => root.querySelector('#pki-details-log') !== null, 'the certificate was not opened from the log');

        assert.match(root.querySelector('#pki-details-log')!.textContent!, /entry #0/);
        assert.equal(root.querySelector('#panel-certificates')!.hasAttribute('hidden'), false);

    });

    it('offers no form to an account that may sign nothing', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki', [ 'authorities:read', 'issuance:read' ], pki,
                                root => root.querySelector('table.pki-list') !== null);

        assert.equal(root.querySelector('form'), null);
        assert.deepEqual([ ...root.querySelectorAll('[role="tab"]') ].map(tab => tab.id), [ 'tab-certificates', 'tab-transparency' ],
                         'the list, and the log, which is read as the list is');
        assert.match(root.querySelector('.notice')!.textContent!, /may look at the certificates of this PKI but not sign any/);

    });

});
