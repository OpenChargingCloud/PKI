/**
 * The PKI page drawn, in a document of happy-dom, against a stand-in PKI:
 * the list and its filter by the common name, the details of a certificate
 * opened from its row, a root CA made from its form and opened in the list,
 * and the forms left out for an account that may sign nothing - and the
 * passwords of keys: optional where a key is made, asked for where the CA
 * chosen to sign has one, and given, changed or taken away in the details -
 * and revoking: a certificate revoked from its details, what the Revocation
 * tab lists, and a certificate downloaded with its key as PKCS#12.
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
             createdAt: '2026-01-01T00:00:00Z', createdBy: 'alice', status: 'valid', revokedAt: null, revocationReason: null };
}

/** What the details of a certificate add to what its list says. */
function detailed(found: Record<string, unknown>): Record<string, unknown> {
    return { ...found, pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', chainPem: '',
             chain: [ { id: found['id'], commonName: found['commonName'], profile: found['profile'] } ],
             issuedCount: 0, belowCount: 0,
             mayDownloadPrivateKey: found['profile'] === 'client' || found['profile'] === 'server',
             transparency: { index: 0, loggedAt: '2026-01-01T00:00:00Z',
                             sct: { sct_version: 0, id: 'bG9n', timestamp: 0, extensions: '', signature: 'c2ln' } },
             revocation: found['revokedAt'] ? { id: found['id'], issuerId: found['issuerId'], serialNumber: '01', commonName: found['commonName'],
                                                notAfter: found['notAfter'], revokedAt: found['revokedAt'], reason: found['revocationReason'], revokedBy: 'alice' } : null,
             issuerKeyEncrypted: certificates.find(one => one['id'] === found['issuerId'])?.['keyEncrypted'] === true,
             mayRevoke: found['profile'] !== 'rootCA' && !found['revokedAt'] };
}

/** What the stand-in says of revoking. */
function revocationOverview(): unknown {
    return { publicURL: 'http://pki.example.org', ocspURL: 'http://pki.example.org/api/v1/pki/ocsp',
             crlURL: 'http://pki.example.org/api/v1/pki/crl/{id}.crl',
             reasons: [ 'unspecified', 'keyCompromise' ], crlValidDays: 7, crlValidDaysWithPassword: 30, maxCRLValidDays: 365,
             cas: [ { id: 'aa', commonName: 'OCC Root CA', profile: 'rootCA', automatic: false, hasKey: true,
                      crl: { number: '3', thisUpdate: '2026-01-01T00:00:00Z', nextUpdate: '2026-01-31T00:00:00Z', entries: 1 }, crlURL: null,
                      responder: { serialNumber: '02', notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z', pem: '' } } ],
             revoked: [ { id: 'ee', issuerId: 'aa', serialNumber: '05', commonName: 'CS-0009', notAfter: '2027-01-01T00:00:00Z',
                          revokedAt: '2026-01-03T00:00:00Z', reason: 'keyCompromise', revokedBy: 'alice', inPKI: false, issuer: 'OCC Root CA' } ] };
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

    if (method === 'GET' && path === '/pki/revocation')
        return revocationOverview();

    if (method === 'GET' && path === '/pki/est')
        return { issuer: 'aa', profile: 'client', validDays: 365, labels: {}, tlsClientCertificates: false,
                 enabled: true, path: '/.well-known/est', https: false, issuers: [ { id: 'aa', commonName: 'OCC Root CA', problem: null } ] };

    if (method === 'PUT' && path === '/pki/est')
        return { ...(body as Record<string, unknown>), enabled: true, path: '/.well-known/est', https: false, issuers: [] };

    const revoke = /^\/pki\/certificates\/([0-9a-f]+)\/revoke$/.exec(path);

    if (method === 'POST' && revoke !== null) {
        const found = certificates.find(certificate => certificate['id'] === revoke[1])!;
        found['status']            = 'revoked';
        found['revokedAt']         = '2026-02-01T00:00:00Z';
        found['revocationReason']  = (body as { reason: string }).reason;
        return { ...detailed(found), warning: null };
    }

    const pkcs12 = /^\/pki\/certificates\/([0-9a-f]+)\/pkcs12$/.exec(path);

    if (method === 'POST' && pkcs12 !== null)
        return { id: pkcs12[1], fileName: 'CS-0001.p12', pkcs12: 'MIIC', legacy: (body as { legacy: boolean }).legacy };

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

    it('revokes a certificate, with the password of the key of its CA', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null, true),
                         certificate('bb', 'CS-0001',     'client', 'aa') ];

        const root = await open(pkiPage, '/pki', everything, pki, root => root.querySelector('table.pki-list') !== null);

        root.querySelector<HTMLElement>('tr[data-id="bb"]')!.click();

        await until(() => root.querySelector('#revoke-form') !== null, 'the details offer no revocation');

        assert.ok(root.querySelector('#pkcs12-form'), 'the certificate of a client goes out as PKCS#12');
        assert.equal(root.querySelector('#revoke-form option[value="caCompromise"]'), null, 'caCompromise is the reason of a CA');

        const confirmed = globalThis.confirm;
        globalThis.confirm = () => true;

        try
        {
            field(root, '#revoke-form', 'reason').value             = 'keyCompromise';
            field(root, '#revoke-form', 'issuerKeyPassword').value  = 'root-password';
            submit(root, '#revoke-form');

            await until(() => root.querySelector('#pki-made') !== null, 'nothing said it was revoked');
        }
        finally
        {
            globalThis.confirm = confirmed;
        }

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/certificates/bb/revoke')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { reason: 'keyCompromise', issuerKeyPassword: 'root-password' });
        assert.match(root.querySelector('#pki-made')!.textContent!, /Revoked the client 'CS-0001'/);

        await until(() => root.querySelector('#pki-details-revoked') !== null, 'the details do not say it was revoked');

        assert.match(root.querySelector('tr[data-id="bb"]')!.textContent!, /revoked/);
        assert.equal(root.querySelector('#revoke-form'), null, 'not twice');

    });

    it('downloads a certificate with its key as PKCS#12', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null),
                         certificate('bb', 'CS-0001',     'client', 'aa', true) ];

        const root = await open(pkiPage, '/pki', everything, pki, root => root.querySelector('table.pki-list') !== null);

        root.querySelector<HTMLElement>('tr[data-id="bb"]')!.click();

        await until(() => root.querySelector('#pkcs12-form') !== null, 'the details offer no PKCS#12');

        field(root, '#pkcs12-form', 'keyPassword').value          = 'key-password';
        field(root, '#pkcs12-form', 'pkcs12Password').value       = 'file-password';
        field(root, '#pkcs12-form', 'pkcs12PasswordAgain').value  = 'file-password';
        submit(root, '#pkcs12-form');

        await until(() => /Downloaded CS-0001\.p12/.test(root.querySelector('#pkcs12-note')?.textContent ?? ''), 'nothing was downloaded');

        const sent = asked.find(one => one.method === 'POST' && one.path === '/pki/certificates/bb/pkcs12')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { keyPassword: 'key-password', pkcs12Password: 'file-password', legacy: false });

    });

    it('lists what was revoked and how the CRL of each CA stands', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null, true) ];

        const root = await open(pkiPage, '/pki?tab=revocation', [ 'issuance:read' ], pki,
                                root => root.querySelector('table.pki-revoked') !== null);

        assert.match(root.querySelector('#pki-ocsp-url')!.textContent!, /pki\.example\.org\/api\/v1\/pki\/ocsp/);
        assert.match(root.querySelector('table.pki-revocation-cas tr[data-id="aa"]')!.textContent!, /#3/);
        assert.match(root.querySelector('table.pki-revocation-cas tr[data-id="aa"]')!.textContent!, /with its password/);
        assert.match(root.querySelector('table.pki-revoked tr[data-id="ee"]')!.textContent!, /CS-0009.*deleted/s);
        assert.equal(root.querySelector<HTMLInputElement>('#public-url-form input[name="publicURL"]')!.disabled, true,
                     'the address is the administrator\'s to set');

    });

    it('says what EST signs, and saves a label added', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null),
                         certificate('ab', 'OCC Sub CA',  'subCA',  'aa') ];

        const root = await open(pkiPage, '/pki?tab=est', everything, pki, root => root.querySelector('#est-form') !== null);

        assert.match(root.querySelector('#pki-est-address')!.textContent!, /\/\.well-known\/est$/);
        assert.equal(field(root, '#est-form', 'issuer').value, 'aa');

        root.querySelector<HTMLButtonElement>('#est-add-label')!.click();

        await until(() => root.querySelector('table.est-labels tbody tr') !== null, 'no label was added');

        const label = root.querySelector<HTMLInputElement>('table.est-labels input[name="label-0"]')!;
        label.value = 'csms';
        label.dispatchEvent(new Event('input', { bubbles: true }));

        const as = root.querySelectorAll<HTMLSelectElement>('table.est-labels select')[1]!;
        as.value = 'server';
        as.dispatchEvent(new Event('change', { bubbles: true }));

        submit(root, '#est-form');

        await until(() => asked.some(one => one.method === 'PUT' && one.path === '/pki/est'), 'nothing was saved');

        const sent = asked.find(one => one.method === 'PUT' && one.path === '/pki/est')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { issuer: 'aa', profile: 'client', validDays: 365, tlsClientCertificates: false,
                                 labels: { csms: { issuer: 'aa', profile: 'server', validDays: 365 } } });

    });

    it('offers no form to an account that may sign nothing', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki', [ 'authorities:read', 'issuance:read' ], pki,
                                root => root.querySelector('table.pki-list') !== null);

        assert.equal(root.querySelector('form'), null);
        assert.deepEqual([ ...root.querySelectorAll('[role="tab"]') ].map(tab => tab.id), [ 'tab-certificates', 'tab-transparency', 'tab-revocation', 'tab-est' ],
                         'the list, the log, what was revoked and what EST signs, which are read as the list is');
        assert.match(root.querySelector('.notice')!.textContent!, /may look at the certificates of this PKI but not sign any/);

    });

});
