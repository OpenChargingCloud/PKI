/**
 * The PKI page drawn, in a document of happy-dom, against a stand-in PKI:
 * the list and its filter by the common name, the details of a certificate
 * opened from its row, a root CA made from its form and opened in the list,
 * and the forms left out for an account that may sign nothing.
 */

import { asked, field, open, submit, until, type Asked } from '../../test/pki.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

const { pkiPage } = await import('./pki.ts');


const everything = [ 'authorities:read', 'authorities:edit', 'issuance:read', 'issuance:edit' ];

function certificate(id: string, commonName: string, profile: string, issuerId: string | null): Record<string, unknown> {
    return { id, profile, commonName, subject: `CN=${commonName}`, issuer: 'CN=Root', issuerId, serialNumber: '01',
             notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z', keyAlgorithm: 'ecc-p384',
             subjectAlternativeNames: [], pathLength: null, hasPrivateKey: true, fromCSR: false,
             createdAt: '2026-01-01T00:00:00Z', createdBy: 'alice', status: 'valid' };
}

let certificates: Record<string, unknown>[] = [];

function pki({ method, path, body }: Asked): unknown {

    if (method === 'GET' && path === '/pki/certificates')
        return { certificates, total: certificates.length, directory: '/srv/pki', maxValidityDays: 36500,
                 keyAlgorithms: [ 'ecc-p256', 'ecc-p384', 'ecc-p521', 'rsa-2048', 'rsa-3072', 'rsa-4096' ] };

    const one = /^\/pki\/certificates\/([0-9a-f]+)$/.exec(path);

    if (method === 'GET' && one !== null) {
        const found = certificates.find(certificate => certificate['id'] === one[1]);
        return found === undefined
                   ? undefined
                   : { ...found, pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', chainPem: '',
                       chain: [ { id: found['id'], commonName: found['commonName'], profile: found['profile'] } ],
                       issuedCount: 0, belowCount: 0, mayDownloadPrivateKey: false };
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

    it('offers no form to an account that may sign nothing', async () => {

        certificates = [ certificate('aa', 'OCC Root CA', 'rootCA', null) ];

        const root = await open(pkiPage, '/pki', [ 'authorities:read', 'issuance:read' ], pki,
                                root => root.querySelector('table.pki-list') !== null);

        assert.equal(root.querySelector('form'), null);
        assert.equal(root.querySelectorAll('[role="tab"]').length, 1);
        assert.match(root.querySelector('.notice')!.textContent!, /may look at the certificates of this PKI but not sign any/);

    });

});
