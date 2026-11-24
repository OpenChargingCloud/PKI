/**
 * The page of the registration authorities drawn, in a document of
 * happy-dom, against a stand-in PKI: the server as it is, who is connected,
 * and what each had signed - and nothing of it, where nobody connected yet.
 */

import { open, type Asked } from '../../test/pki.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

const { raServerPage } = await import('./raServer.ts');


function server(connected: string[], signed: Record<string, number>): Record<string, unknown> {
    return {
        configuration:  { enabled: true, port: 2364, clientAuthentication: [ 'httpAuthOverTLS', 'tlsClientCertificate' ], ssh: { enabled: true } },
        state:          { running: true, tls: true, ssh: true, sshPort: 22 },
        connected,
        signed
    };
}

function answering(Server: Record<string, unknown>) {
    return (asked: Asked) => asked.path === '/configuration/ra-server' ? Server : undefined;
}


describe('the page of the registration authorities', () => {

    it('says the server is listening, who is connected, and what each had signed', async () => {

        await open(raServerPage, '/configuration/ra-server', [ 'registrationAuthorities:read' ],
                   answering(server([ 'csms-01' ], { 'csms-01': 3, 'csms-02': 1 })), root => root.querySelector('#ra-signed') !== null);

        assert.match(document.querySelector('#ra-websocket')?.textContent ?? '', /listening on port 2364, over TLS/);
        assert.match(document.querySelector('#ra-ssh')?.textContent        ?? '', /served on port 22/);
        assert.match(document.querySelector('#ra-connected')?.textContent  ?? '', /csms-01/);

        const rows = [ ...document.querySelectorAll('#ra-signed tbody tr') ].map(row => row.textContent?.replace(/\s+/g, ' ').trim());

        assert.deepEqual(rows.map(row => row?.split(' on the PKI page')[0]), [ 'csms-01 3', 'csms-02 1' ]);

    });

    it('says so, where nobody is connected and nothing was signed', async () => {

        await open(raServerPage, '/configuration/ra-server', [ 'registrationAuthorities:read' ],
                   answering(server([], {})), root => root.querySelector('#ra-signed') !== null);

        assert.match(document.querySelector('#ra-connected')?.textContent ?? '', /No registration authority is connected/);
        assert.match(document.querySelector('#ra-signed')?.textContent    ?? '', /Nothing was signed/);

    });

});
