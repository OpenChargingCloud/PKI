import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { html } from '@node/view';
import { nodeMenu, startNode } from '@node/start';

import { configurationPage } from './pages/configuration';
import { pkiPage } from './pages/pki';
import { raServerPage } from './pages/raServer';

import { connectionsPage }      from '@node/connecting/pages/connections';
import { clientTrustPage }      from '@node/connecting/pages/clientTrust';
import { webSocketLoginsPage }  from '@node/connecting/pages/webSocketLogins';
import { setConnectionsResource, setLoginServer, setNodeNoun, setNodeTraits, setStationsResource } from '@node/connecting/settings';

// The registration authorities - a CSMS that has the CSRs of its charging
// stations signed here - connect over a WebSocket or SSH. Each is written down
// twice, as everybody who connects to a node is: as a connection of the type
// "RegistrationAuthority", which lets it in, and as a login, which says what
// it signs in with. Both are drawn by the pages every node with a WebSocket
// server draws them with - WWCP_Node's connecting/ -, told here that they are
// a PKI's: below "/configuration/ra-server", at the resource
// "registrationAuthorities", and of registration authorities, which speak the
// messages of a PKI and know nothing of OCPP's security profiles.
setConnectionsResource('registrationAuthorities');
setStationsResource('registrationAuthorities');
setNodeNoun('PKI');
setNodeTraits({ oneNodePerOCPPVersion: false, isConnectedTo: true, connectsDown: false,
                examples: { description: 'CSMS 01, a registration authority', url: 'wss://pki.example.org:2364/csms-01' } });
setLoginServer({
    root:              '/configuration/ra-server',
    page:              '/configuration/ra-server',
    loginsPage:        '/configuration/ra-server/logins',
    trustPage:         '/configuration/ra-server/trust',
    login:             'registration authority',
    logins:            'registration authorities',
    who:               'a CSMS, or whoever else has CSRs signed here',
    example:           'csms-01',
    describedAs:       'CSMS 01',
    protocol:          'PKI',
    icon:              'fa-building-shield',
    securityProfiles:  false,
    sshChannels:       false,
    allowedOf:         Server => (Server as { configuration?: { clientAuthentication?: ('httpAuthWithoutTLS' | 'httpAuthOverTLS' | 'tlsClientCertificate')[] } }).configuration?.clientAuthentication ?? []
});

// What a PKI has a page for of its own is its certificates - the CAs, what
// they signed, and the forms that make more of them - at "/pki", first in the
// menu. Everything else is what every node has: its configuration, name
// resolution, the time, the SSH server, the node's own certificate store, who
// it is as a client and the log - see WWCP_Node's start.ts.
startNode({

    name:  'PKI',
    icon:  'fa-key',

    menu: [
        { path: '/pki', label: 'PKI', icon: 'fa-sitemap', permission: [ 'issuance:read', 'authorities:read' ] },
        nodeMenu.configuration([
            nodeMenu.dns,
            nodeMenu.nts,
            nodeMenu.ssh,
            { ...nodeMenu.certificates, label: 'Trusted certificates' },
            // Who may connect as a registration authority, and with what.
            { path: '/configuration/ra-server',         label: 'Registration authorities',  icon: 'fa-building-shield',  permission: [ 'registrationAuthorities:read' ] },
            { path: '/configuration/ra-server/logins',  label: 'WebSocket logins',          icon: 'fa-users-gear',       permission: [ 'registrationAuthorities:read' ] },
            { path: '/configuration/ra-server/trust',   label: 'Accepted chains',           icon: 'fa-user-shield',      permission: [ 'certificates:read' ] },
            { path: '/configuration/connections',       label: 'Connections',               icon: 'fa-network-wired',    permission: [ 'registrationAuthorities:read' ] },
            nodeMenu.identities,
            // What the web interface shows over HTTPS, where the "web"
            // section says "tls": { "certificate": "store" }.
            nodeMenu.serverIdentities
        ]),
        nodeMenu.logs
    ],

    // The node's own store is what this PKI believes and shows as a node -
    // the roots of its time servers, say - and not what it makes. Said on
    // its pages, because "Certificates" on a PKI reads as the other thing.
    certificates: {
        title:  'Trusted certificates',
        hints: {
            believes:  html`
                What this PKI itself believes, beside the roots of this machine: a time server or a name server
                with a CA of its own is reached through one of these. The certificates this PKI makes are on the
                PKI page, not here.
            `,
            presents:  html`
                What it will show a server that asks who it is, with its private key. Kept for when this PKI
                connects to one that does; nothing here presents it yet.
            `
        }
    },

    // "/" is every node's: the first page of the menu the person signed in may
    // open - the PKI for whoever may read it.
    pages: {

        '/configuration':                   configurationPage,
        '/configuration/ra-server':         raServerPage,
        '/configuration/ra-server/logins':  webSocketLoginsPage,
        '/configuration/ra-server/trust':   clientTrustPage,
        '/configuration/connections':       connectionsPage,
        '/pki':                             pkiPage

    }

});
