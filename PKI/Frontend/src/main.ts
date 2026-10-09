import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { html } from '@node/view';
import { nodeMenu, startNode } from '@node/start';

import { configurationPage } from './pages/configuration';
import { pkiPage } from './pages/pki';

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
            nodeMenu.identities
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

        '/configuration':  configurationPage,
        '/pki':            pkiPage

    }

});
