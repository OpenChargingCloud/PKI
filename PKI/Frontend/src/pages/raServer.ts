import { raServerAPI as api, type RAServer } from '../api/client';
import { toURL } from '@node/basePath';
import type { Page } from '@node/router';
import { reloadButton, shell } from '@node/shell';
import { errorMessage } from '@node/ui';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

/** How a client may authenticate, in a few words. */
const IN_WORDS: Record<string, string> = {
    httpAuthWithoutTLS:    'a password, without TLS',
    httpAuthOverTLS:       'a password, over TLS',
    tlsClientCertificate:  'a TLS client certificate'
};

/**
 * The server the registration authorities connect to - a CSMS that has the
 * CSRs of its charging stations signed here, over a WebSocket or SSH - as it
 * is: whether it listens, how one may sign in, who is connected now, and how
 * many certificates each login had signed.
 *
 * Read-only: the server is changed in the "webSocketServer" section of the
 * file, and the PKI started again. Who may connect is changed on the pages
 * below it - the logins, the accepted chains and the connections, which are
 * every WebSocket server's pages.
 */
export const raServerPage: Page = {

    title: 'Registration authorities',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ra-server',
            title:     'Registration authorities',
            subtitle:  'the server they connect to, who is connected, and what each had signed.',
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        let cancelled = false;


        function draw(server: RAServer): void {

            const configuration  = server.configuration;
            const signed         = Object.entries(server.signed);

            render(content, html`

                <div class="cards">

                    <section class="card">

                        <h2><i class="fa-solid fa-server"></i> The server</h2>

                        <div class="kv">
                            <span class="k">WebSocket</span>
                            <span class="v" id="ra-websocket">
                                ${server.state.running
                                      ? html`<span class="badge ok">listening</span> on port ${configuration.port ?? '-'}${server.state.tls ? ', over TLS' : ', without TLS'}`
                                      : configuration.enabled === true
                                            ? html`<span class="badge warn">switched on, not listening</span>`
                                            : html`<span class="badge">switched off</span>`}
                            </span>
                            <span class="k">SSH</span>
                            <span class="v" id="ra-ssh">
                                ${server.state.ssh
                                      ? html`<span class="badge ok">served</span> on port ${server.state.sshPort ?? '-'}, as the subsystem <code>pki@open.charging.cloud</code>`
                                      : html`<span class="badge">not served</span>`}
                            </span>
                            <span class="k">Signing in</span>
                            <span class="v">${(configuration.clientAuthentication ?? []).map(way => IN_WORDS[way] ?? way).join(', ') || '-'}</span>
                            <span class="k">Revocation</span>
                            <span class="v">${configuration.checkCertificateRevocation ? 'a client certificate is checked against its CRL' : 'not checked'}</span>
                        </div>

                        <p class="hint">
                            Changed in the <code>webSocketServer</code> section of the file, and the PKI started again.
                            Who may connect: the <a href="${toURL('/configuration/ra-server/logins')}">logins</a>,
                            the <a href="${toURL('/configuration/ra-server/trust')}">accepted chains</a> and the
                            <a href="${toURL('/configuration/connections')}">connections</a> - a registration authority
                            is written down as both, a connection of the type "RegistrationAuthority" that lets it in and a
                            login it signs in with.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-plug"></i> Connected now</h2>

                        ${server.connected.length === 0
                              ? html`<p class="muted" id="ra-connected">No registration authority is connected.</p>`
                              : html`<ul id="ra-connected">${repeat(server.connected, login => login, login => html`<li><code>${login}</code></li>`)}</ul>`}

                    </section>

                    <section class="card wide">

                        <h2><i class="fa-solid fa-signature"></i> What they had signed</h2>

                        ${signed.length === 0
                              ? html`<p class="muted" id="ra-signed">Nothing was signed for a registration authority yet.</p>`
                              : signedTable(signed)}

                    </section>

                </div>
            `);

        }


        function signedTable(signed: [string, number][]): TemplateResult {

            return html`
                <div class="table-scroll">
                    <table class="table" id="ra-signed">
                        <thead>
                            <tr>
                                <th>Login</th>
                                <th>Certificates</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            ${repeat(signed, ([login]) => login, ([login, count]) => html`
                                <tr>
                                    <td><code>${login}</code></td>
                                    <td>${count}</td>
                                    <td class="right">
                                        ${count === 0 ? nothing : html`<a href="${toURL('/pki')}">on the PKI page</a>`}
                                    </td>
                                </tr>
                            `)}
                        </tbody>
                    </table>
                </div>
            `;

        }


        async function load(): Promise<void> {

            try
            {

                const server = await api.get();

                if (!cancelled)
                    draw(server);

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        void load();

        return () => { cancelled = true; };

    }

};
