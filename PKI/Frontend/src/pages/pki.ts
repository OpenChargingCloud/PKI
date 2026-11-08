import { api,
         apiURL,
         type CertificateProfile,
         type CSRInspection,
         type LogEntry,
         type PKICertificate,
         type PKICertificateDetails,
         type PKICertificates,
         type RevocationOverview,
         type RevocationReason,
         type SubjectName,
         type TransparencyLog }  from '../api/client';
import { auth } from '../auth';
import { must } from '@node/html';
import { appendText, pemBox } from '@node/pemBox';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { rememberTab, tabFromURL, tabsView, type Tab } from '@node/tabs';
import { copyText, errorMessage, field, isChecked, numberField, whileSaving } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * The PKI: every certificate it made, filtered by its common name, with the
 * details of one at a time - and the forms that make more of them: a root CA,
 * a sub-CA below a CA, a certificate for a server or a client with a key made
 * here, and one for the key of a certificate signing request.
 *
 * One page in tabs rather than five pages, because the list is what every
 * form ends in: whatever is made is opened in it at once, and what is typed
 * into one form is still there after a look at the list. Each form is a draft
 * the page holds until it is sent; the filter is none.
 *
 * Beside them, the transparency log: every certificate the PKI signed, in the
 * order it signed them - a deleted one too - with the address a monitor reads
 * it at, and what the log signed last.
 *
 * And what the PKI revoked: a certificate is revoked in its details, and goes
 * into the CRL of its CA and is "revoked" when its responder is asked; the
 * Revocation tab says where certificates find them, and how each CA's CRL and
 * responder stand. A server's or a client's certificate goes out with its key
 * as a PKCS#12 file too.
 *
 * A key made here may be given a password, and need not. A CA whose key has
 * one signs only where its password is given again, so a form shows the field
 * for it once such a CA is chosen to sign; the details of a certificate give
 * its key a password, change it or take it away. The PKI keeps none of them.
 */

/** What a profile is called in a sentence and on a chip. */
const profileWords: Record<CertificateProfile, string> = {
    rootCA:  'root CA',
    subCA:   'sub-CA',
    server:  'server',
    client:  'client'
};

/** "ecc-p256" as a person reads it: "ECC P-256". */
function keyName(Algorithm: string): string {
    const ecc = /^ecc-p(\d+)$/i.exec(Algorithm);
    const rsa = /^rsa-(\d+)$/i.exec(Algorithm);
    return ecc ? `ECC P-${ecc[1]}` : rsa ? `RSA ${rsa[1]}` : Algorithm;
}

/** Why a certificate was revoked, as a sentence says it. */
const reasonWords: Record<RevocationReason, string> = {
    unspecified:           'no reason given',
    keyCompromise:         'its key was compromised',
    caCompromise:          'the key of a CA was compromised',
    affiliationChanged:    'who it is about changed',
    superseded:            'a new one replaces it',
    cessationOfOperation:  'it is not used any more',
    privilegeWithdrawn:    'what it allowed was withdrawn'
};

/** A day, as the browser's language writes it. */
function day(Iso: string): string {
    const date = new Date(Iso);
    return Number.isNaN(date.getTime()) ? Iso : date.toLocaleDateString();
}

/** A moment, as the browser's language writes it. */
function moment(Iso: string): string {
    const date = new Date(Iso);
    return Number.isNaN(date.getTime()) ? Iso : date.toLocaleString();
}

/** How many entries of the log are shown at first, and how many more each time. */
const logPage = 50;

/** A fingerprint in pairs, as openssl and a browser show one. */
function inPairs(Id: string): string {
    return Id.toUpperCase().match(/.{1,2}/g)?.join(':') ?? Id;
}

/** What a file is called that is about this certificate. */
function fileName(Certificate: PKICertificate, Suffix: string): string {
    return (Certificate.commonName.replace(/[^A-Za-z0-9._-]+/g, '_') || Certificate.id.slice(0, 16)) + Suffix;
}

/** Hand the browser a text as a file to save. */
function download(Name: string, Text: string): void {

    const url  = URL.createObjectURL(new Blob([ Text ], { type: 'application/x-pem-file' }));
    const link = document.createElement('a');

    link.href      = url;
    link.download  = Name;

    document.body.append(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1_000);

}

/** Hand the browser bytes, given as Base64, as a file to save. */
function downloadBase64(Name: string, Base64: string, Type: string): void {

    const bytes = Uint8Array.from(atob(Base64), character => character.charCodeAt(0));
    const url   = URL.createObjectURL(new Blob([ bytes ], { type: Type }));
    const link  = document.createElement('a');

    link.href      = url;
    link.download  = Name;

    document.body.append(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1_000);

}

/** The names of a box of them: one per line, or separated by commas or spaces. */
function namesIn(Text: string): string[] {
    return Text.split(/[\s,;]+/).map(name => name.trim()).filter(name => name.length > 0);
}

/** Who a new certificate is about, as its form says it: the empty fields left out. */
function subjectOf(Form: HTMLFormElement): SubjectName {

    const subject: SubjectName = { commonName: field(Form, 'commonName') };

    for (const key of [ 'organization', 'organizationalUnit', 'country', 'state', 'locality' ] as const) {
        const value = field(Form, key);
        if (value.length > 0)
            subject[key] = key === 'country' ? value.toUpperCase() : value;
    }

    return subject;

}


export const pkiPage: Page = {

    title: 'PKI',

    render({ root, url }) {

        const content = shell(root, {
            active:    '/pki',
            title:     'PKI',
            subtitle:  'The certificate authorities of this PKI, and every certificate they signed.',
            // Asked about first, where a form holds a draft: once it is
            // answered, the forms are what the PKI says again - empty.
            actions:   reloadButton(() => { content.querySelectorAll('form').forEach(form => form.reset()); return load(); })
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayMakeCAs  = auth.can('authorities', 'edit');
        const maySign     = auth.can('issuance',    'edit');

        const allTabs: Tab[] = [
            { id: 'certificates',  label: 'Certificates',     icon: 'fa-list'           },
            { id: 'root-ca',       label: 'New root CA',      icon: 'fa-crown'          },
            { id: 'sub-ca',        label: 'New sub-CA',       icon: 'fa-sitemap'        },
            { id: 'issue',         label: 'New certificate',  icon: 'fa-file-signature' },
            { id: 'csr',           label: 'Sign a CSR',       icon: 'fa-file-import'    },
            { id: 'transparency',  label: 'Transparency log', icon: 'fa-scroll'         },
            { id: 'revocation',    label: 'Revocation',       icon: 'fa-ban'            }
        ];

        const tabs = allTabs.filter(tab => tab.id === 'certificates' || tab.id === 'transparency' || tab.id === 'revocation'
                                        || ((tab.id === 'root-ca' || tab.id === 'sub-ca') && mayMakeCAs)
                                        ||  (tab.id === 'issue'                          && maySign)
                                        ||  (tab.id === 'csr'                            && (maySign || mayMakeCAs)));

        let cancelled = false;

        /** What the PKI last said. */
        let current:        PKICertificates | null        = null;

        /** The tab shown. */
        let shown = tabFromURL(tabs, url);

        /** What the list is narrowed to: a text in the common name, and a profile. */
        let narrow          = '';
        let narrowProfile:  CertificateProfile | ''        = '';

        /** The certificate whose details are open, and what the PKI said of it. */
        let openId:         string | null                  = null;
        let details:        PKICertificateDetails | null   = null;
        let detailsProblem                                 = '';

        /** What the last form made, said above the list it was opened in. */
        let made                                           = '';

        /** The transparency log, the entries of it shown - the newest first - and how many. */
        let log:            TransparencyLog | null         = null;
        let logEntries:     LogEntry[]                     = [];
        let logShown                                       = logPage;
        let logProblem                                     = '';

        /** What the PKI says of revoking, once the tab is shown. */
        let revocation:      RevocationOverview | null     = null;
        let revocationProblem                              = '';

        /** The CA each form has chosen to sign, by the id of the form; its first where none was. */
        const issuerChosen: Record<string, string> = {};

        /** What the CSR in its box says, once the PKI has been asked. */
        let csrPreview:     CSRInspection | null           = null;
        let csrProblem                                     = '';
        let csrTimer:       ReturnType<typeof setTimeout> | undefined;


        /** Show another tab, and keep it in the address - and read the log, where it is the log's. */
        function show(id: string): void {
            shown = id;
            rememberTab(tabs, id);
            draw();
            if (id === 'transparency')
                void loadLog();
            if (id === 'revocation')
                void loadRevocation();
        }

        /** Every certificate, or those the filter lets through. */
        function listed(all: PKICertificate[]): PKICertificate[] {
            const text = narrow.trim().toLowerCase();
            return all.filter(certificate => (text.length === 0 || certificate.commonName.toLowerCase().includes(text)) &&
                                             (narrowProfile === '' || certificate.profile === narrowProfile));
        }

        /** The CAs that can sign now: valid, with their key here - and, for a CA below them, allowed to have one. */
        function signers(all: PKICertificate[], ForACA: boolean): PKICertificate[] {
            return all.filter(certificate => (certificate.profile === 'rootCA' || certificate.profile === 'subCA') &&
                                             certificate.hasPrivateKey &&
                                             certificate.status === 'valid' &&
                                             (!ForACA || certificate.pathLength !== 0));
        }

        function commonNameOf(Id: string | null): string {
            return current?.certificates.find(certificate => certificate.id === Id)?.commonName ?? '';
        }


        /** The whole page, from what the PKI last said. */
        function draw(): void {

            if (current === null)
                return;

            const pki = current;

            render(content, html`

                ${mayMakeCAs || maySign ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the certificates of this PKI', 'sign any')}
                    </div>
                `}

                ${tabsView(tabs, shown, show, 'PKI')}

                <section class="tab-panel" role="tabpanel" id="panel-certificates" aria-labelledby="tab-certificates" ?hidden=${shown !== 'certificates'}>
                    ${listView(pki)}
                    ${openId !== null ? detailsView() : nothing}
                </section>

                ${mayMakeCAs ? html`
                    <section class="tab-panel" role="tabpanel" id="panel-root-ca" aria-labelledby="tab-root-ca" ?hidden=${shown !== 'root-ca'}>
                        ${rootCAView(pki)}
                    </section>
                    <section class="tab-panel" role="tabpanel" id="panel-sub-ca" aria-labelledby="tab-sub-ca" ?hidden=${shown !== 'sub-ca'}>
                        ${subCAView(pki)}
                    </section>` : nothing}

                ${maySign ? html`
                    <section class="tab-panel" role="tabpanel" id="panel-issue" aria-labelledby="tab-issue" ?hidden=${shown !== 'issue'}>
                        ${issueView(pki)}
                    </section>` : nothing}

                ${maySign || mayMakeCAs ? html`
                    <section class="tab-panel" role="tabpanel" id="panel-csr" aria-labelledby="tab-csr" ?hidden=${shown !== 'csr'}>
                        ${csrView(pki)}
                    </section>` : nothing}

                <section class="tab-panel" role="tabpanel" id="panel-transparency" aria-labelledby="tab-transparency" ?hidden=${shown !== 'transparency'}>
                    ${transparencyView()}
                </section>

                <section class="tab-panel" role="tabpanel" id="panel-revocation" aria-labelledby="tab-revocation" ?hidden=${shown !== 'revocation'}>
                    ${revocationView()}
                </section>

            `);

        }


        // ------------------------------------------------------------------
        // The list
        // ------------------------------------------------------------------

        function listView(pki: PKICertificates): TemplateResult {

            const shownNow = listed(pki.certificates);

            return html`
                <section class="card" id="pki-certificates">

                    <h2><i class="fa-solid fa-certificate"></i> Certificates</h2>

                    ${made.length > 0 ? html`<div class="notice" id="pki-made" role="status">${made}</div>` : nothing}

                    <div class="pki-filter">
                        <input type="search" id="pki-narrow" placeholder="Common name contains ..." aria-label="Common name contains"
                               .value=${narrow} @input=${(event: Event) => { narrow = (event.currentTarget as HTMLInputElement).value; draw(); }} />
                        <select id="pki-profile" aria-label="Profile"
                                @change=${(event: Event) => { narrowProfile = (event.currentTarget as HTMLSelectElement).value as CertificateProfile | ''; draw(); }}>
                            <option value="" ?selected=${narrowProfile === ''}>Every profile</option>
                            ${(Object.keys(profileWords) as CertificateProfile[]).map(profile => html`
                                <option value="${profile}" ?selected=${narrowProfile === profile}>${profileWords[profile]}</option>
                            `)}
                        </select>
                        <span class="muted" id="pki-count">${shownNow.length} of ${pki.total}</span>
                    </div>

                    ${pki.total === 0
                          ? html`<p class="hint">
                                     This PKI has no certificate yet.
                                     ${mayMakeCAs ? html`Everything begins with a <button type="button" class="btn small" @click=${() => show('root-ca')}>root CA</button>.` : nothing}
                                 </p>`
                          : shownNow.length === 0
                                ? html`<p class="hint">No certificate is let through by the filter.</p>`
                                : html`
                                    <div class="table-scroll">
                                      <table class="records pki-list">
                                          <thead><tr><th>Profile</th><th>Common name</th><th>Signed by</th><th>Valid until</th><th>Status</th><th>Key</th></tr></thead>
                                          <tbody>
                                              ${repeat(shownNow, certificate => certificate.id, certificate => html`
                                                  <tr data-id="${certificate.id}" class="${certificate.id === openId ? 'open' : ''}"
                                                      @click=${() => void open(certificate.id === openId ? null : certificate.id)}>
                                                      <td><span class="chip">${profileWords[certificate.profile]}</span></td>
                                                      <td class="common-name">${certificate.commonName}</td>
                                                      <td>${certificate.issuerId === null ? html`<span class="muted">itself</span>` : commonNameOf(certificate.issuerId) || html`<span class="muted">${certificate.issuer}</span>`}</td>
                                                      <td>${day(certificate.notAfter)}</td>
                                                      <td>${statusChip(certificate)}</td>
                                                      <td>${certificate.hasPrivateKey
                                                                ? certificate.keyEncrypted
                                                                      ? html`<i class="fa-solid fa-lock" title="Its private key is in this PKI, with a password"></i>`
                                                                      : html`<i class="fa-solid fa-key" title="Its private key is in this PKI, without a password"></i>`
                                                                : certificate.fromCSR ? html`<span class="muted">CSR</span>` : nothing}</td>
                                                  </tr>
                                              `)}
                                          </tbody>
                                      </table>
                                    </div>
                                `}

                    <p class="hint">Kept below <code>${pki.directory}</code>, one file per certificate and one per key, named by its fingerprint.</p>

                </section>
            `;

        }

        function statusChip(Certificate: PKICertificate): TemplateResult {
            return Certificate.status === 'valid'
                       ? html`<span class="chip ok">valid</span>`
                       : Certificate.status === 'revoked'
                             ? html`<span class="chip bad">revoked</span>`
                             : html`<span class="chip warn">${Certificate.status === 'expired' ? 'expired' : 'not yet valid'}</span>`;
        }


        // ------------------------------------------------------------------
        // The details of one
        // ------------------------------------------------------------------

        function detailsView(): TemplateResult {

            if (detailsProblem.length > 0)
                return html`<div class="error-box">${detailsProblem}</div>`;

            if (details === null)
                return html`<div class="loading">Loading ...</div>`;

            const certificate  = details;
            const isCA         = certificate.profile === 'rootCA' || certificate.profile === 'subCA';
            const mayDelete    = isCA ? mayMakeCAs : maySign;

            return html`
                <section class="card pki-details" id="pki-details">

                    <h2><i class="fa-solid ${isCA ? 'fa-sitemap' : 'fa-file-contract'}"></i> ${certificate.commonName}</h2>

                    <div class="kv"><span class="k">Profile</span><span class="v">${profileWords[certificate.profile]}${certificate.fromCSR ? ', signed for a CSR' : ''}</span></div>
                    <div class="kv"><span class="k">Subject</span><span class="v"><code>${certificate.subject}</code></span></div>
                    <div class="kv"><span class="k">Chain</span><span class="v">
                        ${certificate.chain.map((step, at) => html`${at > 0 ? html`<i class="fa-solid fa-arrow-left chain-step muted"></i>` : nothing}<button type="button" class="btn small chain-step" ?disabled=${step.id === certificate.id} @click=${() => void open(step.id)}>${step.commonName}</button>`)}
                    </span></div>
                    <div class="kv"><span class="k">Valid</span><span class="v">from ${moment(certificate.notBefore)} until ${moment(certificate.notAfter)} ${statusChip(certificate)}</span></div>
                    <div class="kv"><span class="k">Key</span><span class="v">${keyName(certificate.keyAlgorithm)}${certificate.hasPrivateKey
                                                                                                                  ? certificate.keyEncrypted
                                                                                                                        ? ', its private key in this PKI, with a password'
                                                                                                                        : ', its private key in this PKI, without a password'
                                                                                                                  : ''}</span></div>
                    ${certificate.subjectAlternativeNames.length > 0 ? html`
                        <div class="kv"><span class="k">Other names</span><span class="v">${certificate.subjectAlternativeNames.map(name => html`<code>${name}</code> `)}</span></div>` : nothing}
                    ${isCA ? html`
                        <div class="kv"><span class="k">Path length</span><span class="v">${certificate.pathLength ?? html`<span class="muted">none - any number of sub-CAs below it</span>`}</span></div>
                        <div class="kv"><span class="k">Signed</span><span class="v">${certificate.issuedCount} certificate(s), ${certificate.belowCount} below it in all</span></div>` : nothing}
                    <div class="kv"><span class="k">Serial number</span><span class="v"><code>${certificate.serialNumber}</code></span></div>
                    <div class="kv"><span class="k">SHA-256</span><span class="v fingerprint">${inPairs(certificate.id)}</span></div>
                    <div class="kv"><span class="k">Transparency log</span><span class="v" id="pki-details-log">${certificate.transparency
                        ? html`entry #${certificate.transparency.index}, since ${moment(certificate.transparency.loggedAt)}`
                        : html`<span class="muted">not in it</span>`}</span></div>
                    <div class="kv"><span class="k">Made</span><span class="v">${moment(certificate.createdAt)}${certificate.createdBy !== null ? ` by ${certificate.createdBy}` : ''}</span></div>
                    ${certificate.revocation ? html`
                        <div class="kv"><span class="k">Revoked</span><span class="v" id="pki-details-revoked">
                            ${moment(certificate.revocation.revokedAt)}${certificate.revocation.revokedBy !== null ? ` by ${certificate.revocation.revokedBy}` : ''}:
                            ${reasonWords[certificate.revocation.reason]}
                        </span></div>` : nothing}
                    ${certificate.revocationServices ? caRevocationRows(certificate.revocationServices) : nothing}

                    <div class="pki-actions">
                        <button type="button" class="btn small" id="pki-copy" @click=${(event: Event) => void copy(event.currentTarget as HTMLButtonElement, certificate.pem)}>
                            <i class="fa-solid fa-copy"></i> Copy PEM
                        </button>
                        <button type="button" class="btn small" id="pki-download" @click=${() => download(fileName(certificate, '.crt.pem'), certificate.pem)}>
                            <i class="fa-solid fa-download"></i> Certificate
                        </button>
                        ${certificate.chain.length > 1 ? html`
                            <button type="button" class="btn small" id="pki-download-chain" @click=${() => download(fileName(certificate, '.chain.pem'), certificate.chainPem)}>
                                <i class="fa-solid fa-link"></i> Chain without the root
                            </button>` : nothing}
                        ${certificate.mayDownloadPrivateKey ? html`
                            <button type="button" class="btn small" id="pki-download-key" @click=${() => void downloadKey(certificate)}>
                                <i class="fa-solid fa-key"></i> Private key
                            </button>` : nothing}
                        ${certificate.revocationServices?.crl ? html`
                            <a class="btn small" id="pki-download-crl" href="${apiURL(`/pki/crl/${certificate.id}.crl`)}" download="${fileName(certificate, '.crl')}">
                                <i class="fa-solid fa-ban"></i> CRL
                            </a>` : nothing}
                        ${mayDelete ? html`
                            <button type="button" class="btn small danger" id="pki-delete" @click=${() => void remove(certificate)}>
                                <i class="fa-solid fa-trash"></i> Delete
                            </button>` : nothing}
                        <span class="form-notice" role="status" id="pki-details-note"></span>
                        <span class="form-error"  role="alert"  id="pki-details-error"></span>
                    </div>

                    <pre class="pem">${certificate.pem}</pre>

                    ${certificate.mayDownloadPrivateKey ? pkcs12View(certificate) : nothing}

                    ${certificate.hasPrivateKey && mayDelete ? keyPasswordView(certificate) : nothing}

                    ${certificate.revocationServices && certificate.hasPrivateKey && mayMakeCAs ? signCRLView(certificate) : nothing}

                    ${certificate.mayRevoke ? revokeView(certificate) : nothing}

                </section>
            `;

        }

        /** What a CA's CRL and responder say, in the rows of its details. */
        function caRevocationRows(Services: NonNullable<PKICertificateDetails['revocationServices']>): TemplateResult {
            return html`
                <div class="kv"><span class="k">CRL</span><span class="v" id="pki-details-crl">${Services.crl
                    ? html`number ${Services.crl.number}, ${Services.crl.entries} certificate(s) in it, signed ${moment(Services.crl.thisUpdate)}${Services.crl.nextUpdate !== null ? html`, until ${moment(Services.crl.nextUpdate)}` : nothing}
                           ${Services.automatic ? html`<span class="muted">- signed anew by the PKI by itself</span>` : nothing}`
                    : html`<span class="muted">none yet${Services.hasKey ? ' - signed the next time its key is open' : ': its key is not in this PKI'}</span>`}</span></div>
                <div class="kv"><span class="k">OCSP responder</span><span class="v" id="pki-details-responder">${Services.responder
                    ? html`until ${moment(Services.responder.notAfter)}`
                    : html`<span class="muted">none yet</span>`}</span></div>
            `;
        }

        /** The certificate, its key and the sub-CAs above it, as one PKCS#12 file. */
        function pkcs12View(Certificate: PKICertificateDetails): TemplateResult {
            return html`
                <form id="pkcs12-form" class="form-stack pkcs12" @submit=${(event: SubmitEvent) => onPKCS12(event, Certificate)}>

                    <h3><i class="fa-solid fa-file-zipper"></i> As PKCS#12</h3>

                    <p class="hint">
                        The certificate, its private key and the sub-CAs above it - not the root - in one file, as Windows,
                        Java and many a charging station import it. The file is encrypted with a password of its own.
                    </p>

                    ${Certificate.keyEncrypted ? html`
                        <label>Password of its key
                            <input type="password" name="keyPassword" required autocomplete="off" />
                        </label>` : nothing}

                    <label>Password of the file
                        <input type="password" name="pkcs12Password" required minlength="${current?.minKeyPasswordLength ?? 8}" autocomplete="new-password" />
                        <span class="hint">${current?.minKeyPasswordLength ?? 8} characters at least; whatever imports the file asks for it.</span>
                    </label>
                    <label>The password again
                        <input type="password" name="pkcs12PasswordAgain" required autocomplete="new-password" />
                    </label>
                    <label class="checkbox">
                        <input type="checkbox" name="legacy" />
                        Encrypted as older devices read it - Triple-DES and SHA-1, for nothing that opens AES
                    </label>

                    ${formActions('pkcs12', 'Download as PKCS#12')}

                </form>
            `;
        }

        async function onPKCS12(event: SubmitEvent, Certificate: PKICertificateDetails): Promise<void> {

            event.preventDefault();

            const form      = event.currentTarget as HTMLFormElement;
            const error     = must<HTMLElement>(content, '#pkcs12-error');
            const password  = field(form, 'pkcs12Password', false);

            error.textContent = '';

            if (password !== field(form, 'pkcs12PasswordAgain', false)) {
                error.textContent = 'The two passwords are not the same.';
                return;
            }

            const keyPassword  = Certificate.keyEncrypted ? field(form, 'keyPassword', false) : null;
            const legacy       = isChecked(form, 'legacy');

            try
            {
                const file = await whileSaving(content, must<HTMLElement>(content, '#pkcs12-note'),
                                               () => api.pki.pkcs12(Certificate.id, keyPassword, password, legacy));
                form.reset();
                downloadBase64(file.fileName, file.pkcs12, 'application/x-pkcs12');
                must<HTMLElement>(content, '#pkcs12-note').textContent = `Downloaded ${file.fileName}.`;
            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }

        /** Revoke it, for good, and why. */
        function revokeView(Certificate: PKICertificateDetails): TemplateResult {

            const isCA = Certificate.profile === 'rootCA' || Certificate.profile === 'subCA';

            return html`
                <form id="revoke-form" class="form-stack revoke" @submit=${(event: SubmitEvent) => onRevoke(event, Certificate)}>

                    <h3><i class="fa-solid fa-ban"></i> Revoke</h3>

                    <p class="hint">
                        For good: it goes into the CRL of its CA, signed anew at once, and its CA's OCSP responder says "revoked"
                        to whoever asks - also after it is deleted from this PKI. A certificate to be believed again is made anew.
                    </p>

                    <label>Why
                        <select name="reason">
                            ${(Object.keys(reasonWords) as RevocationReason[]).filter(reason => isCA || reason !== 'caCompromise').map(reason => html`
                                <option value="${reason}">${reason} - ${reasonWords[reason]}</option>
                            `)}
                        </select>
                    </label>

                    ${Certificate.issuerKeyEncrypted ? html`
                        <label>Password of the key of its CA
                            <input type="password" name="issuerKeyPassword" required autocomplete="off" />
                            <span class="hint">The CRL of '${commonNameOf(Certificate.issuerId)}' is signed with its key, which has a password.</span>
                        </label>` : nothing}

                    <div class="form-actions">
                        <button type="submit" class="btn danger">Revoke it</button>
                        <span id="revoke-note"  class="form-notice" role="status"></span>
                        <span id="revoke-error" class="form-error"  role="alert"></span>
                    </div>

                </form>
            `;

        }

        function onRevoke(event: SubmitEvent, Certificate: PKICertificateDetails): void {

            event.preventDefault();

            const form    = event.currentTarget as HTMLFormElement;
            const reason  = field(form, 'reason') as RevocationReason;

            if (!confirm(`Revoke the ${profileWords[Certificate.profile]} '${Certificate.commonName}' for good?\n\nThis is not undone: a certificate to be believed again is made anew.`))
                return;

            const issuerKeyPassword = Certificate.issuerKeyEncrypted ? issuerPasswordOf(form) : null;

            void make(form, 'revoke', () => api.pki.revoke(Certificate.id, reason, issuerKeyPassword),
                      revoked => `Revoked the ${profileWords[revoked.profile]} '${revoked.commonName}': ${reasonWords[reason]}.` +
                                 ((revoked as { warning?: string | null }).warning ? ` ${(revoked as { warning?: string | null }).warning}` : ''));

        }

        /** Sign the CRL of a CA anew, by hand: what a CA whose key has a password needs. */
        function signCRLView(Certificate: PKICertificateDetails): TemplateResult {
            return html`
                <form id="sign-crl-form" class="form-stack sign-crl" @submit=${(event: SubmitEvent) => onSignCRL(event, Certificate)}>

                    <h3><i class="fa-solid fa-rotate"></i> Sign its CRL anew</h3>

                    <p class="hint">
                        ${Certificate.keyEncrypted
                              ? 'Its key has a password, so the PKI signs its CRL only where somebody gives it: now, or the next time it signs or revokes a certificate. Its OCSP responder is made anew too where that is due.'
                              : 'The PKI signs its CRL anew by itself, before half of its time is over; this signs it now, for as long as is asked.'}
                    </p>

                    ${Certificate.keyEncrypted ? html`
                        <label>Password of its key
                            <input type="password" name="keyPassword" required autocomplete="off" />
                        </label>` : nothing}

                    <label>Believed for (days)
                        <input type="number" name="validDays" min="1" max="365" placeholder="${Certificate.keyEncrypted ? (revocation?.crlValidDaysWithPassword ?? 30) : (revocation?.crlValidDays ?? 7)}" />
                        <span class="hint">Empty for what the PKI gives a CRL of a CA like this one.</span>
                    </label>

                    ${formActions('sign-crl', 'Sign the CRL')}

                </form>
            `;
        }

        async function onSignCRL(event: SubmitEvent, Certificate: PKICertificateDetails): Promise<void> {

            event.preventDefault();

            const form         = event.currentTarget as HTMLFormElement;
            const error        = must<HTMLElement>(content, '#sign-crl-error');
            const keyPassword  = Certificate.keyEncrypted ? field(form, 'keyPassword', false) : null;
            const validDays    = field(form, 'validDays') === '' ? null : numberField(form, 'validDays');

            error.textContent = '';

            try
            {
                const services = await whileSaving(content, must<HTMLElement>(content, '#sign-crl-note'),
                                                   () => api.pki.signCRL(Certificate.id, keyPassword, validDays));
                form.reset();
                if (details !== null && details.id === Certificate.id)
                    details = { ...details, revocationServices: services };
                draw();
                must<HTMLElement>(content, '#sign-crl-note').textContent = `Signed CRL number ${services.crl?.number ?? '?'}.`;
            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }

        /** Give the key of a certificate a password, change it, or take it away. */
        function keyPasswordView(Certificate: PKICertificateDetails): TemplateResult {
            return html`
                <form id="key-password-form" class="form-stack key-password" @submit=${(event: SubmitEvent) => onKeyPassword(event, Certificate)}>

                    <h3><i class="fa-solid fa-lock"></i> Password of its private key</h3>

                    <p class="hint">
                        ${Certificate.keyEncrypted
                              ? 'Its key has a password. A new one replaces it; none takes it away, and the key is kept unencrypted.'
                              : 'Its key has no password: whoever can read the directory of this PKI can use it. A password is optional.'}
                    </p>

                    ${Certificate.keyEncrypted ? html`
                        <label>The password it has
                            <input type="password" name="password" required autocomplete="off" />
                        </label>` : nothing}

                    ${newPasswordFields(Certificate.keyEncrypted ? 'Empty, to take the password away.' : '', Certificate.keyEncrypted ? 'The new password' : 'Password of its key')}

                    ${formActions('key-password', Certificate.keyEncrypted ? 'Change the password' : 'Give it a password')}

                </form>
            `;
        }

        function onKeyPassword(event: SubmitEvent, Certificate: PKICertificateDetails): void {

            event.preventDefault();

            const form         = event.currentTarget as HTMLFormElement;
            const newPassword  = newPasswordOf(form, 'key-password');

            if (newPassword === undefined)
                return;

            if (newPassword === null && !Certificate.keyEncrypted) {
                must<HTMLElement>(content, '#key-password-error').textContent = 'Its key has no password, and none was given.';
                return;
            }

            const password = Certificate.keyEncrypted ? field(form, 'password', false) : null;

            void make(form, 'key-password', () => api.pki.keyPassword(Certificate.id, password, newPassword),
                      changed => newPassword === null
                                     ? `The private key of '${changed.commonName}' has no password any more.`
                                     : Certificate.keyEncrypted
                                           ? `The private key of '${changed.commonName}' has a new password.`
                                           : `The private key of '${changed.commonName}' has a password now.`);

        }

        /** Open the details of a certificate - or close them, with null. */
        async function open(Id: string | null): Promise<void> {

            openId          = Id;
            details         = null;
            detailsProblem  = '';
            draw();

            if (Id === null)
                return;

            try
            {
                const loaded = await api.pki.get(Id);
                if (cancelled || openId !== Id)
                    return;
                details = loaded;
            }
            catch (problem)
            {
                if (cancelled || openId !== Id)
                    return;
                detailsProblem = `The certificate could not be loaded: ${errorMessage(problem)}`;
            }

            draw();

        }

        async function copy(Button: HTMLButtonElement, Text: string): Promise<void> {
            must<HTMLElement>(content, '#pki-details-note').textContent = await copyText(Text);
            Button.blur();
        }

        async function downloadKey(Certificate: PKICertificateDetails): Promise<void> {

            const error = must<HTMLElement>(content, '#pki-details-error');
            error.textContent = '';

            try
            {
                const key = await api.pki.privateKey(Certificate.id);
                download(fileName(Certificate, '.key.pem'), key.privateKey);
                if (key.encrypted)
                    must<HTMLElement>(content, '#pki-details-note').textContent = 'The key is encrypted with its password, which whatever opens it asks for.';
            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }

        async function remove(Certificate: PKICertificateDetails): Promise<void> {

            const what   = `the ${profileWords[Certificate.profile]} '${Certificate.commonName}'`;
            const below  = Certificate.belowCount;

            const question = (below > 0
                                  ? `Delete ${what} and the ${below} certificate(s) below it for good?`
                                  : `Delete ${what} for good?`) +
                             '\n\nIts file and its key are gone afterwards. Nothing that went out is revoked by this: ' +
                             'whoever believes its root goes on believing it.';

            if (!confirm(question))
                return;

            const error = must<HTMLElement>(content, '#pki-details-error');
            error.textContent = '';

            try
            {

                const deleted = await whileSaving(content, must<HTMLElement>(content, '#pki-details-note'),
                                                  () => api.pki.remove(Certificate.id, below > 0));

                openId   = null;
                details  = null;
                made     = `Deleted ${what}${deleted.deleted.length > 1 ? ` and ${deleted.deleted.length - 1} certificate(s) below it` : ''}.` +
                           (deleted.warning ? ` ${deleted.warning}` : '');

                await load();

            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }


        // ------------------------------------------------------------------
        // What every form has
        // ------------------------------------------------------------------

        function subjectFields(): TemplateResult {
            return html`
                <div class="subject-fields">
                    <label>Common name (CN)
                        <input name="commonName" required maxlength="64" autocomplete="off" />
                    </label>
                    <label>Organization (O)
                        <input name="organization" maxlength="64" />
                    </label>
                    <label>Organizational unit (OU)
                        <input name="organizationalUnit" maxlength="64" />
                    </label>
                    <label>Country (C)
                        <input name="country" class="capitals" maxlength="2" pattern="[A-Za-z]{2}" placeholder="DE" />
                    </label>
                    <label>State or province (ST)
                        <input name="state" maxlength="64" />
                    </label>
                    <label>Locality (L)
                        <input name="locality" maxlength="64" />
                    </label>
                </div>
            `;
        }

        function keyField(pki: PKICertificates, Preset: string): TemplateResult {
            return html`
                <label>Key
                    <select name="keyAlgorithm">
                        ${pki.keyAlgorithms.map(algorithm => html`<option value="${algorithm}" ?selected=${algorithm === Preset}>${keyName(algorithm)}</option>`)}
                    </select>
                </label>
            `;
        }

        function validityField(pki: PKICertificates, Days: number, Hint: string): TemplateResult {
            return html`
                <label>Valid for (days)
                    <input type="number" name="validDays" min="1" max="${pki.maxValidityDays}" value="${Days}" required />
                    <span class="hint">${Hint}</span>
                </label>
            `;
        }

        function pathLengthField(Preset: string, Hint: string): TemplateResult {
            return html`
                <label>Path length
                    <input type="number" name="pathLength" min="0" max="16" value="${Preset}" placeholder="none" />
                    <span class="hint">${Hint}</span>
                </label>
            `;
        }

        /** The CA a form has chosen to sign: the one picked, or the first that can. */
        function chosenIssuer(pki: PKICertificates, FormId: string, ForACA: boolean): PKICertificate | undefined {
            const all = signers(pki.certificates, ForACA);
            return all.find(ca => ca.id === issuerChosen[FormId]) ?? all[0];
        }

        /**
         * Who signs it - and the password of its key, asked for only where
         * the CA chosen has one: a field that is not shown is no field of the
         * form, and sends nothing.
         */
        function issuerField(pki: PKICertificates, ForACA: boolean, FormId: string): TemplateResult {

            const chosen   = chosenIssuer(pki, FormId, ForACA);
            const locked   = chosen?.keyEncrypted ?? false;

            return html`
                <label>Signed by
                    <select name="issuer" required
                            @change=${(event: Event) => { issuerChosen[FormId] = (event.currentTarget as HTMLSelectElement).value; draw(); }}>
                        ${repeat(signers(pki.certificates, ForACA), ca => ca.id, ca => html`
                            <option value="${ca.id}" ?selected=${ca.id === chosen?.id}>${ca.commonName} - ${profileWords[ca.profile]}, until ${day(ca.notAfter)}${ca.keyEncrypted ? ', its key with a password' : ''}</option>
                        `)}
                    </select>
                    <span class="hint">A CA of this PKI that is valid now and whose key is here.</span>
                </label>
                <label class="issuer-key-password" ?hidden=${!locked}>Password of its key
                    <input type="password" name="issuerKeyPassword" autocomplete="off" ?disabled=${!locked} ?required=${locked} />
                    <span class="hint">The key of '${chosen?.commonName ?? ''}' has a password, and signs nothing without it.</span>
                </label>
            `;

        }

        /** A password for a key, and the same again: optional, and empty for none. */
        function newPasswordFields(Hint: string, Label = 'Password of its key'): TemplateResult {
            return html`
                <div class="key-password-fields">
                    <label>${Label}
                        <input type="password" name="newPassword" minlength="${current?.minKeyPasswordLength ?? 8}" autocomplete="new-password" />
                        <span class="hint">
                            Optional; ${current?.minKeyPasswordLength ?? 8} characters at least. ${Hint}
                            The PKI keeps no password: one that is forgotten makes the key useless.
                        </span>
                    </label>
                    <label>The password again
                        <input type="password" name="newPasswordAgain" autocomplete="new-password" />
                    </label>
                </div>
            `;
        }

        /**
         * The password a form gives a key: null for none - or undefined, and
         * said beside the form, where the two typed are not the same.
         */
        function newPasswordOf(Form: HTMLFormElement, Id: string): string | null | undefined {

            const password = field(Form, 'newPassword', false);

            if (password !== field(Form, 'newPasswordAgain', false)) {
                must<HTMLElement>(content, `#${Id}-error`).textContent = 'The two passwords are not the same.';
                return undefined;
            }

            return password.length > 0 ? password : null;

        }

        /** The password of the key of the CA that signs, where the form asks for it. */
        function issuerPasswordOf(Form: HTMLFormElement): string | null {
            const password = field(Form, 'issuerKeyPassword', false);
            return password.length > 0 ? password : null;
        }

        /** What a form says where there is nothing to sign with yet. */
        function noSigner(pki: PKICertificates, ForACA: boolean): TemplateResult | null {

            if (signers(pki.certificates, ForACA).length > 0)
                return null;

            return html`
                <p class="hint">
                    There is no CA here that could sign it: none that is valid now, has its key in this PKI${ForACA ? ' and may have a CA below it' : ''}.
                    ${mayMakeCAs ? html`<button type="button" class="btn small" @click=${() => show('root-ca')}>Make a root CA</button>` : nothing}
                </p>
            `;

        }

        function formActions(Id: string, Label: string): TemplateResult {
            return html`
                <div class="form-actions">
                    <button type="submit" class="btn primary">${Label}</button>
                    <span id="${Id}-note"  class="form-notice" role="status"></span>
                    <span id="${Id}-error" class="form-error"  role="alert"></span>
                </div>
            `;
        }

        /**
         * Send what a form made, and open it in the list - or say why not
         * beside the form, which keeps what was typed.
         */
        async function make(Form:   HTMLFormElement,
                            Id:     string,
                            Doing:  () => Promise<PKICertificateDetails>,
                            Words:  (made: PKICertificateDetails) => string): Promise<void> {

            const error = must<HTMLElement>(content, `#${Id}-error`);
            error.textContent = '';

            try
            {

                const created = await whileSaving(content, must<HTMLElement>(content, `#${Id}-note`), Doing);

                Form.reset();

                delete issuerChosen[Id];

                made            = Words(created);
                openId          = created.id;
                details         = created;
                detailsProblem  = '';
                narrow          = '';
                narrowProfile   = '';

                if (Id === 'csr') {
                    csrPreview  = null;
                    csrProblem  = '';
                }

                shown = 'certificates';
                rememberTab(tabs, shown);

                await load();

            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }


        // ------------------------------------------------------------------
        // A root CA
        // ------------------------------------------------------------------

        function rootCAView(pki: PKICertificates): TemplateResult {
            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-crown"></i> New root CA</h2>

                    <p class="hint">
                        A new key, and a certificate it signs itself: what everything below it is believed through.
                        Its private key stays in this PKI and never leaves it through this page.
                    </p>

                    <form id="root-ca-form" class="form-stack" @submit=${onRootCA}>
                        ${subjectFields()}
                        ${keyField(pki, 'ecc-p384')}
                        ${validityField(pki, 3650, 'Ten years is usual for a root; nothing below it may outlive it.')}
                        ${pathLengthField('', 'How many sub-CAs may stand below it, one below the other. Empty for any number.')}
                        ${newPasswordFields('Without one, whoever can read the directory of this PKI can sign as this root.')}
                        ${formActions('root-ca', 'Make the root CA')}
                    </form>

                </section>
            `;
        }

        function onRootCA(event: SubmitEvent): void {

            event.preventDefault();

            const form         = event.currentTarget as HTMLFormElement;
            const keyPassword  = newPasswordOf(form, 'root-ca');

            if (keyPassword === undefined)
                return;

            // Read before the form is held still: a disabled field is no
            // field of the form any more.
            const request = {
                subject:       subjectOf(form),
                keyAlgorithm:  field(form, 'keyAlgorithm'),
                validDays:     numberField(form, 'validDays'),
                pathLength:    field(form, 'pathLength') === '' ? null : numberField(form, 'pathLength'),
                keyPassword
            };

            void make(form, 'root-ca', () => api.pki.rootCA(request),
                      created => `Made the root CA '${created.commonName}'.`);

        }


        // ------------------------------------------------------------------
        // A sub-CA
        // ------------------------------------------------------------------

        function subCAView(pki: PKICertificates): TemplateResult {
            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-sitemap"></i> New sub-CA</h2>

                    <p class="hint">
                        A new key, and a certificate a CA of this PKI signs for it: a CA that signs in its turn - the
                        CA of the charging stations of one operator, say, below the root of all of them.
                    </p>

                    ${noSigner(pki, true) ?? html`
                        <form id="sub-ca-form" class="form-stack" @submit=${onSubCA}>
                            ${issuerField(pki, true, 'sub-ca')}
                            ${subjectFields()}
                            ${keyField(pki, 'ecc-p384')}
                            ${validityField(pki, 1825, 'No longer than the CA that signs it.')}
                            ${pathLengthField('0', '0 lets it sign certificates for servers and clients and no CA; empty, as many as its CA allows.')}
                            ${newPasswordFields('Without one, whoever can read the directory of this PKI can sign as this sub-CA.')}
                            ${formActions('sub-ca', 'Make the sub-CA')}
                        </form>
                    `}

                </section>
            `;
        }

        function onSubCA(event: SubmitEvent): void {

            event.preventDefault();

            const form         = event.currentTarget as HTMLFormElement;
            const keyPassword  = newPasswordOf(form, 'sub-ca');

            if (keyPassword === undefined)
                return;

            const request = {
                issuer:             field(form, 'issuer'),
                issuerKeyPassword:  issuerPasswordOf(form),
                subject:            subjectOf(form),
                keyAlgorithm:       field(form, 'keyAlgorithm'),
                validDays:          numberField(form, 'validDays'),
                pathLength:         field(form, 'pathLength') === '' ? null : numberField(form, 'pathLength'),
                keyPassword
            };

            void make(form, 'sub-ca', () => api.pki.subCA(request),
                      created => `Made the sub-CA '${created.commonName}' below '${commonNameOf(created.issuerId)}'.`);

        }


        // ------------------------------------------------------------------
        // A server's or a client's certificate
        // ------------------------------------------------------------------

        function issueView(pki: PKICertificates): TemplateResult {
            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-file-signature"></i> New certificate</h2>

                    <p class="hint">
                        A new key, and a certificate for it below a CA of this PKI: for a server - a CSMS, a local
                        controller - or for a client - a charging station towards its CSMS. The key can be downloaded
                        from its details once it is made.
                    </p>

                    ${noSigner(pki, false) ?? html`
                        <form id="issue-form" class="form-stack" @submit=${onIssue}>
                            ${issuerField(pki, false, 'issue')}
                            <label>For
                                <select name="profile">
                                    <option value="server">a server (TLS server authentication)</option>
                                    <option value="client">a client (TLS client authentication)</option>
                                </select>
                            </label>
                            ${subjectFields()}
                            <label>Other names
                                <textarea name="names" rows="3" spellcheck="false" autocomplete="off" placeholder="csms.example.org&#10;192.168.1.10"></textarea>
                                <span class="hint">
                                    Host names, IP addresses, mail addresses or URIs, one per line. A server certificate
                                    without any gets its common name, where that reads as a host name.
                                </span>
                            </label>
                            ${keyField(pki, 'ecc-p256')}
                            ${validityField(pki, 365, 'No longer than the CA that signs it.')}
                            ${newPasswordFields('With one, the key is downloaded encrypted, and whatever opens it asks for it.')}
                            ${formActions('issue', 'Make the certificate')}
                        </form>
                    `}

                </section>
            `;
        }

        function onIssue(event: SubmitEvent): void {

            event.preventDefault();

            const form         = event.currentTarget as HTMLFormElement;
            const keyPassword  = newPasswordOf(form, 'issue');

            if (keyPassword === undefined)
                return;

            const request = {
                issuer:                   field(form, 'issuer'),
                issuerKeyPassword:        issuerPasswordOf(form),
                keyPassword,
                profile:                  field(form, 'profile') as 'server' | 'client',
                subject:                  subjectOf(form),
                keyAlgorithm:             field(form, 'keyAlgorithm'),
                validDays:                numberField(form, 'validDays'),
                subjectAlternativeNames:  namesIn(field(form, 'names', false))
            };

            void make(form, 'issue', () => api.pki.issue(request),
                      created => `Made the ${profileWords[created.profile]} certificate '${created.commonName}' below '${commonNameOf(created.issuerId)}'.`);

        }


        // ------------------------------------------------------------------
        // A CSR
        // ------------------------------------------------------------------

        function csrView(pki: PKICertificates): TemplateResult {
            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-file-import"></i> Sign a CSR</h2>

                    <p class="hint">
                        A certificate below a CA of this PKI for the key of a certificate signing request - a charging
                        station's, which wants a new client certificate for its CSMS. Who it is about is what the CSR
                        says; what it may be used for is what is chosen here, whatever the CSR asked for.
                    </p>

                    ${noSigner(pki, false) ?? html`
                        <form id="csr-form" class="form-stack" @submit=${onCSR}>

                            ${issuerField(pki, false, 'csr')}

                            <label>Sign it as
                                <select name="profile">
                                    ${maySign ? html`
                                        <option value="client">a client certificate</option>
                                        <option value="server">a server certificate</option>` : nothing}
                                    ${mayMakeCAs ? html`<option value="subCA">a sub-CA, whose key is somewhere else</option>` : nothing}
                                </select>
                            </label>

                            <label>CSR
                                ${pemBox({
                                    id:           'csr-text',
                                    name:         'csr',
                                    rows:         8,
                                    placeholder:  '-----BEGIN CERTIFICATE REQUEST-----',
                                    accept:       '.csr,.req,.pem,.txt',
                                    onFiles:      async (files, box) => {
                                                      for (const file of files)
                                                          appendText(box, await file.text());
                                                  },
                                    onChanged:    box => inspectSoon(box.value)
                                })}
                            </label>

                            ${csrPreviewView()}

                            <label class="checkbox">
                                <input type="checkbox" name="takeNames" checked />
                                Take over the other names the CSR asks for
                            </label>

                            <label>Other names besides
                                <textarea name="names" rows="2" spellcheck="false" autocomplete="off"></textarea>
                                <span class="hint">Host names, IP addresses, mail addresses or URIs, one per line.</span>
                            </label>

                            ${validityField(pki, 365, 'No longer than the CA that signs it.')}
                            ${mayMakeCAs ? pathLengthField('0', 'For a sub-CA only: how many CAs may stand below it.') : nothing}

                            ${formActions('csr', 'Sign it')}

                        </form>
                    `}

                </section>
            `;
        }

        function csrPreviewView(): TemplateResult | typeof nothing {

            if (csrProblem.length > 0)
                return html`<div class="form-error" id="csr-problem">${csrProblem}</div>`;

            if (csrPreview === null)
                return nothing;

            const csr = csrPreview;

            return html`
                <div class="csr-preview" id="csr-preview">
                    <div class="kv"><span class="k">Subject</span><span class="v"><code>${csr.subject}</code></span></div>
                    <div class="kv"><span class="k">Key</span><span class="v">
                        ${keyName(csr.keyAlgorithm)}
                        ${csr.keySupported ? nothing : html`<span class="chip warn">not signed here</span>`}
                    </span></div>
                    <div class="kv"><span class="k">Other names</span><span class="v">
                        ${csr.subjectAlternativeNames.length > 0 ? csr.subjectAlternativeNames.map(name => html`<code>${name}</code> `) : html`<span class="muted">none</span>`}
                    </span></div>
                    <div class="kv"><span class="k">Signature</span><span class="v">
                        ${csr.signatureValid ? html`<span class="chip ok">holds</span>` : html`<span class="chip warn">does not hold - it will not be signed</span>`}
                    </span></div>
                </div>
            `;

        }

        /** Ask the PKI what the CSR in the box says, once typing has paused. */
        function inspectSoon(Text: string): void {

            clearTimeout(csrTimer);

            csrTimer = setTimeout(() => void inspect(Text), 400);

        }

        async function inspect(Text: string): Promise<void> {

            if (Text.trim().length === 0) {
                csrPreview = null;
                csrProblem = '';
                draw();
                return;
            }

            try
            {
                const inspection = await api.pki.inspectCSR(Text);
                if (cancelled)
                    return;
                csrPreview = inspection;
                csrProblem = '';
            }
            catch (problem)
            {
                if (cancelled)
                    return;
                csrPreview = null;
                csrProblem = errorMessage(problem);
            }

            draw();

        }

        function onCSR(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            const request = {
                issuer:                       field(form, 'issuer'),
                issuerKeyPassword:            issuerPasswordOf(form),
                profile:                      field(form, 'profile') as 'subCA' | 'server' | 'client',
                csr:                          field(form, 'csr'),
                validDays:                    numberField(form, 'validDays'),
                subjectAlternativeNames:      namesIn(field(form, 'names', false)),
                takeSubjectAlternativeNames:  isChecked(form, 'takeNames'),
                pathLength:                   field(form, 'pathLength') === '' ? null : numberField(form, 'pathLength')
            };

            void make(form, 'csr', () => api.pki.signCSR(request),
                      created => `Signed the CSR of '${created.commonName}' as a ${profileWords[created.profile]} below '${commonNameOf(created.issuerId)}'.`);

        }


        // ------------------------------------------------------------------
        // The transparency log
        // ------------------------------------------------------------------

        /** Where a monitor reads the log: the base RFC 6962 puts "/ct/v1/get-sth" and the rest below. */
        function logAddress(): string {
            return new URL(apiURL('/pki/transparency'), location.href).href;
        }

        function transparencyView(): TemplateResult {

            if (logProblem.length > 0)
                return html`<div class="error-box">${logProblem}</div>`;

            if (log === null)
                return html`<div class="loading">Loading ...</div>`;

            const theLog  = log;
            const first   = logEntries.length > 0 ? logEntries[logEntries.length - 1]!.index : 0;

            return html`
                <section class="card" id="pki-transparency">

                    <h2><i class="fa-solid fa-scroll"></i> Transparency log</h2>

                    <p class="hint">
                        Every certificate this PKI signed, in the order it signed them, in a Merkle tree whose head
                        the log signs - as RFC 6962 has a certificate transparency log do it. Nothing is ever taken
                        out of it: a certificate deleted from the PKI stays in its log. A monitor reads it at the
                        address below, signed in with an API key of an account that may look at the certificates.
                    </p>

                    ${theLog.broken ? html`
                        <div class="error-box" id="pki-transparency-broken">
                            The log is broken, and the PKI signs nothing until it is repaired: ${theLog.problems.join(' ')}
                        </div>` : theLog.problems.length > 0 ? html`
                        <div class="notice">${theLog.problems.join(' ')}</div>` : nothing}

                    <div class="kv"><span class="k">Address</span><span class="v"><code id="pki-transparency-address">${logAddress()}</code></span></div>
                    <div class="kv"><span class="k">Log ID</span><span class="v fingerprint">${theLog.logId}</span></div>
                    <div class="kv"><span class="k">Certificates</span><span class="v">${theLog.treeSize}</span></div>
                    ${theLog.sth !== null ? html`
                        <div class="kv"><span class="k">Newest tree head</span><span class="v">
                            ${theLog.sth.tree_size} certificate(s), signed ${theLog.signedAt !== null ? moment(theLog.signedAt) : ''}
                        </span></div>
                        <div class="kv"><span class="k">Root hash</span><span class="v fingerprint">${theLog.sth.sha256_root_hash}</span></div>` : nothing}

                    <div class="pki-actions">
                        <button type="button" class="btn small" id="pki-transparency-copy-address"
                                @click=${(event: Event) => void copyLog(event.currentTarget as HTMLButtonElement, logAddress())}>
                            <i class="fa-solid fa-copy"></i> Copy the address
                        </button>
                        <button type="button" class="btn small" id="pki-transparency-download-key"
                                @click=${() => download('transparency-log.pub.pem', theLog.publicKey)}>
                            <i class="fa-solid fa-download"></i> Public key
                        </button>
                        <span class="form-notice" role="status" id="pki-transparency-note"></span>
                    </div>

                    ${logEntries.length === 0
                          ? html`<p class="hint">The log has no certificate yet.</p>`
                          : html`
                              <div class="table-scroll">
                                <table class="records pki-log">
                                    <thead><tr><th>#</th><th>Logged</th><th>Profile</th><th>Common name</th><th>In the PKI</th></tr></thead>
                                    <tbody>
                                        ${repeat(logEntries, entry => entry.index, entry => html`
                                            <tr data-index="${entry.index}" class="${entry.inPKI ? 'clickable' : ''}"
                                                @click=${() => { if (entry.inPKI) { show('certificates'); void open(entry.id); } }}>
                                                <td>${entry.index}</td>
                                                <td>${moment(entry.loggedAt)}</td>
                                                <td><span class="chip">${entry.ocspResponder ? 'OCSP responder' : profileWords[entry.profile]}</span></td>
                                                <td class="common-name">${entry.commonName}</td>
                                                <td>${entry.ocspResponder
                                                          ? html`<span class="muted">beside its CA</span>`
                                                          : entry.inPKI ? html`<span class="chip ok">yes</span>` : html`<span class="chip warn">deleted</span>`}
                                                    ${entry.revoked ? html`<span class="chip bad">revoked</span>` : nothing}</td>
                                            </tr>
                                        `)}
                                    </tbody>
                                </table>
                              </div>
                              ${first > 0 ? html`
                                  <button type="button" class="btn small" id="pki-transparency-older" @click=${() => { logShown += logPage; void loadLog(); }}>
                                      Show older
                                  </button>` : nothing}
                          `}

                </section>
            `;

        }

        async function copyLog(Button: HTMLButtonElement, Text: string): Promise<void> {
            must<HTMLElement>(content, '#pki-transparency-note').textContent = await copyText(Text);
            Button.blur();
        }

        /** The log, and its newest entries - as many as are shown - the newest first. */
        async function loadLog(): Promise<void> {

            try
            {

                const loaded  = await api.pki.transparency();
                const start   = Math.max(0, loaded.treeSize - logShown);
                const listed  = loaded.treeSize > 0 ? (await api.pki.logEntries(start, loaded.treeSize - 1)).entries : [];

                if (cancelled)
                    return;

                log         = loaded;
                logEntries  = [ ...listed ].reverse();
                logProblem  = '';

            }
            catch (problem)
            {
                if (cancelled)
                    return;
                logProblem = `The transparency log could not be loaded: ${errorMessage(problem)}`;
            }

            draw();

        }


        // ------------------------------------------------------------------
        // Revocation
        // ------------------------------------------------------------------

        function revocationView(): TemplateResult {

            if (revocationProblem.length > 0)
                return html`<div class="error-box">${revocationProblem}</div>`;

            if (revocation === null)
                return html`<div class="loading">Loading ...</div>`;

            const overview = revocation;

            return html`
                <section class="card" id="pki-revocation">

                    <h2><i class="fa-solid fa-ban"></i> Revocation</h2>

                    <p class="hint">
                        Whoever checks a certificate of this PKI asks whether it was revoked: in the CRL of its CA, or of the
                        OCSP responder - both open to everybody, without signing in. A certificate made below a CA names
                        where they are, once the PKI is told the address it is reached at from outside.
                    </p>

                    <form id="public-url-form" class="form-stack" @submit=${onPublicURL}>
                        <label>The address the PKI is reached at
                            <input name="publicURL" type="url" placeholder="http://pki.example.org" .value=${overview.publicURL ?? ''} ?disabled=${!mayMakeCAs} />
                            <span class="hint">
                                http rather than https serves most of whoever checks: a CRL and an OCSP response are signed. Empty for none -
                                then certificates name no CRL and no responder. What is made already keeps what it names.
                            </span>
                        </label>
                        ${mayMakeCAs ? formActions('public-url', 'Save the address') : nothing}
                    </form>

                    ${overview.ocspURL !== null ? html`
                        <div class="kv"><span class="k">OCSP responder</span><span class="v"><code id="pki-ocsp-url">${overview.ocspURL}</code></span></div>
                        <div class="kv"><span class="k">CRL of a CA</span><span class="v"><code>${overview.crlURL}</code></span></div>` : html`
                        <div class="notice" id="pki-no-public-url">Certificates made now name no CRL and no OCSP responder: the PKI was told no address it is reached at.</div>`}

                    <h3>The CAs</h3>

                    ${overview.cas.length === 0 ? html`<p class="hint">This PKI has no CA yet.</p>` : html`
                        <div class="table-scroll">
                            <table class="records pki-revocation-cas">
                                <thead><tr><th>CA</th><th>CRL</th><th>In it</th><th>Until</th><th>OCSP responder until</th><th>Signed anew</th></tr></thead>
                                <tbody>
                                    ${repeat(overview.cas, ca => ca.id, ca => html`
                                        <tr data-id="${ca.id}" class="clickable" @click=${() => { show('certificates'); void open(ca.id); }}>
                                            <td class="common-name">${ca.commonName} <span class="chip">${profileWords[ca.profile]}</span></td>
                                            <td>${ca.crl ? `#${ca.crl.number}` : html`<span class="chip warn">none</span>`}</td>
                                            <td>${ca.crl?.entries ?? ''}</td>
                                            <td>${ca.crl?.nextUpdate ? moment(ca.crl.nextUpdate) : ''}</td>
                                            <td>${ca.responder ? moment(ca.responder.notAfter) : html`<span class="chip warn">none</span>`}</td>
                                            <td>${ca.automatic
                                                      ? html`<span class="chip ok">by itself</span>`
                                                      : ca.hasKey ? html`<span class="chip warn">with its password</span>` : html`<span class="muted">its key is not here</span>`}</td>
                                        </tr>
                                    `)}
                                </tbody>
                            </table>
                        </div>`}

                    <h3>Revoked</h3>

                    ${overview.revoked.length === 0 ? html`<p class="hint">Nothing was revoked.</p>` : html`
                        <div class="table-scroll">
                            <table class="records pki-revoked">
                                <thead><tr><th>Revoked</th><th>Common name</th><th>Below</th><th>Why</th><th>By</th></tr></thead>
                                <tbody>
                                    ${repeat(overview.revoked, one => one.id, one => html`
                                        <tr data-id="${one.id}" class="${one.inPKI ? 'clickable' : ''}"
                                            @click=${() => { if (one.inPKI) { show('certificates'); void open(one.id); } }}>
                                            <td>${moment(one.revokedAt)}</td>
                                            <td class="common-name">${one.commonName}${one.inPKI ? nothing : html` <span class="chip warn">deleted</span>`}</td>
                                            <td>${one.issuer ?? ''}</td>
                                            <td>${reasonWords[one.reason]}</td>
                                            <td>${one.revokedBy ?? ''}</td>
                                        </tr>
                                    `)}
                                </tbody>
                            </table>
                        </div>`}

                </section>
            `;

        }

        async function onPublicURL(event: SubmitEvent): Promise<void> {

            event.preventDefault();

            const form   = event.currentTarget as HTMLFormElement;
            const error  = must<HTMLElement>(content, '#public-url-error');
            const url    = field(form, 'publicURL');

            error.textContent = '';

            try
            {
                revocation = await whileSaving(content, must<HTMLElement>(content, '#public-url-note'),
                                               () => api.pki.setPublicURL(url.length > 0 ? url : null));
                draw();
                must<HTMLElement>(content, '#public-url-note').textContent = 'Saved.';
            }
            catch (problem)
            {
                error.textContent = errorMessage(problem);
            }

        }

        async function loadRevocation(): Promise<void> {

            try
            {
                const loaded = await api.pki.revocation();
                if (cancelled)
                    return;
                revocation         = loaded;
                revocationProblem  = '';
            }
            catch (problem)
            {
                if (cancelled)
                    return;
                revocationProblem = `What the PKI revoked could not be loaded: ${errorMessage(problem)}`;
            }

            draw();

        }


        // ------------------------------------------------------------------
        // Loading
        // ------------------------------------------------------------------

        async function load(): Promise<void> {

            try
            {

                const loaded = await api.pki.list();

                if (cancelled)
                    return;

                current = loaded;

                // A certificate deleted somewhere else meanwhile has no
                // details to show any more.
                if (openId !== null && !loaded.certificates.some(certificate => certificate.id === openId)) {
                    openId   = null;
                    details  = null;
                }

                draw();

                if (shown === 'transparency')
                    void loadLog();

                if (shown === 'revocation')
                    void loadRevocation();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The certificates of this PKI could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; clearTimeout(csrTimer); release(); };

    }

};
