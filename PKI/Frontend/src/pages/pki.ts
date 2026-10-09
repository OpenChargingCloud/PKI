import { api,
         type CertificateProfile,
         type CSRInspection,
         type PKICertificate,
         type PKICertificateDetails,
         type PKICertificates,
         type SubjectName }  from '../api/client';
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
            { id: 'csr',           label: 'Sign a CSR',       icon: 'fa-file-import'    }
        ];

        const tabs = allTabs.filter(tab => tab.id === 'certificates'
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

        /** What the CSR in its box says, once the PKI has been asked. */
        let csrPreview:     CSRInspection | null           = null;
        let csrProblem                                     = '';
        let csrTimer:       ReturnType<typeof setTimeout> | undefined;


        /** Show another tab, and keep it in the address. */
        function show(id: string): void {
            shown = id;
            rememberTab(tabs, id);
            draw();
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
                                                                ? html`<i class="fa-solid fa-key" title="Its private key is in this PKI"></i>`
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
                    <div class="kv"><span class="k">Key</span><span class="v">${keyName(certificate.keyAlgorithm)}${certificate.hasPrivateKey ? ', its private key in this PKI' : ''}</span></div>
                    ${certificate.subjectAlternativeNames.length > 0 ? html`
                        <div class="kv"><span class="k">Other names</span><span class="v">${certificate.subjectAlternativeNames.map(name => html`<code>${name}</code> `)}</span></div>` : nothing}
                    ${isCA ? html`
                        <div class="kv"><span class="k">Path length</span><span class="v">${certificate.pathLength ?? html`<span class="muted">none - any number of sub-CAs below it</span>`}</span></div>
                        <div class="kv"><span class="k">Signed</span><span class="v">${certificate.issuedCount} certificate(s), ${certificate.belowCount} below it in all</span></div>` : nothing}
                    <div class="kv"><span class="k">Serial number</span><span class="v"><code>${certificate.serialNumber}</code></span></div>
                    <div class="kv"><span class="k">SHA-256</span><span class="v fingerprint">${inPairs(certificate.id)}</span></div>
                    <div class="kv"><span class="k">Made</span><span class="v">${moment(certificate.createdAt)}${certificate.createdBy !== null ? ` by ${certificate.createdBy}` : ''}</span></div>

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
                        ${mayDelete ? html`
                            <button type="button" class="btn small danger" id="pki-delete" @click=${() => void remove(certificate)}>
                                <i class="fa-solid fa-trash"></i> Delete
                            </button>` : nothing}
                        <span class="form-notice" role="status" id="pki-details-note"></span>
                        <span class="form-error"  role="alert"  id="pki-details-error"></span>
                    </div>

                    <pre class="pem">${certificate.pem}</pre>

                </section>
            `;

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

        function issuerField(pki: PKICertificates, ForACA: boolean): TemplateResult {
            return html`
                <label>Signed by
                    <select name="issuer" required>
                        ${repeat(signers(pki.certificates, ForACA), ca => ca.id, ca => html`
                            <option value="${ca.id}">${ca.commonName} - ${profileWords[ca.profile]}, until ${day(ca.notAfter)}</option>
                        `)}
                    </select>
                    <span class="hint">A CA of this PKI that is valid now and whose key is here.</span>
                </label>
            `;
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
                        ${formActions('root-ca', 'Make the root CA')}
                    </form>

                </section>
            `;
        }

        function onRootCA(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            // Read before the form is held still: a disabled field is no
            // field of the form any more.
            const request = {
                subject:       subjectOf(form),
                keyAlgorithm:  field(form, 'keyAlgorithm'),
                validDays:     numberField(form, 'validDays'),
                pathLength:    field(form, 'pathLength') === '' ? null : numberField(form, 'pathLength')
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
                            ${issuerField(pki, true)}
                            ${subjectFields()}
                            ${keyField(pki, 'ecc-p384')}
                            ${validityField(pki, 1825, 'No longer than the CA that signs it.')}
                            ${pathLengthField('0', '0 lets it sign certificates for servers and clients and no CA; empty, as many as its CA allows.')}
                            ${formActions('sub-ca', 'Make the sub-CA')}
                        </form>
                    `}

                </section>
            `;
        }

        function onSubCA(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            const request = {
                issuer:        field(form, 'issuer'),
                subject:       subjectOf(form),
                keyAlgorithm:  field(form, 'keyAlgorithm'),
                validDays:     numberField(form, 'validDays'),
                pathLength:    field(form, 'pathLength') === '' ? null : numberField(form, 'pathLength')
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
                            ${issuerField(pki, false)}
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
                            ${formActions('issue', 'Make the certificate')}
                        </form>
                    `}

                </section>
            `;
        }

        function onIssue(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            const request = {
                issuer:                   field(form, 'issuer'),
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

                            ${issuerField(pki, false)}

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
