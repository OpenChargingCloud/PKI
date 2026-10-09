import { nodeAPI,
         request,
         type Certificate        as NodeCertificate,
         type CertificateImport  as NodeCertificateImport,
         type CertificateStore   as NodeCertificateStore,
         type NodeConfiguration,
         type NodeMe,
         type NodeResource,
         type NodeStatus,
         type Operation }  from '@node/api/client';


// What every node answers - the log, name resolution, the time, the store,
// who is signed in - and how it is asked are WWCP_Node's, and every page here
// reads them from this module as before. What follows is what a PKI says of
// its own: its resources, its configuration's own sections, the kinds its
// node store keeps - and its certificates, below "/pki".
export * from '@node/api/client';


/**
 * What a role may be allowed to touch on this PKI: what every node has, and
 * its certificate authorities and what they sign.
 */
export type Resource = NodeResource | 'authorities' | 'issuance';

/** What somebody signed in to this PKI may do: an operation on a resource, written "issuance:edit". */
export type Permission = `${Resource}:${Operation}`;

/** Who is signed in to the web interface. */
export type Me = NodeMe<Resource>;

/** How the PKI is doing right now: what every node says, and nothing more yet. */
export type Status = NodeStatus;

/**
 * What the PKI is made of: every node's sections, and its own. Only the
 * shape the Configuration page relies on is named; the fields of each
 * section are rendered from whatever the PKI sends.
 */
export interface Configuration extends NodeConfiguration {
    pki:    Record<string, unknown>;
    store:  Record<string, unknown>;
}

/**
 * What a certificate in the node's own store is for: the four kinds of TLS,
 * which are what the PKI believes and shows as a node - its time servers'
 * roots, say. Not the certificates it makes: those are below.
 */
export type CertificateKind = 'tlsRoot' | 'clientRoot' | 'tlsServer' | 'tlsIdentity';

/** One certificate in the node's own store. */
export type Certificate = NodeCertificate<CertificateKind>;

/** What an import into the node's own store sends. */
export type CertificateImport = NodeCertificateImport<CertificateKind>;

/** The node's own store, grouped the way it is shown. */
export type CertificateStore = NodeCertificateStore<CertificateKind>;


/** What a certificate of the PKI is: a root, a CA below one, or a server's or a client's below either. */
export type CertificateProfile = 'rootCA' | 'subCA' | 'server' | 'client';

/** Whether a certificate holds now. */
export type CertificateStatus = 'valid' | 'expired' | 'notYetValid';

/** One certificate this PKI made, as its list shows it. */
export interface PKICertificate {
    /** Its SHA-256 fingerprint, in lower case without colons. */
    id:                       string;
    profile:                  CertificateProfile;
    commonName:               string;
    subject:                  string;
    issuer:                   string;
    /** The CA that signed it, in this PKI; null for a root. */
    issuerId:                 string | null;
    serialNumber:             string;
    notBefore:                string;
    notAfter:                 string;
    /** "ecc-p256", "rsa-2048" - or what a key of another kind is, for a CSR's. */
    keyAlgorithm:             string;
    subjectAlternativeNames:  string[];
    pathLength:               number | null;
    /** Whether this PKI made its key, and has it. */
    hasPrivateKey:            boolean;
    fromCSR:                  boolean;
    createdAt:                string;
    createdBy:                string | null;
    status:                   CertificateStatus;
}

/** One certificate, as its details show it. */
export interface PKICertificateDetails extends PKICertificate {
    pem:                    string;
    /** The certificate and the sub-CAs above it, without the root: what a server or a client presents. */
    chainPem:               string;
    /** The certificate and every CA above it, up to its root. */
    chain:                  { id: string; commonName: string; profile: CertificateProfile }[];
    /** How many it signed itself, and how many are below it all the way down. */
    issuedCount:            number;
    belowCount:             number;
    /** Whether whoever is signed in may have its key: never a CA's. */
    mayDownloadPrivateKey:  boolean;
}

/** Every certificate of the PKI, and what it makes new ones with. */
export interface PKICertificates {
    certificates:     PKICertificate[];
    total:            number;
    directory:        string;
    keyAlgorithms:    string[];
    maxValidityDays:  number;
}

/** Who a certificate is about: the common name, and what is around it where it is given. */
export interface SubjectName {
    commonName:           string;
    organization?:        string;
    organizationalUnit?:  string;
    country?:             string;
    state?:               string;
    locality?:            string;
}

/** A new root CA. A number left empty is sent as null - not said - and the PKI takes its own. */
export interface NewRootCA {
    subject:       SubjectName;
    keyAlgorithm:  string;
    validDays:     number;
    pathLength:    number | null;
}

/** A new sub-CA, below a CA of this PKI. */
export interface NewSubCA extends NewRootCA {
    issuer:  string;
}

/** A new certificate for a server or a client, with a key made by the PKI. */
export interface NewCertificate {
    issuer:                   string;
    profile:                  'server' | 'client';
    subject:                  SubjectName;
    keyAlgorithm:             string;
    validDays:                number;
    subjectAlternativeNames:  string[];
}

/** A certificate for the key of a CSR. */
export interface CSRSigning {
    issuer:                       string;
    profile:                      'subCA' | 'server' | 'client';
    csr:                          string;
    validDays:                    number;
    subjectAlternativeNames:      string[];
    takeSubjectAlternativeNames:  boolean;
    pathLength:                   number | null;
}

/** What a CSR says, before anything is signed. */
export interface CSRInspection {
    subject:                  string;
    commonName:               string | null;
    keyAlgorithm:             string;
    keySupported:             boolean;
    subjectAlternativeNames:  string[];
    signatureValid:           boolean;
}

/** What a deletion took with it. */
export interface PKIDeleted {
    deleted:  string[];
    warning:  string | null;
}


const pki = (id: string) => `/pki/certificates/${encodeURIComponent(id)}`;

/** How the PKI is asked: the routes every node has, typed with the PKI's own of them, and its certificates. */
export const api = {

    ...nodeAPI<{ me: Me; status: Status; configuration: Configuration; kind: CertificateKind; store: CertificateStore }>(),

    pki: {
        list:        ()                                => request<PKICertificates>       ('GET',    '/pki/certificates'),
        get:         (id: string)                      => request<PKICertificateDetails> ('GET',    pki(id)),
        privateKey:  (id: string)                      => request<{ id: string; privateKey: string }>('GET', `${pki(id)}/key`),
        remove:      (id: string, withIssued: boolean) => request<PKIDeleted>            ('DELETE', `${pki(id)}${withIssued ? '?withIssued=true' : ''}`),
        rootCA:      (ca: NewRootCA)                   => request<PKICertificateDetails> ('POST',   '/pki/rootCAs',      ca),
        subCA:       (ca: NewSubCA)                    => request<PKICertificateDetails> ('POST',   '/pki/subCAs',       ca),
        issue:       (certificate: NewCertificate)     => request<PKICertificateDetails> ('POST',   '/pki/certificates', certificate),
        signCSR:     (signing: CSRSigning)             => request<PKICertificateDetails> ('POST',   '/pki/csr',          signing),
        inspectCSR:  (csr: string)                     => request<CSRInspection>         ('POST',   '/pki/csr/inspect',  { csr })
    }

};
