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
 * roots, say - and the identity its web interface shows over HTTPS. Not the
 * certificates it makes: those are below.
 */
export type CertificateKind = 'tlsRoot' | 'clientRoot' | 'tlsServer' | 'tlsIdentity' | 'tlsServerIdentity';

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
    /** Whether that key has a password - which the PKI keeps nowhere. */
    keyEncrypted:             boolean;
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
    /** Where it is in the transparency log of the PKI; null where the log does not have it. */
    transparency:           CertificateInTheLog | null;
}

/** A signed certificate timestamp, as RFC 6962 writes one: the log's id and signature in Base64. */
export interface SignedCertificateTimestamp {
    sct_version:  number;
    id:           string;
    timestamp:    number;
    extensions:   string;
    signature:    string;
}

/** Where a certificate is in the transparency log, since when, and the log's word for it. */
export interface CertificateInTheLog {
    index:     number;
    loggedAt:  string;
    sct:       SignedCertificateTimestamp;
}

/** A signed tree head, as get-sth of RFC 6962 answers it. */
export interface SignedTreeHead {
    tree_size:            number;
    timestamp:            number;
    sha256_root_hash:     string;
    tree_head_signature:  string;
}

/** The transparency log of the PKI: who it is, how big, its newest tree head - and what is wrong with it. */
export interface TransparencyLog {
    logId:              string;
    publicKey:          string;
    treeSize:           number;
    /** None where the log is broken: it signs nothing then. */
    sth:                SignedTreeHead | null;
    signedAt:           string | null;
    maximumMergeDelay:  number;
    broken:             boolean;
    problems:           string[];
    directory:          string;
}

/** One entry of the log, as its list shows it - read from the certificate, which the PKI may not have any more. */
export interface LogEntry {
    index:       number;
    timestamp:   number;
    loggedAt:    string;
    id:          string;
    commonName:  string;
    subject:     string;
    issuer:      string;
    profile:     CertificateProfile;
    notAfter:    string;
    /** Whether the PKI still has it: a deleted one stays in the log. */
    inPKI:       boolean;
}

/** Every certificate of the PKI, and what it makes new ones with. */
export interface PKICertificates {
    certificates:     PKICertificate[];
    total:            number;
    directory:        string;
    keyAlgorithms:         string[];
    maxValidityDays:       number;
    /** The shortest password a key may be given; none at all is fine too. */
    minKeyPasswordLength:  number;
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

/**
 * A new root CA. A number left empty is sent as null - not said - and the PKI
 * takes its own; a password left empty, as none: the key is kept unencrypted.
 */
export interface NewRootCA {
    subject:       SubjectName;
    keyAlgorithm:  string;
    validDays:     number;
    pathLength:    number | null;
    keyPassword:   string | null;
}

/** A new sub-CA, below a CA of this PKI - with the password of that CA's key, where it has one. */
export interface NewSubCA extends NewRootCA {
    issuer:             string;
    issuerKeyPassword:  string | null;
}

/** A new certificate for a server or a client, with a key made by the PKI. */
export interface NewCertificate {
    issuer:                   string;
    issuerKeyPassword:        string | null;
    keyPassword:              string | null;
    profile:                  'server' | 'client';
    subject:                  SubjectName;
    keyAlgorithm:             string;
    validDays:                number;
    subjectAlternativeNames:  string[];
}

/** A certificate for the key of a CSR. */
export interface CSRSigning {
    issuer:                       string;
    issuerKeyPassword:            string | null;
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
        privateKey:  (id: string)                      => request<{ id: string; privateKey: string; encrypted: boolean }>('GET', `${pki(id)}/key`),
        keyPassword: (id: string, password: string | null, newPassword: string | null) =>
                                                          request<PKICertificateDetails> ('POST',   `${pki(id)}/key/password`, { password, newPassword }),
        remove:      (id: string, withIssued: boolean) => request<PKIDeleted>            ('DELETE', `${pki(id)}${withIssued ? '?withIssued=true' : ''}`),
        rootCA:      (ca: NewRootCA)                   => request<PKICertificateDetails> ('POST',   '/pki/rootCAs',      ca),
        subCA:       (ca: NewSubCA)                    => request<PKICertificateDetails> ('POST',   '/pki/subCAs',       ca),
        issue:       (certificate: NewCertificate)     => request<PKICertificateDetails> ('POST',   '/pki/certificates', certificate),
        signCSR:     (signing: CSRSigning)             => request<PKICertificateDetails> ('POST',   '/pki/csr',          signing),
        inspectCSR:  (csr: string)                     => request<CSRInspection>         ('POST',   '/pki/csr/inspect',  { csr }),
        transparency: ()                               => request<TransparencyLog>       ('GET',    '/pki/transparency'),
        logEntries:  (start: number, end: number)      => request<{ treeSize: number; entries: LogEntry[] }>('GET', `/pki/transparency/entries?start=${start}&end=${end}`)
    }

};
