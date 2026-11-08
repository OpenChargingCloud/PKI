/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of PKI <https://github.com/OpenChargingCloud/PKI>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.PKI.Revocation;

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// What the store says of the certificates it revoked: a CRL per CA, and
    /// an OCSP responder per CA that answers for every certificate below it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In "revocation" beside the certificates: "revoked.json", every
    /// certificate revoked - kept after the certificate is deleted, since it
    /// is still revoked out there - and per CA "&lt;id&gt;.crl", its newest
    /// CRL as DER, and "&lt;id&gt;.ocsp.crt" and "&lt;id&gt;.ocsp.key", its
    /// OCSP responder.
    /// </para>
    /// <para>
    /// A CRL is signed with the key of its CA. Where that key has no
    /// password, the PKI signs it anew by itself, for <see cref="CRLValidity"/>
    /// at a time, before half of that is over. Where it has one, the CRL is
    /// signed whenever the password is given - when the CA signs a
    /// certificate, revokes one, or its CRL is signed by hand - for
    /// <see cref="CRLValidityWithPassword"/>, or as long as is asked.
    /// </para>
    /// <para>
    /// An OCSP response is signed by a responder of the CA's - RFC 6960,
    /// section 4.2.2.2 - and never with the CA's own key: a certificate the
    /// CA signed for the purpose, with the extended key usage of OCSP
    /// signing and "id-pkix-ocsp-nocheck", whose key has no password, so that
    /// it answers at any hour whatever the CA's key has. It is made, and made
    /// anew <see cref="ResponderRenewal"/> before it runs out, wherever the
    /// CA's key is opened for something else, and is in the transparency log
    /// as everything the PKI signs is. Whoever can read the directory can
    /// answer for the CA - and nothing more: the responder signs no
    /// certificate and no CRL.
    /// </para>
    /// <para>
    /// The responder answers "good" for a certificate the CA signed - in the
    /// store or deleted from it, which is not revoking it - "revoked" for one
    /// it revoked, and "unknown" for a serial number it never signed: what
    /// the transparency log has is what it knows was signed.
    /// </para>
    /// </remarks>
    public sealed partial class PKIStore
    {

        #region Data

        /// <summary>
        /// The name of the directory of the CRLs and the OCSP responders,
        /// beside the certificates.
        /// </summary>
        public const   String    RevocationDirectoryName  = "revocation";

        /// <summary>
        /// The name of the list of the certificates revoked.
        /// </summary>
        public const   String    RevokedFileName          = "revoked.json";

        /// <summary>
        /// For how long a CRL the PKI signs by itself is to be believed - a
        /// CA whose key has no password.
        /// </summary>
        public static readonly TimeSpan  CRLValidity              = TimeSpan.FromDays(7);

        /// <summary>
        /// For how long a CRL of a CA whose key has a password is to be
        /// believed, unless another time is asked: it is signed only where
        /// somebody gives the password.
        /// </summary>
        public static readonly TimeSpan  CRLValidityWithPassword  = TimeSpan.FromDays(30);

        /// <summary>
        /// The longest a CRL signed by hand may be believed.
        /// </summary>
        public const   Int32     MaxCRLValidityDays       = 365;

        /// <summary>
        /// For how long the certificate of an OCSP responder holds - no longer
        /// than its CA.
        /// </summary>
        public static readonly TimeSpan  ResponderValidity        = TimeSpan.FromDays(365);

        /// <summary>
        /// How long before it runs out a responder is made anew.
        /// </summary>
        public static readonly TimeSpan  ResponderRenewal         = TimeSpan.FromDays(90);

        /// <summary>
        /// For how long an OCSP response is to be believed: what a client may
        /// keep it for.
        /// </summary>
        public static readonly TimeSpan  OCSPValidity             = TimeSpan.FromHours(24);

        /// <summary>
        /// How long the same answer to the same question - without a nonce -
        /// is given again rather than signed anew.
        /// </summary>
        public static readonly TimeSpan  OCSPReuse                = TimeSpan.FromMinutes(10);

        /// <summary>
        /// How long before a CRL or a responder of a CA with a password runs
        /// out it is said in the log, every time the PKI looks.
        /// </summary>
        public static readonly TimeSpan  RevocationWarning        = TimeSpan.FromDays(3);

        private readonly Dictionary<String, RevokedCertificate>                                 revoked         = new (StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, (X509Certificate2 Certificate, AsymmetricAlgorithm Key)>  responders  = new (StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, (Byte[] NameHash, Byte[] KeyHash)>                  caHashes        = new (StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, (Byte[] Response, DateTimeOffset ProducedAt)>       ocspAnswers     = new (StringComparer.Ordinal);
        private readonly Dictionary<String, HashSet<String>>                                    loggedSerials   = new (StringComparer.OrdinalIgnoreCase);
        private          Int64                                                                  indexedEntries;

        #endregion

        #region Properties

        /// <summary>
        /// Where the CRLs, the OCSP responders and the list of revocations are.
        /// </summary>
        public String                RevocationDirectory
            => Path.Combine(Directory, RevocationDirectoryName);

        /// <summary>
        /// Where whoever checks a certificate finds its CRL and the OCSP
        /// responder - written into every certificate made below a CA from now
        /// on; null to write none.
        /// </summary>
        public RevocationAddresses?  Addresses   { get; set; }

        /// <summary>
        /// What went wrong around revocation that did not stop what was asked -
        /// a CRL that could not be written after a certificate was revoked, say
        /// - for the log.
        /// </summary>
        public Action<String>?       OnWarning   { get; set; }

        #endregion


        #region Reading

        /// <summary>
        /// Every certificate revoked, the latest first - deleted from the store
        /// or not.
        /// </summary>
        public IReadOnlyList<RevokedCertificate> Revoked()
        {
            lock (gate)
                return revoked.Values.OrderByDescending(one => one.RevokedAt).ToList();
        }

        /// <summary>
        /// The revocation of a certificate, or null where it was not revoked.
        /// </summary>
        public RevokedCertificate? RevocationOf(String Id)
        {
            lock (gate)
                return revoked.TryGetValue(Normalized(Id), out var revocation) ? revocation : null;
        }

        /// <summary>
        /// The newest CRL of a CA, as DER - or null where it has none yet.
        /// </summary>
        public Byte[]? CRL(String CAId)
        {

            var file = CRLFile(Normalized(CAId));

            lock (gate)
                return File.Exists(file) ? File.ReadAllBytes(file) : null;

        }

        /// <summary>
        /// What the newest CRL of a CA says of itself, or null where it has none.
        /// </summary>
        public CRLInfo? CRLInfoOf(String CAId)

            => CRL(CAId) is Byte[] crl
                   ? CRLInfo.TryRead(crl)
                   : null;

        /// <summary>
        /// The certificate of the OCSP responder of a CA, or null where it has
        /// none yet.
        /// </summary>
        public X509Certificate2? ResponderOf(String CAId)
        {

            var file = ResponderFile(Normalized(CAId));

            lock (gate)
            {
                try
                {
                    return File.Exists(file) ? X509Certificate2.CreateFromPem(File.ReadAllText(file)) : null;
                }
                catch (CryptographicException)
                {
                    return null;
                }
            }

        }

        #endregion

        #region TryRevoke(Id, Reason, IssuerKeyPassword, RevokedBy, out Certificate, out Error, out Warning, out NotFound, out NotSaved)

        /// <summary>
        /// Revoke a certificate for good: it is in the CRL of its CA from now
        /// on, signed anew at once, and its CA's responder says "revoked".
        /// </summary>
        /// <remarks>
        /// A root CA is not revoked: no CA above it signs a CRL it is in, and
        /// a root is believed no more by being taken out of every trust store.
        /// The CRL is signed with the key of the CA, so a CA whose key has a
        /// password revokes nothing without it - a revocation its CRL does not
        /// say would be one half of what it claims. A CA whose key is not
        /// here revokes all the same, with a warning: its responder, where it
        /// has one, still says so.
        /// </remarks>
        /// <param name="Id">The certificate.</param>
        /// <param name="Reason">Why - RFC 5280, section 5.3.1.</param>
        /// <param name="IssuerKeyPassword">The password of the key of its CA, where that has one.</param>
        /// <param name="RevokedBy">Who asked.</param>
        public Boolean TryRevoke(String                                        Id,
                                 X509RevocationReason                          Reason,
                                 String?                                       IssuerKeyPassword,
                                 String?                                       RevokedBy,
                                 [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                 [NotNullWhen(false)] out String?              Error,
                                 out String?                                   Warning,
                                 out Boolean                                   NotFound,
                                 out Boolean                                   NotSaved)
        {

            Certificate  = null;
            Error        = null;
            Warning      = null;
            NotFound     = false;
            NotSaved     = false;

            lock (gate)
            {

                var certificate = Get(Id);

                if (certificate is null)
                {
                    NotFound = true;
                    Error    = $"There is no certificate '{Id}' in this PKI.";
                    return false;
                }

                if (certificate.Profile == CertificateProfile.RootCA)
                {
                    Error = $"The root CA '{certificate.CommonName}' is not revoked: no CA above it signs a CRL it is in. " +
                             "A root is believed no more by being taken out of every trust store it is in.";
                    return false;
                }

                if (revoked.TryGetValue(certificate.Id, out var already))
                {
                    Error = $"The {certificate.Profile.InWords()} '{certificate.CommonName}' was revoked already, on {already.RevokedAt:u}.";
                    return false;
                }

                if (Reason == X509RevocationReason.CACompromise && !certificate.Profile.IsCA())
                {
                    Error = $"'caCompromise' is the reason of a CA; '{certificate.CommonName}' is a {certificate.Profile.InWords()}.";
                    return false;
                }

                if (!RevocationReasons.All.Contains(Reason))
                {
                    Error = $"A certificate is revoked for one of: {String.Join(", ", RevocationReasons.All.Select(RevocationReasons.AsText))}.";
                    return false;
                }

                var issuer = certificate.IssuerId is null ? null : Get(certificate.IssuerId);

                if (issuer is null)
                {
                    Error = $"The CA of '{certificate.CommonName}' is not in this PKI, so nothing here can say it was revoked.";
                    return false;
                }

                #region The key of the CA, which signs the CRL

                using var issuerCertificate  = Load(issuer.Id)!;
                var keyPEM                   = PrivateKeyPEM(issuer.Id);
                AsymmetricAlgorithm? issuerKey = null;

                if (keyPEM is not null &&
                    !TryLoadKey(keyPEM, issuerCertificate.PublicKey, IssuerKeyPassword, out issuerKey, out var keyError))
                {
                    Error = $"Nothing was revoked: the CRL of the {issuer.Profile.InWords()} '{issuer.CommonName}' is signed with its key, and {keyError}";
                    return false;
                }

                #endregion

                using (issuerKey)
                {

                    var revocation = new RevokedCertificate(
                                         Id:            certificate.Id,
                                         IssuerId:      issuer.Id,
                                         SerialNumber:  RevocationReasons.NormalizedSerial(certificate.SerialNumber),
                                         CommonName:    certificate.CommonName,
                                         NotAfter:      certificate.NotAfter,
                                         RevokedAt:     timeProvider.GetUtcNow(),
                                         Reason:        Reason,
                                         RevokedBy:     RevokedBy
                                     );

                    revoked[certificate.Id] = revocation;

                    if (!TryWriteRevoked(out var writeError))
                    {
                        revoked.Remove(certificate.Id);
                        NotSaved = true;
                        Error    = $"Nothing was revoked: '{RevokedFile}' could not be written - {writeError}";
                        return false;
                    }

                    var changed = certificate with {
                                      RevokedAt         = revocation.RevokedAt,
                                      RevocationReason  = RevocationReasons.AsText(Reason)
                                  };

                    certificates[certificate.Id] = changed;

                    // The list of revocations is what counts, and what the
                    // next start reads.
                    TryWriteIndex(out _);

                    ocspAnswers.Clear();

                    var problems = issuerKey is null
                                       ? [ $"The private key of the {issuer.Profile.InWords()} '{issuer.CommonName}' is not in this PKI, so its CRL does not say so - only its OCSP responder, where it has one." ]
                                       : KeepRevocationFresh(issuer, issuerCertificate, issuerKey, ForceCRL: true, Validity: null);

                    Warning     = problems.Count > 0 ? String.Join(" ", problems) : null;
                    Certificate = changed;
                    return true;

                }

            }

        }

        #endregion

        #region TrySignCRL(CAId, KeyPassword, ValidDays, out CRL, out Error, out NotFound, out NotSaved)

        /// <summary>
        /// Sign the CRL of a CA anew - and make its OCSP responder anew where
        /// it is due - with its key, opened with its password where it has one.
        /// </summary>
        /// <param name="CAId">The CA.</param>
        /// <param name="KeyPassword">The password of its key, where it has one.</param>
        /// <param name="ValidDays">For how many days the CRL is to be believed; null for what a CA of its key is given.</param>
        public Boolean TrySignCRL(String                               CAId,
                                  String?                              KeyPassword,
                                  Int32?                               ValidDays,
                                  [NotNullWhen(true)]  out CRLInfo?    CRL,
                                  [NotNullWhen(false)] out String?     Error,
                                  out Boolean                          NotFound,
                                  out Boolean                          NotSaved)
        {

            CRL       = null;
            Error     = null;
            NotFound  = false;
            NotSaved  = false;

            if (ValidDays is < 1 or > MaxCRLValidityDays)
            {
                Error = $"A CRL is believed for 1 to {MaxCRLValidityDays} days; {ValidDays} is not among them.";
                return false;
            }

            lock (gate)
            {

                var ca = Get(CAId);

                if (ca is null || !ca.Profile.IsCA())
                {
                    NotFound = true;
                    Error    = ca is null
                                   ? $"There is no CA '{CAId}' in this PKI."
                                   : $"'{ca.CommonName}' is a {ca.Profile.InWords()}, which signs no CRL.";
                    return false;
                }

                var keyPEM = PrivateKeyPEM(ca.Id);

                if (keyPEM is null)
                {
                    NotFound = true;
                    Error    = $"The private key of the {ca.Profile.InWords()} '{ca.CommonName}' is not in this PKI, so it signs no CRL here.";
                    return false;
                }

                using var caCertificate = Load(ca.Id)!;

                if (!TryLoadKey(keyPEM, caCertificate.PublicKey, KeyPassword, out var key, out var keyError))
                {
                    Error = $"The CRL of the {ca.Profile.InWords()} '{ca.CommonName}' was not signed: {keyError}";
                    return false;
                }

                using (key)
                {

                    var problems = KeepRevocationFresh(ca, caCertificate, key, ForceCRL: true,
                                                       Validity: ValidDays is Int32 days ? TimeSpan.FromDays(days) : null);

                    CRL = CRLInfoOf(ca.Id);

                    if (CRL is null || problems.Count > 0)
                    {
                        CRL       = null;
                        NotSaved  = true;
                        Error     = String.Join(" ", problems.DefaultIfEmpty("The CRL could not be read back."));
                        return false;
                    }

                    return true;

                }

            }

        }

        #endregion

        #region RefreshRevocation()

        /// <summary>
        /// Sign anew what is due of every CA whose key has no password - its
        /// CRL, its OCSP responder - and say what is due of those whose key has
        /// one, or is not here: what the PKI looks at when it starts and every
        /// hour after.
        /// </summary>
        /// <returns>What needs somebody, one sentence each - for the log.</returns>
        public IReadOnlyList<String> RefreshRevocation()
        {

            var problems = new List<String>();

            lock (gate)
            {

                var now = timeProvider.GetUtcNow();

                foreach (var ca in certificates.Values.Where(one => one.Profile.IsCA()).OrderBy(one => one.CreatedAt).ToList())
                {

                    // A CA out of its validity signs nothing, and whoever
                    // checks below it fails on its validity before its CRL.
                    if (now < ca.NotBefore || now > ca.NotAfter)
                        continue;

                    if (ca.HasPrivateKey && !ca.KeyEncrypted)
                    {

                        using var caCertificate = Load(ca.Id)!;

                        if (!TryLoadKey(PrivateKeyPEM(ca.Id)!, caCertificate.PublicKey, null, out var key, out var keyError))
                        {
                            problems.Add($"The CRL of the {ca.Profile.InWords()} '{ca.CommonName}' could not be signed: {keyError}");
                            continue;
                        }

                        using (key)
                            problems.AddRange(KeepRevocationFresh(ca, caCertificate, key, ForceCRL: false, Validity: null));

                        continue;

                    }

                    var why       = ca.HasPrivateKey
                                        ? "its key has a password - it is signed the next time the CA signs a certificate, revokes one or its CRL is signed by hand"
                                        : "its key is not in this PKI";

                    var crl       = CRLInfoOf(ca.Id);

                    if (crl is null)
                        problems.Add($"The {ca.Profile.InWords()} '{ca.CommonName}' has no CRL yet: {why}.");

                    else if (crl.NextUpdate is DateTimeOffset nextUpdate && nextUpdate - now < RevocationWarning)
                        problems.Add($"The CRL of the {ca.Profile.InWords()} '{ca.CommonName}' {(nextUpdate < now ? "ran out" : "runs out")} on {nextUpdate:u}: {why}.");

                    using var responder = ResponderOf(ca.Id);

                    if (responder is null)
                        problems.Add($"The {ca.Profile.InWords()} '{ca.CommonName}' has no OCSP responder yet: {why}.");

                    else if (responder.NotAfter.ToUniversalTime() - now.UtcDateTime < RevocationWarning)
                        problems.Add($"The OCSP responder of the {ca.Profile.InWords()} '{ca.CommonName}' {(responder.NotAfter.ToUniversalTime() < now.UtcDateTime ? "ran out" : "runs out")} on {responder.NotAfter.ToUniversalTime():u}: {why}.");

                }

            }

            return problems;

        }

        #endregion

        #region AnswerOCSP(Request)

        /// <summary>
        /// The answer to an OCSP request, as DER: signed by the responder of the
        /// CA the request asks about - or unsigned, where it cannot be answered.
        /// </summary>
        /// <remarks>
        /// One CA per request, as RFC 5019 has it: a request about certificates
        /// below several CAs is "unauthorized", as one about a CA this PKI does
        /// not have is. A CA that has no responder yet is "tryLater". The same
        /// question without a nonce is answered with the same response for
        /// <see cref="OCSPReuse"/>, so that whoever asks a thousand times makes
        /// the PKI sign once.
        /// </remarks>
        public Byte[] AnswerOCSP(ReadOnlyMemory<Byte> Request)
        {

            if (!OCSP.TryParseRequest(Request, out var request, out _))
                return OCSP.ErrorResponse(OCSPResponseStatus.MalformedRequest);

            lock (gate)
            {

                var now = timeProvider.GetUtcNow();

                #region The one CA the request asks about

                IssuedCertificate? ca = null;

                foreach (var certID in request.Certificates)
                {

                    var found = CAOf(certID);

                    if (found is null || (ca is not null && ca.Id != found.Id))
                        return OCSP.ErrorResponse(OCSPResponseStatus.Unauthorized);

                    ca = found;

                }

                #endregion

                var reuse = request.Nonce is null && request.Certificates.Count == 1
                                ? $"{ca!.Id}|{request.Certificates[0].HashAlgorithm}|{request.Certificates[0].SerialNumber}"
                                : null;

                if (reuse is not null &&
                    ocspAnswers.TryGetValue(reuse, out var answered) &&
                    now - answered.ProducedAt < OCSPReuse)
                {
                    return answered.Response;
                }

                var responder = ResponderKeyOf(ca!.Id);

                if (responder is null || now.UtcDateTime > responder.Value.Certificate.NotAfter.ToUniversalTime())
                    return OCSP.ErrorResponse(OCSPResponseStatus.TryLater);

                var signed      = SignedBy(ca.Id);
                var nextUpdate  = Min(now + OCSPValidity, new DateTimeOffset(responder.Value.Certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero));
                var responses   = new List<OCSPSingleResponse>();

                foreach (var certID in request.Certificates)
                {

                    var revocation = revoked.Values.FirstOrDefault(one => one.IssuerId == ca.Id && one.SerialNumber == certID.SerialNumber);

                    responses.Add(revocation is not null
                                      ? new OCSPSingleResponse(certID, OCSPCertStatus.Revoked, revocation.RevokedAt, revocation.Reason, now, nextUpdate)
                                      : new OCSPSingleResponse(certID,
                                                               signed.Contains(certID.SerialNumber) ? OCSPCertStatus.Good : OCSPCertStatus.Unknown,
                                                               null, null, now, nextUpdate));

                }

                var response = OCSP.Response(responses, request.Nonce, responder.Value.Certificate, responder.Value.Key,
                                             KeyAlgorithm.Of(responder.Value.Certificate.PublicKey)?.Hash ?? HashAlgorithmName.SHA256,
                                             now);

                if (reuse is not null)
                {

                    // Old answers out, so that whoever asks about every serial
                    // there is does not fill the memory.
                    foreach (var old in ocspAnswers.Where(one => now - one.Value.ProducedAt >= OCSPReuse).Select(one => one.Key).ToList())
                        ocspAnswers.Remove(old);

                    ocspAnswers[reuse] = (response, now);

                }

                return response;

            }

        }

        #endregion


        #region (private) KeepRevocationFresh(CA, CACertificate, CAKey, ForceCRL, Validity)

        /// <summary>
        /// With the key of a CA open: its CRL signed anew where that is due or
        /// asked for, and its OCSP responder made anew where that is due.
        /// Called under the lock.
        /// </summary>
        /// <returns>What could not be done, one sentence each.</returns>
        private List<String> KeepRevocationFresh(IssuedCertificate    CA,
                                                 X509Certificate2     CACertificate,
                                                 AsymmetricAlgorithm  CAKey,
                                                 Boolean              ForceCRL,
                                                 TimeSpan?            Validity)
        {

            var problems  = new List<String>();

            lock (gate)
            {

                var now       = timeProvider.GetUtcNow();

                if (now < CA.NotBefore || now > CA.NotAfter)
                {
                    problems.Add($"The {CA.Profile.InWords()} '{CA.CommonName}' is valid from {CA.NotBefore:u} until {CA.NotAfter:u}, and signs no CRL outside that.");
                    return problems;
                }

                var validity  = Validity ?? (CA.KeyEncrypted ? CRLValidityWithPassword : CRLValidity);
                var crl       = CRLInfoOf(CA.Id);

                if (ForceCRL || crl?.NextUpdate is null || crl.NextUpdate.Value - now < validity / 2)
                {
                    if (!TryWriteCRL(CA, CACertificate, CAKey, crl, now, validity, out var error))
                        problems.Add(error);
                }

                if (ResponderIsDue(CA, now) && !TryMakeResponder(CA, CACertificate, CAKey, now, out var responderError))
                    problems.Add(responderError);

            }

            return problems;

        }

        #endregion

        #region (private) TryWriteCRL(CA, CACertificate, CAKey, Current, Now, Validity, out Error)

        /// <summary>
        /// The CRL of a CA: every certificate it revoked that has not run out
        /// yet, numbered one after the one before - through a temporary file
        /// moved into place.
        /// </summary>
        private Boolean TryWriteCRL(IssuedCertificate                 CA,
                                    X509Certificate2                  CACertificate,
                                    AsymmetricAlgorithm               CAKey,
                                    CRLInfo?                          Current,
                                    DateTimeOffset                    Now,
                                    TimeSpan                          Validity,
                                    [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            var builder = new CertificateRevocationListBuilder();

            foreach (var revocation in revoked.Values.Where(one => one.IssuerId == CA.Id && one.NotAfter > Now).OrderBy(one => one.RevokedAt))
                builder.AddEntry(Convert.FromHexString(revocation.SerialNumber),
                                 revocation.RevokedAt,
                                 // RFC 5280, section 5.3.1: "unspecified"
                                 // is said by saying no reason at all.
                                 revocation.Reason == X509RevocationReason.Unspecified ? null : revocation.Reason);

            var nextUpdate  = Min(Now + Validity, CA.NotAfter);
            var file        = CRLFile(CA.Id);
            var temporary   = file + ".tmp";

            try
            {

                var crl = builder.Build(
                              CACertificate.SubjectName,
                              GeneratorFor(CAKey),
                              (Current?.Number ?? 0) + 1,
                              nextUpdate,
                              KeyAlgorithm.Of(CACertificate.PublicKey)?.Hash ?? HashAlgorithmName.SHA256,
                              X509AuthorityKeyIdentifierExtension.CreateFromCertificate(CACertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false),
                              Now
                          );

                System.IO.Directory.CreateDirectory(RevocationDirectory);
                TryDelete(temporary);
                File.WriteAllBytes(temporary, crl);
                File.Move(temporary, file, overwrite: true);

                return true;

            }
            catch (Exception e)
            {
                TryDelete(temporary);
                Error = $"The CRL of the {CA.Profile.InWords()} '{CA.CommonName}' could not be written to '{file}': {e.Message}";
                return false;
            }

        }

        #endregion

        #region (private) ResponderIsDue(CA, Now)

        /// <summary>
        /// Whether a CA needs an OCSP responder made: it has none, or one that
        /// runs out within <see cref="ResponderRenewal"/> - where a new one
        /// would outlast it, which near the end of the CA it would not.
        /// </summary>
        private Boolean ResponderIsDue(IssuedCertificate  CA,
                                       DateTimeOffset     Now)
        {

            using var responder = ResponderOf(CA.Id);

            if (responder is null)
                return true;

            var notAfter = new DateTimeOffset(responder.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            return notAfter - Now < ResponderRenewal &&
                   Min(Now + ResponderValidity, CA.NotAfter) > notAfter + TimeSpan.FromDays(1);

        }

        #endregion

        #region (private) TryMakeResponder(CA, CACertificate, CAKey, Now, out Error)

        /// <summary>
        /// A new OCSP responder of a CA: a key of the kind of the CA's, and a
        /// certificate the CA signs for it - in the transparency log before it
        /// is anywhere else, as every certificate the PKI signs.
        /// </summary>
        private Boolean TryMakeResponder(IssuedCertificate                 CA,
                                         X509Certificate2                  CACertificate,
                                         AsymmetricAlgorithm               CAKey,
                                         DateTimeOffset                    Now,
                                         [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            var algorithm  = KeyAlgorithm.Of(CACertificate.PublicKey) ?? KeyAlgorithm.ECC_P256;
            var key        = algorithm.NewKey();
            var name       = new X500DistinguishedNameBuilder();

            name.AddCommonName($"{CA.CommonName} OCSP Responder");

            var request    = NewRequest(name.Build(), new PublicKey(key), algorithm.Hash);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid(OCSP.OCSPSigningOID, "OCSP Signing") ], critical: false));
            request.CertificateExtensions.Add(new X509Extension(OCSP.NoCheckOID, [ 0x05, 0x00 ], critical: false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(CACertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));

            X509Certificate2 certificate;

            try
            {
                certificate = request.Create(
                                  CACertificate.SubjectName,
                                  GeneratorFor(CAKey),
                                  Now - ClockSkew,
                                  Min(Now + ResponderValidity, CA.NotAfter),
                                  NewSerialNumber()
                              );
            }
            catch (CryptographicException e)
            {
                key.Dispose();
                Error = $"The OCSP responder of the {CA.Profile.InWords()} '{CA.CommonName}' could not be signed: {e.Message}";
                return false;
            }

            var chain = ChainCertificates(CA.Id);

            try
            {
                if (!Transparency.TryAppend(certificate, chain, out _, out var logError))
                {
                    certificate.Dispose();
                    key.Dispose();
                    Error = $"The {CA.Profile.InWords()} '{CA.CommonName}' has no new OCSP responder: {logError}";
                    return false;
                }
            }
            finally
            {
                foreach (var one in chain)
                    one.Dispose();
            }

            var keyFile          = ResponderKeyFile(CA.Id);
            var certificateFile  = ResponderFile(CA.Id);

            try
            {

                System.IO.Directory.CreateDirectory(RevocationDirectory);

                // The key first: a certificate beside the key of the one
                // before it would be a responder whose answers nobody believes.
                TryDelete(keyFile + ".tmp");
                WritePrivately(keyFile + ".tmp", KeyPEM(key, null));
                TryDelete(certificateFile + ".tmp");
                File.WriteAllText(certificateFile + ".tmp", certificate.ExportCertificatePem() + "\n");

                File.Move(keyFile         + ".tmp", keyFile,         overwrite: true);
                File.Move(certificateFile + ".tmp", certificateFile, overwrite: true);

            }
            catch (Exception e)
            {
                TryDelete(keyFile         + ".tmp");
                TryDelete(certificateFile + ".tmp");
                certificate.Dispose();
                key.Dispose();
                Error = $"The OCSP responder of the {CA.Profile.InWords()} '{CA.CommonName}' could not be written to '{RevocationDirectory}': {e.Message}";
                return false;
            }

            ForgetResponder(CA.Id);
            responders[CA.Id] = (certificate, key);

            return true;

        }

        #endregion

        #region (private) Responders, CAs and serial numbers

        /// <summary>
        /// The responder of a CA with its key, read once. Called under the lock.
        /// </summary>
        private (X509Certificate2 Certificate, AsymmetricAlgorithm Key)? ResponderKeyOf(String CAId)
        {

            if (responders.TryGetValue(CAId, out var responder))
                return responder;

            var certificateFile  = ResponderFile(CAId);
            var keyFile          = ResponderKeyFile(CAId);

            if (!File.Exists(certificateFile) || !File.Exists(keyFile))
                return null;

            try
            {

                var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(certificateFile));

                if (!TryLoadKey(File.ReadAllText(keyFile), certificate.PublicKey, null, out var key, out var error))
                {
                    certificate.Dispose();
                    OnWarning?.Invoke($"The key of the OCSP responder in '{keyFile}' could not be read: {error}");
                    return null;
                }

                responders[CAId] = (certificate, key);
                return responders[CAId];

            }
            catch (Exception e)
            {
                OnWarning?.Invoke($"The OCSP responder in '{certificateFile}' could not be read: {e.Message}");
                return null;
            }

        }

        private void ForgetResponder(String CAId)
        {

            if (responders.Remove(CAId, out var old))
            {
                old.Certificate.Dispose();
                old.Key.Dispose();
            }

            ocspAnswers.Clear();

        }

        /// <summary>
        /// The CA a CertID names, by the hashes of its name and its key - or
        /// null where it is none of this PKI's. Called under the lock.
        /// </summary>
        private IssuedCertificate? CAOf(OCSPCertID CertID)
        {

            if (OCSP.HashOf(CertID.HashAlgorithm) is null)
                return null;

            foreach (var ca in certificates.Values.Where(one => one.Profile.IsCA()))
            {

                var key = $"{ca.Id}|{CertID.HashAlgorithm}";

                if (!caHashes.TryGetValue(key, out var hashes))
                {
                    using var certificate = Load(ca.Id);
                    if (certificate is null)
                        continue;
                    hashes = caHashes[key] = OCSP.HashesOf(certificate, CertID.HashAlgorithm);
                }

                if (hashes.NameHash.AsSpan().SequenceEqual(CertID.IssuerNameHash) &&
                    hashes.KeyHash. AsSpan().SequenceEqual(CertID.IssuerKeyHash))
                {
                    return ca;
                }

            }

            return null;

        }

        /// <summary>
        /// The serial numbers the given CA signed: of the certificates in the
        /// store, and of every certificate in the transparency log below it -
        /// those deleted, and its responders. Called under the lock.
        /// </summary>
        private HashSet<String> SignedBy(String CAId)
        {

            #region What the log took in since it was last looked at

            while (indexedEntries < Transparency.Count)
            {

                var entries = Transparency.Entries(indexedEntries, Transparency.Count - 1);

                if (entries.Count == 0)
                    break;

                foreach (var entry in entries)
                {

                    indexedEntries++;

                    if (entry.Chain.Count == 0)
                        continue;

                    try
                    {

                        using var certificate = X509CertificateLoader.LoadCertificate(entry.Certificate);
                        var issuerId          = Convert.ToHexString(SHA256.HashData(entry.Chain[0])).ToLowerInvariant();

                        if (!loggedSerials.TryGetValue(issuerId, out var serials))
                            serials = loggedSerials[issuerId] = new HashSet<String>(StringComparer.Ordinal);

                        serials.Add(RevocationReasons.NormalizedSerial(certificate.SerialNumber));

                    }
                    catch (CryptographicException)
                    { }

                }

            }

            #endregion

            var signed = loggedSerials.TryGetValue(CAId, out var logged)
                             ? new HashSet<String>(logged, StringComparer.Ordinal)
                             : new HashSet<String>(StringComparer.Ordinal);

            foreach (var certificate in certificates.Values.Where(one => CAId.Equals(one.IssuerId, StringComparison.OrdinalIgnoreCase) && one.Id != CAId))
                signed.Add(RevocationReasons.NormalizedSerial(certificate.SerialNumber));

            return signed;

        }

        #endregion

        #region (private) The list of revocations

        private String RevokedFile
            => Path.Combine(RevocationDirectory, RevokedFileName);

        private String CRLFile(String CAId)
            => Path.Combine(RevocationDirectory, CAId + ".crl");

        private String ResponderFile(String CAId)
            => Path.Combine(RevocationDirectory, CAId + ".ocsp.crt");

        private String ResponderKeyFile(String CAId)
            => Path.Combine(RevocationDirectory, CAId + ".ocsp.key");

        /// <summary>
        /// The list of revocations, read at the start - and every certificate
        /// of the store it names said to be revoked.
        /// </summary>
        private void LoadRevocations(List<String> PassedOver)
        {

            if (!File.Exists(RevokedFile))
                return;

            JArray list;

            try
            {
                using var reader = new JsonTextReader(new StringReader(File.ReadAllText(RevokedFile))) {
                                       DateParseHandling = DateParseHandling.None
                                   };

                list = JArray.Load(reader);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException($"The list of the certificates the PKI revoked, '{RevokedFile}', could not be read: {e.Message} " +
                                                     "Repair it: without it, every certificate revoked would be believed again.");
            }

            foreach (var entry in list)
            {

                var revocation = RevokedCertificate.TryParse(entry);

                if (revocation is null)
                {
                    PassedOver.Add($"An entry of '{RevokedFile}' could not be read and was passed over: {entry.ToString(Formatting.None)}");
                    continue;
                }

                revoked[revocation.Id] = revocation;

                if (certificates.TryGetValue(revocation.Id, out var certificate))
                    certificates[revocation.Id] = certificate with {
                                                      RevokedAt         = revocation.RevokedAt,
                                                      RevocationReason  = RevocationReasons.AsText(revocation.Reason)
                                                  };

            }

        }

        /// <summary>
        /// The list of revocations, through a temporary file moved into place.
        /// Called under the lock.
        /// </summary>
        private Boolean TryWriteRevoked([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            var temporary = RevokedFile + ".tmp";

            try
            {

                System.IO.Directory.CreateDirectory(RevocationDirectory);

                var list = new JArray(revoked.Values.
                                              OrderBy(one => one.RevokedAt).
                                              Select (one => one.ToJSON()));

                File.WriteAllText(temporary, list.ToString(Formatting.Indented));
                File.Move(temporary, RevokedFile, overwrite: true);

                return true;

            }
            catch (Exception e)
            {
                TryDelete(temporary);
                Error = e.Message;
                return false;
            }

        }

        /// <summary>
        /// What is left of the revocation of CAs deleted from the store: their
        /// CRLs, their responders, and the revocations of what they signed -
        /// which nothing here can say any more. The revocation of a deleted CA
        /// itself stays: the CA above it still says so. Called under the lock.
        /// </summary>
        private void ForgetRevocationOf(IEnumerable<IssuedCertificate> Removed)
        {

            var changed = false;

            foreach (var ca in Removed.Where(one => one.Profile.IsCA()))
            {

                ForgetResponder(ca.Id);

                foreach (var key in caHashes.Keys.Where(key => key.StartsWith(ca.Id + "|", StringComparison.OrdinalIgnoreCase)).ToList())
                    caHashes.Remove(key);

                TryDelete(CRLFile(ca.Id));
                TryDelete(ResponderFile(ca.Id));
                TryDelete(ResponderKeyFile(ca.Id));

                foreach (var below in revoked.Values.Where(one => one.IssuerId == ca.Id).ToList())
                {
                    revoked.Remove(below.Id);
                    changed = true;
                }

            }

            if (changed && !TryWriteRevoked(out var error))
                OnWarning?.Invoke($"'{RevokedFile}' could not be written after CAs were deleted: {error}");

        }

        private static DateTimeOffset Min(DateTimeOffset A, DateTimeOffset B)
            => A < B ? A : B;

        #endregion

    }

}
