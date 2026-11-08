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
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.PKI.Revocation;
using cloud.charging.open.PKI.Transparency;

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// What a CSR says, before anything is signed: who it is about, its key,
    /// the names it asks for and whether its signature holds.
    /// </summary>
    public sealed record CSRInspection(String                 Subject,
                                       String?                CommonName,
                                       String                 KeyAlgorithm,
                                       Boolean                KeySupported,
                                       IReadOnlyList<String>  SubjectAlternativeNames,
                                       Boolean                SignatureValid)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("subject",                  Subject),
                   new JProperty("commonName",               CommonName),
                   new JProperty("keyAlgorithm",             KeyAlgorithm),
                   new JProperty("keySupported",             KeySupported),
                   new JProperty("subjectAlternativeNames",  new JArray(SubjectAlternativeNames)),
                   new JProperty("signatureValid",           SignatureValid)
               );

    }


    /// <summary>
    /// The certificates this PKI made, and what makes more of them: root CAs,
    /// sub-CAs below them, and server and client certificates below either -
    /// with a key made here, or for the key of a certificate signing request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A directory - "pki" beside the configuration file - with two files per
    /// certificate, named by its SHA-256 fingerprint: "&lt;id&gt;.crt", the
    /// certificate as PEM, and "&lt;id&gt;.key", its private key as PKCS#8 PEM
    /// where this PKI made the key. And "index.json" beside them, which says
    /// what each of them is for, who asked for it and when, so that a list
    /// does not read every file. A certificate made from a CSR has no key
    /// here: its key never left whoever asked.
    /// </para>
    /// <para>
    /// A private key is kept unencrypted unless it was given a password: then
    /// it is an "ENCRYPTED PRIVATE KEY", PKCS#8 encrypted with AES-256 and a
    /// key derived from the password by PBKDF2 - see <see cref="KeyEncryption"/>.
    /// The password itself is kept nowhere: a CA whose key has one signs only
    /// when it is given again, and the key of a server or a client goes out
    /// as it is kept, for whoever has it to open with the password. Either
    /// way, the file system guards the keys too: on Linux and macOS they are
    /// written readable by their owner alone. Whoever can read this directory
    /// can sign as every CA in it whose key has no password.
    /// </para>
    /// <para>
    /// Beside them, in "transparency", the certificate transparency log of
    /// the PKI - see <see cref="TransparencyLog"/>. Every certificate is
    /// written to it before it is kept anywhere else, so that there is none
    /// the log does not have; a certificate the log could not take is not
    /// kept, and a deleted one stays in the log.
    /// </para>
    /// <para>
    /// And in "revocation", what it revoked: a CRL per CA, and an OCSP
    /// responder per CA - see PKIStore.Revocation.cs.
    /// </para>
    /// <para>
    /// Everything that changes the store does so under one lock, and writes
    /// the index through a temporary file moved into place, so that a
    /// process dying mid-write leaves the old index behind and not half of
    /// the new one. A change the disk refuses is undone - files written for it
    /// are deleted again - and said as such, with <c>NotSaved</c>.
    /// </para>
    /// </remarks>
    public sealed partial class PKIStore
    {

        #region Data

        /// <summary>
        /// The name of the index beside the certificates.
        /// </summary>
        public const   String  IndexFileName       = "index.json";

        /// <summary>
        /// The name of the directory of the transparency log, beside the
        /// certificates.
        /// </summary>
        public const   String  TransparencyDirectory  = "transparency";

        /// <summary>
        /// The longest a certificate may be made for: a hundred years, which
        /// is more than any root anybody uses and less than X.509 can write.
        /// </summary>
        public const   Int32   MaxValidityDays     = 36_500;

        /// <summary>
        /// How far back a certificate's validity begins: five minutes before
        /// it was made, so that a machine whose clock is a little behind this
        /// one does not find it "not yet valid" for the first minutes of its
        /// life.
        /// </summary>
        public static readonly TimeSpan  ClockSkew  = TimeSpan.FromMinutes(5);

        /// <summary>
        /// The shortest password a private key may be given: a password is
        /// optional, but one of three letters protects nothing.
        /// </summary>
        public const   Int32   MinKeyPasswordLength  = 8;

        /// <summary>
        /// How a private key with a password is encrypted: PKCS#8 with
        /// AES-256-CBC, its key derived from the password by PBKDF2 with
        /// SHA-256 and 600,000 iterations - what OWASP asks of PBKDF2 with
        /// SHA-256 - so that openssl and every TLS stack can open it.
        /// </summary>
        public static readonly PbeParameters  KeyEncryption  = new (PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);

        private const  String  EncryptedKeyLabel     = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

        private readonly  Object                                 gate          = new();
        private readonly  Dictionary<String, IssuedCertificate>  certificates  = new (StringComparer.OrdinalIgnoreCase);
        private readonly  TimeProvider                           timeProvider;

        #endregion

        #region Properties

        /// <summary>
        /// Where the certificates, their keys and the index are.
        /// </summary>
        public String                  Directory    { get; }

        /// <summary>
        /// Where the index is.
        /// </summary>
        public String                  IndexFile
            => Path.Combine(Directory, IndexFileName);

        /// <summary>
        /// What the store passed over when it was read: an entry of the index
        /// whose certificate file is gone, or one it could not read - each
        /// said in a sentence, for the log.
        /// </summary>
        public IReadOnlyList<String>   PassedOver   { get; }

        /// <summary>
        /// The certificate transparency log of this PKI: every certificate it
        /// signed, deleted or not.
        /// </summary>
        public TransparencyLog         Transparency            { get; }

        /// <summary>
        /// How many certificates of the store the log did not have when it was
        /// read, and took in then: every one of them, where the log was made
        /// at that start.
        /// </summary>
        public Int32                   TakenIntoTheLog         { get; }

        /// <summary>
        /// How many certificates are in it.
        /// </summary>
        public Int32 Count
        {
            get
            {
                lock (gate)
                    return certificates.Count;
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The store in the given directory, made where there is none yet.
        /// </summary>
        /// <param name="Directory">Where the certificates, their keys and the index are.</param>
        /// <param name="TimeProvider">The clock, or null for the system one.</param>
        public PKIStore(String         Directory,
                        TimeProvider?  TimeProvider   = null)
        {

            this.Directory     = Path.GetFullPath(Directory);
            this.timeProvider  = TimeProvider ?? TimeProvider.System;

            System.IO.Directory.CreateDirectory(this.Directory);

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(this.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var passedOver = new List<String>();

            if (File.Exists(IndexFile))
            {

                JArray index;

                try
                {
                    // Dates as the text they were written as: Json.NET would
                    // otherwise make every one of them a DateTime of this
                    // machine's zone, and its text again without the fraction
                    // of a second it was written with.
                    using var reader = new JsonTextReader(new StringReader(File.ReadAllText(IndexFile))) {
                                           DateParseHandling = DateParseHandling.None
                                       };

                    index = JArray.Load(reader);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException($"The index of the PKI, '{IndexFile}', could not be read: {e.Message} Repair it, or move it away to start with an empty PKI.");
                }

                foreach (var entry in index)
                {

                    var certificate = IssuedCertificate.TryParse(entry);

                    if (certificate is null)
                    {
                        passedOver.Add($"An entry of '{IndexFile}' could not be read and was passed over: {entry.ToString(Formatting.None)}");
                        continue;
                    }

                    if (!File.Exists(CertificateFile(certificate.Id)))
                    {
                        passedOver.Add($"The {certificate.Profile.InWords()} '{certificate.CommonName}' ({certificate.Id}) has no file '{CertificateFile(certificate.Id)}' any more, and was passed over.");
                        continue;
                    }

                    // The key is what is on the disk, not what the index says:
                    // a key somebody moved away is a CA that can sign no more.
                    var keyFile = KeyFile(certificate.Id);

                    certificates[certificate.Id] = certificate with {
                                                       HasPrivateKey  = File.Exists(keyFile),
                                                       KeyEncrypted   = File.Exists(keyFile) && IsEncrypted(File.ReadAllText(keyFile))
                                                   };

                }

            }

            LoadRevocations(passedOver);

            #region The transparency log, with every certificate of the store in it

            Transparency = new TransparencyLog(Path.Combine(this.Directory, TransparencyDirectory), this.timeProvider);

            foreach (var problem in Transparency.Problems)
                passedOver.Add($"Transparency log: {problem}");

            // Those it does not have yet - all of them, where the log is new
            // - in the order they were made, so that a CA is in it before
            // what it signed.
            var notInTheLog = certificates.Values.
                                           Where  (certificate => Transparency.Find(certificate.Id) is null).
                                           OrderBy(certificate => certificate.CreatedAt).
                                           ToList();

            foreach (var certificate in notInTheLog)
            {

                using var x509   = Load(certificate.Id)!;
                var chain        = ChainCertificates(certificate.IssuerId);

                try
                {
                    if (!Transparency.TryAppend(x509, chain, out _, out var error))
                    {
                        passedOver.Add($"Transparency log: the {certificate.Profile.InWords()} '{certificate.CommonName}' ({certificate.Id}) is not in it - {error}");
                        break;
                    }
                }
                finally
                {
                    foreach (var one in chain)
                        one.Dispose();
                }

                TakenIntoTheLog++;

            }

            if (TakenIntoTheLog > 0 && !Transparency.IsNew)
                passedOver.Add($"Transparency log: {TakenIntoTheLog} certificate(s) of the store were not in it, and were taken in now - " +
                                "with the time of this start, not the time they were made.");

            #endregion

            PassedOver = passedOver;

        }

        #endregion


        #region Reading

        /// <summary>
        /// Every certificate, the newest first - or those whose common name
        /// holds the given text, whatever its case, and those of the given
        /// profile.
        /// </summary>
        public IReadOnlyList<IssuedCertificate> Find(String?              CommonName  = null,
                                                     CertificateProfile?  Profile     = null)
        {

            lock (gate)
            {
                return certificates.Values.
                           Where  (certificate => String.IsNullOrWhiteSpace(CommonName) ||
                                                  certificate.CommonName.Contains(CommonName.Trim(), StringComparison.OrdinalIgnoreCase)).
                           Where  (certificate => Profile is null || certificate.Profile == Profile).
                           OrderByDescending(certificate => certificate.CreatedAt).
                           ThenBy (certificate => certificate.CommonName, StringComparer.OrdinalIgnoreCase).
                           ToList();
            }

        }

        /// <summary>
        /// One certificate by its SHA-256 fingerprint, in any of the ways a
        /// fingerprint is written - with colons, in capitals - or null.
        /// </summary>
        public IssuedCertificate? Get(String Id)
        {

            lock (gate)
            {
                return certificates.TryGetValue(Normalized(Id), out var certificate)
                           ? certificate
                           : null;
            }

        }

        /// <summary>
        /// The certificates the given CA signed - directly, not further below.
        /// </summary>
        public IReadOnlyList<IssuedCertificate> IssuedBy(String Id)
        {

            var id = Normalized(Id);

            lock (gate)
            {
                return certificates.Values.
                           Where(certificate => certificate.Id != id && id.Equals(certificate.IssuerId, StringComparison.OrdinalIgnoreCase)).
                           ToList();
            }

        }

        /// <summary>
        /// The certificate and every CA above it, up to its root - as far as
        /// this store has them.
        /// </summary>
        public IReadOnlyList<IssuedCertificate> Chain(String Id)
        {

            var chain = new List<IssuedCertificate>();

            lock (gate)
            {

                var next = Get(Id);

                while (next is not null && chain.All(one => one.Id != next.Id))
                {
                    chain.Add(next);
                    next = next.IssuerId is null ? null : Get(next.IssuerId);
                }

            }

            return chain;

        }

        /// <summary>
        /// The certificate as PEM, or null where there is none.
        /// </summary>
        public String? CertificatePEM(String Id)
        {

            var file = CertificateFile(Normalized(Id));

            return Get(Id) is not null && File.Exists(file)
                       ? File.ReadAllText(file)
                       : null;

        }

        /// <summary>
        /// The certificate and the sub-CAs above it, as PEM, the certificate
        /// first and without the root: what a TLS server or client presents.
        /// </summary>
        public String? ChainPEM(String Id)
        {

            var chain = Chain(Id).Where(certificate => certificate.Profile != CertificateProfile.RootCA || certificate.Id == Normalized(Id)).ToList();

            if (chain.Count == 0)
                return null;

            var builder = new StringBuilder();

            foreach (var certificate in chain)
                builder.Append(CertificatePEM(certificate.Id)?.TrimEnd()).Append('\n');

            return builder.ToString();

        }

        /// <summary>
        /// The private key as PKCS#8 PEM, as it is kept: encrypted where it
        /// was given a password, unencrypted where not - or null where this PKI
        /// does not have it.
        /// </summary>
        public String? PrivateKeyPEM(String Id)
        {

            var file = KeyFile(Normalized(Id));

            return Get(Id) is not null && File.Exists(file)
                       ? File.ReadAllText(file)
                       : null;

        }

        /// <summary>
        /// The certificate itself, or null.
        /// </summary>
        public X509Certificate2? Load(String Id)
        {

            var pem = CertificatePEM(Id);

            return pem is null
                       ? null
                       : X509Certificate2.CreateFromPem(pem);

        }

        #endregion


        #region TryCreateRootCA(...)

        /// <summary>
        /// A new root CA: a new key, and a certificate it signed itself.
        /// </summary>
        /// <param name="Subject">Who it is.</param>
        /// <param name="KeyAlgorithm">What kind of key it is made with.</param>
        /// <param name="ValidDays">For how many days from now it holds.</param>
        /// <param name="PathLength">How many sub-CAs may stand below it, one below the other; null for any number.</param>
        /// <param name="KeyPassword">The password its key is encrypted with; null to keep it unencrypted.</param>
        /// <param name="CreatedBy">Who asked for it.</param>
        public Boolean TryCreateRootCA(SubjectName                                   Subject,
                                       KeyAlgorithm                                  KeyAlgorithm,
                                       Int32                                         ValidDays,
                                       Int32?                                        PathLength,
                                       String?                                       KeyPassword,
                                       String?                                       CreatedBy,
                                       [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                       [NotNullWhen(false)] out String?              Error,
                                       out Boolean                                   NotSaved)
        {

            Certificate  = null;
            NotSaved     = false;

            if (!ValidityIsFine(ValidDays, out Error) ||
                !PathLengthIsFine(PathLength, out Error) ||
                !KeyPasswordIsFine(KeyPassword, out Error))
            {
                return false;
            }

            using var key   = KeyAlgorithm.NewKey();
            var now         = timeProvider.GetUtcNow();
            var subject     = Subject.ToX500();

            var request     = NewRequest(subject, new PublicKey(key), KeyAlgorithm.Hash);
            AddExtensions(request, CertificateProfile.RootCA, request.PublicKey, PathLength, [], issuer: null, IssuerId: null);

            using var certificate = request.Create(
                                        subject,
                                        GeneratorFor(key),
                                        now - ClockSkew,
                                        now.AddDays(ValidDays),
                                        NewSerialNumber()
                                    );

            if (!TryKeep(certificate, key, KeyPassword, CertificateProfile.RootCA, null, PathLength, false, CreatedBy, out Certificate, out Error, out NotSaved))
                return false;

            // Its key is open now, and may not be again for a while: its CRL
            // and its OCSP responder, while it is.
            Warn(KeepRevocationFresh(Certificate, certificate, key, ForceCRL: true, Validity: null));

            return true;

        }

        #endregion

        #region TryIssue(...)

        /// <summary>
        /// A new certificate below a CA of this store, with a new key: a
        /// sub-CA, or a certificate for a server or a client.
        /// </summary>
        /// <param name="IssuerId">The CA that signs it.</param>
        /// <param name="IssuerKeyPassword">The password of the CA's key, where it has one.</param>
        /// <param name="Profile">A sub-CA, a server or a client.</param>
        /// <param name="Subject">Who it is about.</param>
        /// <param name="KeyAlgorithm">What kind of key it is made with.</param>
        /// <param name="ValidDays">For how many days from now it holds; no longer than its CA.</param>
        /// <param name="AlternativeNames">The other names it is valid for - a server's host names and addresses.</param>
        /// <param name="PathLength">For a sub-CA: how many sub-CAs may stand below it; null for as many as its CA allows.</param>
        /// <param name="KeyPassword">The password its new key is encrypted with; null to keep it unencrypted.</param>
        /// <param name="CreatedBy">Who asked for it.</param>
        public Boolean TryIssue(String                                        IssuerId,
                                String?                                       IssuerKeyPassword,
                                CertificateProfile                            Profile,
                                SubjectName                                   Subject,
                                KeyAlgorithm                                  KeyAlgorithm,
                                Int32                                         ValidDays,
                                IReadOnlyList<String>                         AlternativeNames,
                                Int32?                                        PathLength,
                                String?                                       KeyPassword,
                                String?                                       CreatedBy,
                                [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                [NotNullWhen(false)] out String?              Error,
                                out Boolean                                   NotSaved)
        {

            Certificate  = null;
            NotSaved     = false;

            if (Profile == CertificateProfile.RootCA)
            {
                Error = "A root CA signs itself; it is made as one, not below a CA.";
                return false;
            }

            if (!KeyPasswordIsFine(KeyPassword, out Error))
                return false;

            using var key = KeyAlgorithm.NewKey();

            return TrySign(IssuerId, IssuerKeyPassword, Profile, Subject.ToX500(), Subject.CommonName, new PublicKey(key), key, KeyPassword,
                           ValidDays, WithHostName(Profile, Subject.CommonName, AlternativeNames), PathLength, false, CreatedBy,
                           out Certificate, out Error, out NotSaved);

        }

        #endregion

        #region TryIssueFromCSR(...)

        /// <summary>
        /// A new certificate below a CA of this store for the key of a
        /// certificate signing request: who it is about is what the request
        /// says, what it may be used for is what the profile says, whatever
        /// the request asked for.
        /// </summary>
        /// <remarks>
        /// The extensions a request asks for are not taken over, but for its
        /// alternative names, where <paramref name="TakeAlternativeNames"/>
        /// says so: a request that asks to be a CA, or to sign code, is
        /// signed as what the person signing it chose, and nothing more. That
        /// is the difference between a PKI and a signing oracle.
        /// </remarks>
        /// <param name="IssuerId">The CA that signs it.</param>
        /// <param name="IssuerKeyPassword">The password of the CA's key, where it has one.</param>
        /// <param name="Profile">A sub-CA, a server or a client.</param>
        /// <param name="CSR">The request, as PEM - or as Base64 of its DER.</param>
        /// <param name="ValidDays">For how many days from now it holds; no longer than its CA.</param>
        /// <param name="AlternativeNames">Other names it is valid for, beside those taken from the request.</param>
        /// <param name="TakeAlternativeNames">Whether the names the request asks for are taken over.</param>
        /// <param name="PathLength">For a sub-CA: how many sub-CAs may stand below it.</param>
        /// <param name="CreatedBy">Who asked for it.</param>
        public Boolean TryIssueFromCSR(String                                        IssuerId,
                                       String?                                       IssuerKeyPassword,
                                       CertificateProfile                            Profile,
                                       String                                        CSR,
                                       Int32                                         ValidDays,
                                       IReadOnlyList<String>                         AlternativeNames,
                                       Boolean                                       TakeAlternativeNames,
                                       Int32?                                        PathLength,
                                       String?                                       CreatedBy,
                                       [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                       [NotNullWhen(false)] out String?              Error,
                                       out Boolean                                   NotSaved)
        {

            Certificate  = null;
            NotSaved     = false;

            if (Profile == CertificateProfile.RootCA)
            {
                Error = "A root CA signs itself; a CSR is signed as a sub-CA, a server or a client.";
                return false;
            }

            if (!TryLoadCSR(CSR, out var request, out Error))
                return false;

            if (KeyAlgorithm.Of(request.PublicKey) is null)
            {
                Error = $"The CSR is for a key of {KeyAlgorithm.Describe(request.PublicKey)}, which this PKI does not sign: " +
                        $"{String.Join(", ", KeyAlgorithm.All.Select(algorithm => algorithm.Name))}.";
                return false;
            }

            var commonName = CommonNameOf(request.SubjectName);

            if (commonName is null)
            {
                Error = "The CSR names no common name, and a certificate of this PKI is found by its common name.";
                return false;
            }

            var names = new List<String>();

            if (TakeAlternativeNames)
                names.AddRange(AlternativeNames_Of(request));

            foreach (var name in AlternativeNames)
                if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    names.Add(name);

            foreach (var name in names)
            {
                if (!Issuance.AlternativeNames.IsValid(name, out var why))
                {
                    Error = why;
                    return false;
                }
            }

            return TrySign(IssuerId, IssuerKeyPassword, Profile, request.SubjectName, commonName, request.PublicKey, null, null,
                           ValidDays, WithHostName(Profile, commonName, names), PathLength, true, CreatedBy,
                           out Certificate, out Error, out NotSaved);

        }

        #endregion

        #region (static) TryInspectCSR(CSR, out Inspection, out Error)

        /// <summary>
        /// What a CSR says, without signing anything - and whether its
        /// signature holds, which a request that does not hold is still
        /// shown for: somebody pasting it wants to know what is in it.
        /// </summary>
        public static Boolean TryInspectCSR(String                                    CSR,
                                            [NotNullWhen(true)]  out CSRInspection?   Inspection,
                                            [NotNullWhen(false)] out String?          Error)
        {

            Inspection = null;

            var signatureValid = TryLoadCSR(CSR, out var request, out Error);

            if (!signatureValid)
            {
                if (!TryLoadCSR(CSR, out request, out _, SkipSignature: true))
                    return false;
                Error = null;
            }

            Inspection = new CSRInspection(
                             Subject:                  request!.SubjectName.Name,
                             CommonName:               CommonNameOf(request.SubjectName),
                             KeyAlgorithm:             KeyAlgorithm.Of(request.PublicKey)?.Name ?? KeyAlgorithm.Describe(request.PublicKey),
                             KeySupported:             KeyAlgorithm.Of(request.PublicKey) is not null,
                             SubjectAlternativeNames:  AlternativeNames_Of(request),
                             SignatureValid:           signatureValid
                         );

            return true;

        }

        #endregion

        #region TryRemove(Id, WithIssued, out Removed, out Error, out NotFound, out NotSaved)

        /// <summary>
        /// Delete a certificate for good - its file, its key and its entry -
        /// and, where it is a CA and <paramref name="WithIssued"/> says so,
        /// everything it signed, all the way down.
        /// </summary>
        /// <remarks>
        /// A CA that signed certificates still in the store is not deleted on
        /// its own: what it signed would be left with an issuer nobody can
        /// look up, and nothing could ever sign below it again. Deleting is
        /// not revoking - a certificate that went out is still believed by
        /// whoever believes its root - and nothing here pretends otherwise.
        /// </remarks>
        public Boolean TryRemove(String                                                  Id,
                                 Boolean                                                 WithIssued,
                                 [NotNullWhen(true)]  out IReadOnlyList<IssuedCertificate>?  Removed,
                                 [NotNullWhen(false)] out String?                        Error,
                                 out Boolean                                             NotFound,
                                 out Boolean                                             NotSaved)
        {

            Removed   = null;
            Error     = null;
            NotFound  = false;
            NotSaved  = false;

            lock (gate)
            {

                var certificate = Get(Id);

                if (certificate is null)
                {
                    NotFound = true;
                    Error    = $"There is no certificate '{Id}' in this PKI.";
                    return false;
                }

                // Everything below it, the deepest first, so that a run that
                // stops halfway leaves no certificate without its issuer.
                var below = new List<IssuedCertificate>();
                var queue = new Queue<IssuedCertificate>([ certificate ]);

                while (queue.TryDequeue(out var next))
                {
                    foreach (var issued in IssuedBy(next.Id))
                    {
                        if (below.All(one => one.Id != issued.Id))
                        {
                            below.Add(issued);
                            queue.Enqueue(issued);
                        }
                    }
                }

                if (below.Count > 0 && !WithIssued)
                {
                    Error = $"The {certificate.Profile.InWords()} '{certificate.CommonName}' signed {below.Count} certificate(s) still in this PKI. " +
                             "Delete them first, or delete it with everything it signed.";
                    return false;
                }

                var removed = below.AsEnumerable().Reverse().Append(certificate).ToList();
                var before  = new Dictionary<String, IssuedCertificate>(certificates, StringComparer.OrdinalIgnoreCase);

                foreach (var one in removed)
                    certificates.Remove(one.Id);

                if (!TryWriteIndex(out var writeError))
                {

                    certificates.Clear();

                    foreach (var (id, one) in before)
                        certificates[id] = one;

                    NotSaved = true;
                    Error    = $"Nothing was deleted: the index '{IndexFile}' could not be written - {writeError}";
                    return false;

                }

                // The index no longer names them; a file that cannot be deleted
                // now is one the next look at the directory finds without an
                // entry, and a key left behind is still said in the log.
                var leftBehind = new List<String>();

                foreach (var one in removed)
                {
                    foreach (var file in new[] { KeyFile(one.Id), CertificateFile(one.Id) })
                    {
                        try
                        {
                            if (File.Exists(file))
                                File.Delete(file);
                        }
                        catch (Exception)
                        {
                            leftBehind.Add(file);
                        }
                    }
                }

                ForgetRevocationOf(removed);

                Removed = removed;
                Error   = leftBehind.Count > 0
                              ? $"Deleted from the index, but these files could not be deleted: {String.Join(", ", leftBehind)}"
                              : null;

                return true;

            }

        }

        #endregion

        #region TryChangeKeyPassword(Id, Password, NewPassword, out Certificate, out Error, out NotFound, out NotSaved)

        /// <summary>
        /// Give the private key of a certificate a password, another one, or
        /// none any more: the key is opened with the password it has - none,
        /// where it has none - and kept anew, encrypted with the new one, or
        /// unencrypted where that is null.
        /// </summary>
        /// <remarks>
        /// The key file is replaced through a temporary file moved into place,
        /// so that a process dying mid-write leaves the old key behind and not
        /// half of the new one. Whether a key is encrypted is read from its
        /// file at every start, so an index that cannot be written afterwards
        /// is said again correctly then.
        /// </remarks>
        /// <param name="Id">The certificate whose key it is.</param>
        /// <param name="Password">The password the key has now; null where it has none.</param>
        /// <param name="NewPassword">The password it is to have; null for none.</param>
        public Boolean TryChangeKeyPassword(String                                        Id,
                                            String?                                       Password,
                                            String?                                       NewPassword,
                                            [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                            [NotNullWhen(false)] out String?              Error,
                                            out Boolean                                   NotFound,
                                            out Boolean                                   NotSaved)
        {

            Certificate  = null;
            NotFound     = false;
            NotSaved     = false;

            if (!KeyPasswordIsFine(NewPassword, out Error))
                return false;

            lock (gate)
            {

                var certificate = Get(Id);

                if (certificate is null)
                {
                    NotFound = true;
                    Error    = $"There is no certificate '{Id}' in this PKI.";
                    return false;
                }

                var keyPEM = PrivateKeyPEM(certificate.Id);

                if (keyPEM is null)
                {
                    NotFound = true;
                    Error    = certificate.FromCSR
                                   ? $"'{certificate.CommonName}' was signed for a CSR: its private key never was here."
                                   : $"The private key of '{certificate.CommonName}' is not in this PKI any more.";
                    return false;
                }

                using var x509 = Load(certificate.Id)!;

                if (!TryLoadKey(keyPEM, x509.PublicKey, Password, out var key, out var keyError))
                {
                    Error = $"The password of the private key of the {certificate.Profile.InWords()} '{certificate.CommonName}' was not changed: {keyError}";
                    return false;
                }

                var keyFile    = KeyFile(certificate.Id);
                var temporary  = keyFile + ".tmp";

                using (key)
                {
                    try
                    {
                        TryDelete(temporary);
                        WritePrivately(temporary, KeyPEM(key, NewPassword));
                        File.Move(temporary, keyFile, overwrite: true);
                    }
                    catch (Exception e)
                    {
                        TryDelete(temporary);
                        NotSaved = true;
                        Error    = $"The private key could not be written to '{Directory}', and was left as it was: {e.Message}";
                        return false;
                    }
                }

                var changed = certificate with { KeyEncrypted = NewPassword is not null };

                certificates[certificate.Id] = changed;

                // The key file is what counts, and what the next start reads.
                TryWriteIndex(out _);

                Certificate = changed;
                return true;

            }

        }

        #endregion


        #region (private) TrySign(...)

        /// <summary>
        /// Sign a public key below a CA of this store, as the given profile,
        /// and keep what came out.
        /// </summary>
        private Boolean TrySign(String                                        IssuerId,
                                String?                                       IssuerKeyPassword,
                                CertificateProfile                            Profile,
                                X500DistinguishedName                         Subject,
                                String                                        CommonName,
                                PublicKey                                     PublicKey,
                                AsymmetricAlgorithm?                          PrivateKey,
                                String?                                       KeyPassword,
                                Int32                                         ValidDays,
                                IReadOnlyList<String>                         AlternativeNames,
                                Int32?                                        PathLength,
                                Boolean                                       FromCSR,
                                String?                                       CreatedBy,
                                [NotNullWhen(true)]  out IssuedCertificate?   Certificate,
                                [NotNullWhen(false)] out String?              Error,
                                out Boolean                                   NotSaved)
        {

            Certificate  = null;
            NotSaved     = false;

            if (!ValidityIsFine(ValidDays, out Error) ||
                !PathLengthIsFine(PathLength, out Error))
            {
                return false;
            }

            var issuer = Get(IssuerId);

            if (issuer is null)
            {
                Error = $"There is no CA '{IssuerId}' in this PKI to sign with.";
                return false;
            }

            if (!issuer.Profile.IsCA())
            {
                Error = $"'{issuer.CommonName}' is a {issuer.Profile.InWords()}, which signs nothing.";
                return false;
            }

            var keyPEM = PrivateKeyPEM(issuer.Id);

            if (keyPEM is null)
            {
                Error = $"The private key of the {issuer.Profile.InWords()} '{issuer.CommonName}' is not in this PKI, so it can sign nothing here.";
                return false;
            }

            var now       = timeProvider.GetUtcNow();
            var notAfter  = now.AddDays(ValidDays);

            if (now < issuer.NotBefore || now > issuer.NotAfter)
            {
                Error = $"The {issuer.Profile.InWords()} '{issuer.CommonName}' is valid from {issuer.NotBefore:u} until {issuer.NotAfter:u}, and signs nothing outside that.";
                return false;
            }

            // A certificate that outlives its CA is believed by nobody for the
            // rest of its life, and does not look it: it is said here rather
            // than cut short without a word.
            if (notAfter > issuer.NotAfter)
            {
                Error = $"{ValidDays} days would outlive the {issuer.Profile.InWords()} '{issuer.CommonName}', which holds until {issuer.NotAfter:u} - " +
                        $"at most {(Int32) Math.Floor((issuer.NotAfter - now).TotalDays)} days below it.";
                return false;
            }

            #region What the CA allows below it

            if (Profile == CertificateProfile.SubCA && issuer.PathLength is Int32 allowed)
            {

                if (allowed == 0)
                {
                    Error = $"The {issuer.Profile.InWords()} '{issuer.CommonName}' may sign no CA below it: its path length is 0.";
                    return false;
                }

                if (PathLength is null)
                    PathLength = allowed - 1;

                else if (PathLength > allowed - 1)
                {
                    Error = $"Below the {issuer.Profile.InWords()} '{issuer.CommonName}', whose path length is {allowed}, a sub-CA's path length is at most {allowed - 1}.";
                    return false;
                }

            }

            if (Profile != CertificateProfile.SubCA)
                PathLength = null;

            #endregion

            using var issuerCertificate  = Load(issuer.Id)!;

            if (!TryLoadKey(keyPEM, issuerCertificate.PublicKey, IssuerKeyPassword, out var loadedKey, out var keyError))
            {
                Error = $"The {issuer.Profile.InWords()} '{issuer.CommonName}' signs nothing: {keyError}";
                return false;
            }

            using var issuerKey          = loadedKey;

            var hash     = KeyAlgorithm.Of(issuerCertificate.PublicKey)?.Hash ?? HashAlgorithmName.SHA256;
            var request  = NewRequest(Subject, PublicKey, hash);

            AddExtensions(request, Profile, PublicKey, PathLength, AlternativeNames, issuerCertificate, issuer.Id);

            using var certificate = request.Create(
                                        issuerCertificate.SubjectName,
                                        GeneratorFor(issuerKey),
                                        now - ClockSkew,
                                        notAfter,
                                        NewSerialNumber()
                                    );

            if (!TryKeep(certificate, PrivateKey, KeyPassword, Profile, issuer.Id, PathLength, FromCSR, CreatedBy, out Certificate, out Error, out NotSaved))
                return false;

            // The key of the CA is open, and that of a new sub-CA too: what is
            // due of their CRLs and responders, while they are - for a CA
            // whose key has a password, the only time it is.
            Warn(KeepRevocationFresh(issuer, issuerCertificate, issuerKey, ForceCRL: false, Validity: null));

            if (Profile == CertificateProfile.SubCA && PrivateKey is not null)
                Warn(KeepRevocationFresh(Certificate, certificate, PrivateKey, ForceCRL: true, Validity: null));

            return true;

        }

        #endregion

        #region (private) TryKeep(...)

        /// <summary>
        /// Write a certificate and its key, where there is one, and name it in
        /// the index - or none of the three, and why not.
        /// </summary>
        private Boolean TryKeep(X509Certificate2                              Certificate,
                                AsymmetricAlgorithm?                          PrivateKey,
                                String?                                       KeyPassword,
                                CertificateProfile                            Profile,
                                String?                                       IssuerId,
                                Int32?                                        PathLength,
                                Boolean                                       FromCSR,
                                String?                                       CreatedBy,
                                [NotNullWhen(true)]  out IssuedCertificate?   Issued,
                                [NotNullWhen(false)] out String?              Error,
                                out Boolean                                   NotSaved)
        {

            Issued    = null;
            Error     = null;
            NotSaved  = false;

            var id = Certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

            var entry = new IssuedCertificate(
                            Id:                       id,
                            Profile:                  Profile,
                            CommonName:               Certificate.GetNameInfo(X509NameType.SimpleName, false),
                            Subject:                  Certificate.Subject,
                            Issuer:                   Certificate.Issuer,
                            IssuerId:                 IssuerId,
                            SerialNumber:             Certificate.SerialNumber,
                            NotBefore:                new DateTimeOffset(Certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero),
                            NotAfter:                 new DateTimeOffset(Certificate.NotAfter. ToUniversalTime(), TimeSpan.Zero),
                            KeyAlgorithm:             KeyAlgorithm.Of(Certificate.PublicKey)?.Name ?? KeyAlgorithm.Describe(Certificate.PublicKey),
                            SubjectAlternativeNames:  AlternativeNames.Of(Certificate),
                            PathLength:               PathLength,
                            HasPrivateKey:            PrivateKey is not null,
                            KeyEncrypted:             PrivateKey is not null && KeyPassword is not null,
                            FromCSR:                  FromCSR,
                            CreatedAt:                timeProvider.GetUtcNow(),
                            CreatedBy:                CreatedBy
                        );

            lock (gate)
            {

                if (certificates.ContainsKey(id))
                {
                    Error = $"This PKI has the certificate {id} already.";
                    return false;
                }

                // Deleted while this was being signed: kept, it would be a
                // certificate below an issuer nobody can look up.
                if (IssuerId is not null && !certificates.ContainsKey(IssuerId))
                {
                    Error = "Its CA was deleted while it was being signed, and it was not kept.";
                    return false;
                }

                // In the log before it is anywhere else: a certificate the log
                // could not take is not kept, and one the log took and the
                // disk then refused is in the log all the same - it was
                // signed, which is what the log says.
                var chain = ChainCertificates(IssuerId);

                try
                {
                    if (!Transparency.TryAppend(Certificate, chain, out _, out var logError))
                    {
                        NotSaved = true;
                        Error    = $"Nothing was kept: {logError}";
                        return false;
                    }
                }
                finally
                {
                    foreach (var one in chain)
                        one.Dispose();
                }

                var written = new List<String>();

                try
                {

                    if (PrivateKey is not null)
                    {
                        WritePrivately(KeyFile(id), KeyPEM(PrivateKey, KeyPassword));
                        written.Add(KeyFile(id));
                    }

                    File.WriteAllText(CertificateFile(id), Certificate.ExportCertificatePem() + "\n");
                    written.Add(CertificateFile(id));

                }
                catch (Exception e)
                {

                    foreach (var file in written)
                        TryDelete(file);

                    NotSaved = true;
                    Error    = $"The certificate could not be written to '{Directory}': {e.Message}";
                    return false;

                }

                certificates[id] = entry;

                if (!TryWriteIndex(out var writeError))
                {

                    certificates.Remove(id);

                    foreach (var file in written)
                        TryDelete(file);

                    NotSaved = true;
                    Error    = $"The index '{IndexFile}' could not be written, and nothing was kept: {writeError}";
                    return false;

                }

            }

            Issued = entry;
            return true;

        }

        #endregion

        #region (private) TryWriteIndex(out Error)

        /// <summary>
        /// The index, through a temporary file moved into place. Called under
        /// the lock.
        /// </summary>
        private Boolean TryWriteIndex([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            var temporary = IndexFile + ".tmp";

            try
            {

                var index = new JArray(certificates.Values.
                                                    OrderBy(certificate => certificate.CreatedAt).
                                                    Select (certificate => certificate.ToJSON()));

                File.WriteAllText(temporary, index.ToString(Formatting.Indented));
                File.Move(temporary, IndexFile, overwrite: true);

                return true;

            }
            catch (Exception e)
            {
                TryDelete(temporary);
                Error = e.Message;
                return false;
            }

        }

        #endregion


        #region (private static) The request and its extensions

        /// <summary>
        /// A request for the given key, to be signed with the given hash -
        /// with PKCS#1 padding where the key is RSA, which is what every TLS
        /// stack of a charging station verifies.
        /// </summary>
        private static CertificateRequest NewRequest(X500DistinguishedName  Subject,
                                                     PublicKey              PublicKey,
                                                     HashAlgorithmName      Hash)

            => new (Subject, PublicKey, Hash, PublicKey.GetRSAPublicKey() is not null ? RSASignaturePadding.Pkcs1 : null);

        /// <summary>
        /// The extensions of a profile: whether it is a CA and how many below
        /// it, what its key may be used for, what it is for in TLS, its other
        /// names, and the identifiers that link it to its key and its CA.
        /// </summary>
        private void AddExtensions(CertificateRequest     Request,
                                   CertificateProfile     Profile,
                                   PublicKey              PublicKey,
                                   Int32?                 PathLength,
                                   IReadOnlyList<String>  AlternativeNames,
                                   X509Certificate2?      issuer,
                                   String?                IssuerId)
        {

            var isRSA = PublicKey.GetRSAPublicKey() is not null;

            if (Profile.IsCA())
            {

                Request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, PathLength is not null, PathLength ?? 0, critical: true));
                Request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign |
                                                                            X509KeyUsageFlags.CrlSign     |
                                                                            X509KeyUsageFlags.DigitalSignature, critical: true));

            }

            else
            {

                Request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));

                // A key of RSA may be what a TLS client encrypts the secret
                // with; a key of a curve only ever signs.
                Request.CertificateExtensions.Add(new X509KeyUsageExtension(isRSA
                                                                                ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
                                                                                : X509KeyUsageFlags.DigitalSignature, critical: true));

                Request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                                                      [ Profile == CertificateProfile.Server
                                                            ? new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")
                                                            : new Oid("1.3.6.1.5.5.7.3.2", "Client Authentication") ],
                                                      critical: false));

            }

            if (Issuance.AlternativeNames.ToExtension(AlternativeNames) is X509Extension names)
                Request.CertificateExtensions.Add(names);

            Request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(PublicKey, critical: false));

            if (issuer is not null)
                Request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false));

            // Where whoever checks it asks whether it was revoked, and finds
            // the CA it was signed by - where the PKI was told the address it
            // is reached at.
            if (issuer is not null && IssuerId is not null && Addresses is RevocationAddresses addresses)
            {
                Request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([ addresses.CRL(IssuerId) ], critical: false));
                Request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([ addresses.OCSP ], [ addresses.CAIssuer(IssuerId) ], critical: false));
            }

        }

        /// <summary>
        /// What signs with a key: ECDSA, or RSA with PKCS#1 padding.
        /// </summary>
        private static X509SignatureGenerator GeneratorFor(AsymmetricAlgorithm Key)

            => Key switch {
                   ECDsa  ecdsa  => X509SignatureGenerator.CreateForECDsa(ecdsa),
                   RSA    rsa    => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
                   _             => throw new NotSupportedException($"A key of {Key.GetType().Name} signs nothing here.")
               };

        /// <summary>
        /// A private key from its PEM, of the kind the public key beside it is
        /// - opened with the password where it is encrypted, and said why not
        /// where there is none or it is not the one.
        /// </summary>
        private static Boolean TryLoadKey(String                                           PEM,
                                          PublicKey                                        PublicKey,
                                          String?                                          Password,
                                          [NotNullWhen(true)]  out AsymmetricAlgorithm?    Key,
                                          [NotNullWhen(false)] out String?                 Error)
        {

            Key    = null;
            Error  = null;

            var encrypted = IsEncrypted(PEM);

            if (encrypted && String.IsNullOrEmpty(Password))
            {
                Error = "its private key has a password, and none was given.";
                return false;
            }

            AsymmetricAlgorithm key;

            if (PublicKey.GetECDsaPublicKey() is ECDsa ecdsaPublic)
            {
                ecdsaPublic.Dispose();
                key = ECDsa.Create();
            }
            else
                key = RSA.Create();

            try
            {

                if (encrypted)
                    key.ImportFromEncryptedPem(PEM, Password);
                else
                    key.ImportFromPem(PEM);

                Key = key;
                return true;

            }
            catch (CryptographicException)
            {

                key.Dispose();

                Error = encrypted
                            ? "the password given is not the one of its private key."
                            : "its private key could not be read.";

                return false;

            }

        }

        /// <summary>
        /// A private key as PKCS#8 PEM: encrypted with the password, where
        /// there is one - see <see cref="KeyEncryption"/>.
        /// </summary>
        private static String KeyPEM(AsymmetricAlgorithm  Key,
                                     String?              Password)

            => (Password is null
                    ? Key.ExportPkcs8PrivateKeyPem()
                    : Key.ExportEncryptedPkcs8PrivateKeyPem(Password, KeyEncryption)) + "\n";

        /// <summary>
        /// Whether a private key's PEM is encrypted.
        /// </summary>
        private static Boolean IsEncrypted(String PEM)

            => PEM.Contains(EncryptedKeyLabel, StringComparison.Ordinal);

        /// <summary>
        /// Sixteen random bytes, positive: what RFC 5280 asks of a serial
        /// number - unique, at most twenty bytes - and 64 bits of entropy more
        /// than the CA/Browser Forum asks for.
        /// </summary>
        private static Byte[] NewSerialNumber()
        {

            var serial = RandomNumberGenerator.GetBytes(16);

            serial[0] &= 0x7F;

            if (serial[0] == 0)
                serial[0] = 0x01;

            return serial;

        }

        #endregion

        #region (private static) Reading a CSR

        /// <summary>
        /// A CSR from its PEM - under either label it is written with - or
        /// from Base64 of its DER; its signature checked unless told not to.
        /// </summary>
        private static Boolean TryLoadCSR(String                                         CSR,
                                          [NotNullWhen(true)]  out CertificateRequest?   Request,
                                          [NotNullWhen(false)] out String?               Error,
                                          Boolean                                        SkipSignature = false)
        {

            Request  = null;
            Error    = null;

            var text = CSR?.Trim() ?? "";

            if (text.Length == 0)
            {
                Error = "There is no CSR to sign.";
                return false;
            }

            // "NEW CERTIFICATE REQUEST" is what some tools - and older
            // charging stations - write; it is the same structure.
            text = text.Replace("-----BEGIN NEW CERTIFICATE REQUEST-----", "-----BEGIN CERTIFICATE REQUEST-----").
                        Replace("-----END NEW CERTIFICATE REQUEST-----",   "-----END CERTIFICATE REQUEST-----");

            if (!text.Contains("-----BEGIN"))
                text = "-----BEGIN CERTIFICATE REQUEST-----\n" + text + "\n-----END CERTIFICATE REQUEST-----";

            var options = CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions |
                          (SkipSignature ? CertificateRequestLoadOptions.SkipSignatureValidation : CertificateRequestLoadOptions.Default);

            try
            {
                Request = CertificateRequest.LoadSigningRequestPem(text, HashAlgorithmName.SHA256, options, RSASignaturePadding.Pkcs1);
                return true;
            }
            catch (CryptographicException e)
            {
                Error = SkipSignature
                            ? $"This is no certificate signing request: {e.Message}"
                            : $"The CSR could not be read, or its signature does not hold: {e.Message}";
                return false;
            }
            catch (ArgumentException e)
            {
                Error = $"This is no certificate signing request: {e.Message}";
                return false;
            }

        }

        /// <summary>
        /// The alternative names a CSR asks for.
        /// </summary>
        private static List<String> AlternativeNames_Of(CertificateRequest Request)

            => AlternativeNames.Of(Request.CertificateExtensions);

        /// <summary>
        /// The common name of a distinguished name, or null where it has none.
        /// </summary>
        private static String? CommonNameOf(X500DistinguishedName Name)
        {

            foreach (var part in Name.EnumerateRelativeDistinguishedNames())
            {
                if (!part.HasMultipleElements && part.GetSingleElementType().Value == "2.5.4.3")
                    return part.GetSingleElementValue()?.Trim() is { Length: > 0 } commonName ? commonName : null;
            }

            return null;

        }

        #endregion

        #region (private) Checks

        private static Boolean ValidityIsFine(Int32 ValidDays, [NotNullWhen(false)] out String? Error)
        {

            Error = ValidDays < 1 || ValidDays > MaxValidityDays
                        ? $"A certificate holds for 1 to {MaxValidityDays} days; {ValidDays} is not among them."
                        : null;

            return Error is null;

        }

        /// <summary>
        /// A password for a private key: none at all, or one of
        /// <see cref="MinKeyPasswordLength"/> characters at least.
        /// </summary>
        private static Boolean KeyPasswordIsFine(String? Password, [NotNullWhen(false)] out String? Error)
        {

            Error = Password is not null && Password.Length < MinKeyPasswordLength
                        ? $"A password for a private key has {MinKeyPasswordLength} characters at least, or there is none."
                        : null;

            return Error is null;

        }

        private static Boolean PathLengthIsFine(Int32? PathLength, [NotNullWhen(false)] out String? Error)
        {

            Error = PathLength is < 0 or > 16
                        ? $"A path length is 0 to 16, or none at all; {PathLength} is not."
                        : null;

            return Error is null;

        }

        /// <summary>
        /// A server certificate's names, and its common name among them where
        /// it was given none and the common name reads as a host name: a
        /// browser and every TLS stack after RFC 6125 believe the alternative
        /// names alone, and a server certificate with none is one nobody can
        /// connect to.
        /// </summary>
        private static IReadOnlyList<String> WithHostName(CertificateProfile     Profile,
                                                          String                 CommonName,
                                                          IReadOnlyList<String>  AlternativeNames)

            => Profile == CertificateProfile.Server && AlternativeNames.Count == 0 && Issuance.AlternativeNames.LooksLikeAHostName(CommonName)
                   ? [ CommonName ]
                   : AlternativeNames;

        #endregion

        #region (private) Warn(Problems)

        private void Warn(IEnumerable<String> Problems)
        {
            foreach (var problem in Problems)
                OnWarning?.Invoke(problem);
        }

        #endregion

        #region (private) ChainCertificates(IssuerId)

        /// <summary>
        /// The CA of the given id and every one above it up to its root, read
        /// from their files: what the log is told of a certificate's chain.
        /// </summary>
        private List<X509Certificate2> ChainCertificates(String? IssuerId)

            => IssuerId is null
                   ? []
                   : Chain(IssuerId).Select(one => Load(one.Id)).OfType<X509Certificate2>().ToList();

        #endregion

        #region (private) Files

        private String CertificateFile(String Id)
            => Path.Combine(Directory, Id + ".crt");

        private String KeyFile(String Id)
            => Path.Combine(Directory, Id + ".key");

        /// <summary>
        /// A fingerprint as the store spells it: lower case, without colons,
        /// spaces or dashes.
        /// </summary>
        public static String Normalized(String Id)

            => new String(Id.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();

        /// <summary>
        /// A file only its owner may read, where the system can say so.
        /// </summary>
        private static void WritePrivately(String FileName, String Text)
        {

            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(FileName, Text);
                return;
            }

            using var stream = new FileStream(FileName, new FileStreamOptions {
                                                         Mode            = FileMode.CreateNew,
                                                         Access          = FileAccess.Write,
                                                         UnixCreateMode  = UnixFileMode.UserRead | UnixFileMode.UserWrite
                                                     });

            using var writer = new StreamWriter(stream);
            writer.Write(Text);

        }

        private static void TryDelete(String FileName)
        {
            try
            {
                if (File.Exists(FileName))
                    File.Delete(FileName);
            }
            catch (Exception)
            { }
        }

        #endregion

    }

}
