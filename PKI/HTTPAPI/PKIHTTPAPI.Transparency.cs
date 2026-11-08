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
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Transparency;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// The certificate transparency log of the PKI, below
    /// "v1/pki/transparency": what the web interface shows of it, and below
    /// "ct/v1" what RFC 6962, section 4, has a log answer - so that a monitor
    /// that speaks to the logs of the web speaks to this one, at
    /// "https://&lt;pki&gt;/api/v1/pki/transparency".
    /// </summary>
    /// <remarks>
    /// <para>
    /// | | |
    /// |---|---|
    /// | <c>GET v1/pki/transparency</c> | the log: its id, its public key, its newest signed tree head, and what is wrong with it |
    /// | <c>GET v1/pki/transparency/entries?start=&amp;end=</c> | its entries as the web interface lists them |
    /// | <c>GET .../ct/v1/get-sth</c> | the newest signed tree head |
    /// | <c>GET .../ct/v1/get-sth-consistency?first=&amp;second=</c> | the proof that the tree of second entries grew from the tree of first |
    /// | <c>GET .../ct/v1/get-proof-by-hash?hash=&amp;tree_size=</c> | the audit path of a leaf |
    /// | <c>GET .../ct/v1/get-entries?start=&amp;end=</c> | the entries, as leaves and chains |
    /// | <c>GET .../ct/v1/get-roots</c> | the roots it takes certificates below: the PKI's |
    /// | <c>GET .../ct/v1/get-entry-and-proof?leaf_index=&amp;tree_size=</c> | one entry, with its audit path |
    /// </para>
    /// <para>
    /// Nothing is added from outside: there is no add-chain and no
    /// add-pre-chain, and the log has what the PKI signed and nothing else.
    /// </para>
    /// <para>
    /// Not open to everybody, as the logs of the web are: the log names every
    /// certificate of the PKI - every charging station, every host - and is
    /// read as the PKI is, by whoever may look at its certificates. A
    /// monitor signs in with an API key of an account in the "operator" role.
    /// </para>
    /// </remarks>
    public partial class PKIHTTPAPI
    {

        #region (private) RegisterTransparencyURLTemplates()

        private void RegisterTransparencyURLTemplates()
        {

            var root = HTTPPath.Root + "v1/pki/transparency";
            var ct   = root + "/ct/v1";

            AddHandler(root,                            GetTransparencyLog,      HTTPMethod.GET);
            AddHandler(root + "/entries",               GetLogEntries,           HTTPMethod.GET);

            AddHandler(ct   + "/get-sth",               GetSTH,                  HTTPMethod.GET);
            AddHandler(ct   + "/get-sth-consistency",   GetSTHConsistency,       HTTPMethod.GET);
            AddHandler(ct   + "/get-proof-by-hash",     GetProofByHash,          HTTPMethod.GET);
            AddHandler(ct   + "/get-entries",           GetEntries,              HTTPMethod.GET);
            AddHandler(ct   + "/get-roots",             GetRoots,                HTTPMethod.GET);
            AddHandler(ct   + "/get-entry-and-proof",   GetEntryAndProof,        HTTPMethod.GET);

        }

        #endregion


        #region (private) GetTransparencyLog(Request)

        /// <summary>
        /// GET /api/v1/pki/transparency: the log - its id, its public key, how
        /// many certificates are in it, its newest signed tree head, and what
        /// is wrong with it, where something is.
        /// </summary>
        private Task<HTTPResponse> GetTransparencyLog(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var log  = PKI.Store.Transparency;
            var sth  = log.TreeHead();

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("logId",              Convert.ToBase64String(log.LogId)),
                           new JProperty("publicKey",          log.PublicKeyPEM),
                           new JProperty("treeSize",           log.Count),
                           new JProperty("sth",                sth?.ToJSON()),
                           new JProperty("signedAt",           sth is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(sth.Timestamp).ToString("o", CultureInfo.InvariantCulture)),
                           new JProperty("maximumMergeDelay",  0),
                           new JProperty("broken",             log.IsBroken),
                           new JProperty("problems",           new JArray(log.Problems)),
                           new JProperty("directory",          log.Directory)
                       ))
                   );

        }

        #endregion

        #region (private) GetLogEntries(Request)

        /// <summary>
        /// GET /api/v1/pki/transparency/entries?start=&amp;end=: the entries of
        /// the log as the web interface lists them - what each certificate is,
        /// read from the certificate itself, and whether the PKI still has it.
        /// </summary>
        private Task<HTTPResponse> GetLogEntries(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryRange(Request, "start", "end", out var start, out var end, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            var log = PKI.Store.Transparency;

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("treeSize",  log.Count),
                           new JProperty("entries",   new JArray(log.Entries(start, end).Select(EntryJSON)))
                       ))
                   );

        }

        #endregion


        #region (private) GetSTH(Request)

        /// <summary>
        /// GET .../ct/v1/get-sth: the newest signed tree head - and 503 where
        /// the log is broken, which signs none.
        /// </summary>
        private Task<HTTPResponse> GetSTH(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       PKI.Store.Transparency.TreeHead() is SignedTreeHead sth
                           ? JSONResponse(Request, HTTPStatusCode.OK, sth.ToJSON())
                           : Broken(Request)
                   );

        }

        #endregion

        #region (private) GetSTHConsistency(Request)

        /// <summary>
        /// GET .../ct/v1/get-sth-consistency?first=&amp;second=: the proof that
        /// the tree of the first "second" entries grew from the tree of the
        /// first "first".
        /// </summary>
        private Task<HTTPResponse> GetSTHConsistency(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var log = PKI.Store.Transparency;

            if (!TryInt64(Request, "first",  out var first,  out var error) ||
                !TryInt64(Request, "second", out var second, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            if (first < 1 || first > second || second > log.Count)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"'first' is 1 at least and 'second' at most {log.Count}, the size of the log, and no less than 'first'."));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("consistency", Hashes(log.ConsistencyProof(first, second)))
                       ))
                   );

        }

        #endregion

        #region (private) GetProofByHash(Request)

        /// <summary>
        /// GET .../ct/v1/get-proof-by-hash?hash=&amp;tree_size=: where the leaf
        /// of the given hash is, and its audit path in the tree of
        /// "tree_size" entries.
        /// </summary>
        private Task<HTTPResponse> GetProofByHash(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var log = PKI.Store.Transparency;

            if (!TryInt64(Request, "tree_size", out var treeSize, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            if (!TryBase64(Request, "hash", out var hash, out error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            if (treeSize < 1 || treeSize > log.Count)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'tree_size' is 1 at least and {log.Count} at most, the size of the log."));

            if (log.IndexOf(hash) is not Int64 index || index >= treeSize)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"No leaf of this hash is in the tree of {treeSize} entries."));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("leaf_index",  index),
                           new JProperty("audit_path",  Hashes(log.InclusionProof(index, treeSize)))
                       ))
                   );

        }

        #endregion

        #region (private) GetEntries(Request)

        /// <summary>
        /// GET .../ct/v1/get-entries?start=&amp;end=: the entries from "start"
        /// up to and including "end" - as many as there are, and a thousand at
        /// most - each as its leaf and the chain above it.
        /// </summary>
        private Task<HTTPResponse> GetEntries(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryRange(Request, "start", "end", out var start, out var end, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("entries", new JArray(PKI.Store.Transparency.Entries(start, end).Select(entry => new JObject(
                                                        new JProperty("leaf_input",  Convert.ToBase64String(entry.MerkleTreeLeaf)),
                                                        new JProperty("extra_data",  Convert.ToBase64String(entry.ExtraData))
                                                    ))))
                       ))
                   );

        }

        #endregion

        #region (private) GetRoots(Request)

        /// <summary>
        /// GET .../ct/v1/get-roots: the roots the log takes certificates below
        /// - the root CAs of this PKI.
        /// </summary>
        private Task<HTTPResponse> GetRoots(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var roots = new JArray();

            foreach (var root in PKI.Store.Find(null, CertificateProfile.RootCA))
            {
                using var certificate = PKI.Store.Load(root.Id);
                if (certificate is not null)
                    roots.Add(Convert.ToBase64String(certificate.RawData));
            }

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("certificates", roots)
                       ))
                   );

        }

        #endregion

        #region (private) GetEntryAndProof(Request)

        /// <summary>
        /// GET .../ct/v1/get-entry-and-proof?leaf_index=&amp;tree_size=: one
        /// entry, with its audit path in the tree of "tree_size" entries.
        /// </summary>
        private Task<HTTPResponse> GetEntryAndProof(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var log = PKI.Store.Transparency;

            if (!TryInt64(Request, "leaf_index", out var index,    out var error) ||
                !TryInt64(Request, "tree_size",  out var treeSize, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            if (treeSize < 1 || treeSize > log.Count || index < 0 || index >= treeSize)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"'leaf_index' is below 'tree_size', which is {log.Count} at most, the size of the log."));

            var entry = log.Entries(index, index).Single();

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("leaf_input",  Convert.ToBase64String(entry.MerkleTreeLeaf)),
                           new JProperty("extra_data",  Convert.ToBase64String(entry.ExtraData)),
                           new JProperty("audit_path",  Hashes(log.InclusionProof(index, treeSize)))
                       ))
                   );

        }

        #endregion


        #region (private) What the routes of the log share

        /// <summary>
        /// Where a certificate is in the log, and its signed certificate
        /// timestamp: what its details say of the log - or null where the log
        /// does not have it.
        /// </summary>
        private JObject? TransparencyJSON(IssuedCertificate Certificate)

            => PKI.Store.Transparency.Find(Certificate.Id) is LogEntry entry
                   ? new JObject(
                         new JProperty("index",     entry.Index),
                         new JProperty("loggedAt",  entry.LoggedAt.ToString("o", CultureInfo.InvariantCulture)),
                         new JProperty("sct",       entry.SCTJSON(PKI.Store.Transparency.LogId))
                     )
                   : null;

        /// <summary>
        /// One entry, as the web interface lists it.
        /// </summary>
        private JObject EntryJSON(LogEntry Entry)
        {

            using var certificate = X509CertificateLoader.LoadCertificate(Entry.Certificate);

            var kept = PKI.Store.Get(Entry.CertificateId);

            return new JObject(
                       new JProperty("index",       Entry.Index),
                       new JProperty("timestamp",   Entry.Timestamp),
                       new JProperty("loggedAt",    Entry.LoggedAt.ToString("o", CultureInfo.InvariantCulture)),
                       new JProperty("id",          Entry.CertificateId),
                       new JProperty("commonName",  certificate.GetNameInfo(X509NameType.SimpleName, false)),
                       new JProperty("subject",     certificate.Subject),
                       new JProperty("issuer",      certificate.Issuer),
                       new JProperty("profile",     (kept?.Profile ?? ProfileOf(certificate)).AsText()),
                       new JProperty("notAfter",    new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero).ToString("o", CultureInfo.InvariantCulture)),
                       new JProperty("inPKI",       kept is not null),
                       new JProperty("revoked",     PKI.Store.RevocationOf(Entry.CertificateId) is not null),

                       // A responder of a CA is signed by the PKI and in its
                       // log, but kept beside its CA rather than in the store.
                       new JProperty("ocspResponder",
                                                    certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()?.
                                                                EnhancedKeyUsages.OfType<System.Security.Cryptography.Oid>().Any(usage => usage.Value == Revocation.OCSP.OCSPSigningOID) == true)
                   );

        }

        /// <summary>
        /// What a certificate the PKI does not have any more was made as, read
        /// from the certificate: a CA that signed itself, a CA, a server's or a
        /// client's.
        /// </summary>
        private static CertificateProfile ProfileOf(X509Certificate2 Certificate)
        {

            if (Certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority == true)
                return Certificate.SubjectName.RawData.AsSpan().SequenceEqual(Certificate.IssuerName.RawData)
                           ? CertificateProfile.RootCA
                           : CertificateProfile.SubCA;

            return Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()?.
                               EnhancedKeyUsages.OfType<System.Security.Cryptography.Oid>().Any(usage => usage.Value == "1.3.6.1.5.5.7.3.1") == true
                       ? CertificateProfile.Server
                       : CertificateProfile.Client;

        }

        private HTTPResponse Broken(HTTPRequest Request)

            => ErrorJSON(Request, HTTPStatusCode.ServiceUnavailable,
                         $"The transparency log is broken, and signs nothing: {String.Join(" ", PKI.Store.Transparency.Problems)}");

        private static JArray Hashes(IReadOnlyList<Byte[]> Hashes)
            => new (Hashes.Select(Convert.ToBase64String));

        private static Boolean TryInt64(HTTPRequest                       Request,
                                        String                            Name,
                                        out Int64                         Value,
                                        [NotNullWhen(false)] out String?  Error)
        {

            Error = Int64.TryParse(Request.QueryString.GetString(Name), NumberStyles.None, CultureInfo.InvariantCulture, out Value)
                        ? null
                        : $"'{Name}' is a whole number, 0 or more.";

            return Error is null;

        }

        private static Boolean TryRange(HTTPRequest                       Request,
                                        String                            Start,
                                        String                            End,
                                        out Int64                         From,
                                        out Int64                         To,
                                        [NotNullWhen(false)] out String?  Error)
        {

            To = 0;

            if (!TryInt64(Request, Start, out From, out Error) ||
                !TryInt64(Request, End,   out To,   out Error))
            {
                return false;
            }

            Error = To < From ? $"'{End}' is no less than '{Start}'." : null;

            return Error is null;

        }

        private static Boolean TryBase64(HTTPRequest                         Request,
                                         String                              Name,
                                         [NotNullWhen(true)]  out Byte[]?    Value,
                                         [NotNullWhen(false)] out String?    Error)
        {

            Value = null;
            Error = null;

            // A "+" that was not escaped arrives as a space.
            var text = Request.QueryString.GetString(Name)?.Replace(' ', '+');

            try
            {
                Value = Convert.FromBase64String(text ?? "");
                if (Value.Length == 32)
                    return true;
            }
            catch (FormatException)
            { }

            Value = null;
            Error = $"'{Name}' is a SHA-256 hash, in Base64.";
            return false;

        }

        #endregion

    }

}
