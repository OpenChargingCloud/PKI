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

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Transparency
{

    /// <summary>
    /// One certificate in the log: where, since when, what it is, the chain
    /// above it, and the signature of the log over its timestamp - what
    /// together with the log's id is its signed certificate timestamp.
    /// </summary>
    /// <remarks>
    /// An entry of a precertificate is what RFC 6962 calls a precert_entry:
    /// its leaf is the precertificate's TBSCertificate without its poison and
    /// the hash of its CA's key, and the timestamp signed is the one the
    /// certificate carries. The certificate itself is kept beside it, as
    /// what the PKI signed once the log had signed - and is what the entry
    /// is found by.
    /// </remarks>
    /// <param name="Index">Where it is in the log, from 0.</param>
    /// <param name="Timestamp">When the log took it in, in milliseconds since 1970, as RFC 6962 counts.</param>
    /// <param name="CertificateId">Its SHA-256 fingerprint, as the store names it.</param>
    /// <param name="Certificate">The certificate, DER.</param>
    /// <param name="Chain">The CAs above it up to its root, DER; none for a root.</param>
    /// <param name="Signature">The log's signature over its timestamp, as the DigitallySigned of RFC 5246.</param>
    /// <param name="PreCertificate">The precertificate the timestamp was signed for, DER; null where the certificate itself was.</param>
    public sealed record LogEntry(Int64                  Index,
                                  Int64                  Timestamp,
                                  String                 CertificateId,
                                  Byte[]                 Certificate,
                                  IReadOnlyList<Byte[]>  Chain,
                                  Byte[]                 Signature,
                                  Byte[]?                PreCertificate = null)
    {

        /// <summary>
        /// When the log took it in.
        /// </summary>
        public DateTimeOffset LoggedAt
            => DateTimeOffset.FromUnixTimeMilliseconds(Timestamp);

        /// <summary>
        /// Whether the log signed a precertificate, whose timestamp the
        /// certificate carries.
        /// </summary>
        public Boolean IsPrecertificate
            => PreCertificate is not null;

        /// <summary>
        /// What the log signed of a precertificate: its TBSCertificate without
        /// the poison.
        /// </summary>
        public Byte[] PrecertificateTBS
            => Precertificate.TBSWithout(PreCertificate ?? throw new InvalidOperationException("No precertificate was logged."), Precertificate.PoisonOID);

        /// <summary>
        /// The MerkleTreeLeaf of RFC 6962 - what is hashed into the tree, and
        /// what "leaf_input" of get-entries is.
        /// </summary>
        public Byte[] MerkleTreeLeaf
            => IsPrecertificate
                   ? TLS.PrecertMerkleTreeLeaf(Timestamp, Precertificate.IssuerKeyHash(Chain[0]), PrecertificateTBS)
                   : TLS.MerkleTreeLeaf(Timestamp, Certificate);

        /// <summary>
        /// What the log signed: the input of its signed certificate timestamp.
        /// </summary>
        public Byte[] SignatureInput
            => IsPrecertificate
                   ? TLS.PrecertTimestampInput(Timestamp, Precertificate.IssuerKeyHash(Chain[0]), PrecertificateTBS)
                   : TLS.CertificateTimestampInput(Timestamp, Certificate);

        /// <summary>
        /// The hash of its leaf in the tree.
        /// </summary>
        public Byte[] LeafHash
            => MerkleTree.LeafHash(MerkleTreeLeaf);

        /// <summary>
        /// The chain above it, as "extra_data" of get-entries is: an
        /// X509ChainEntry, or a PrecertChainEntry.
        /// </summary>
        public Byte[] ExtraData
            => IsPrecertificate
                   ? TLS.PrecertChainEntry(PreCertificate!, Chain)
                   : TLS.CertificateChain(Chain);

        /// <summary>
        /// The signed certificate timestamp, as TLS writes it - as a
        /// certificate carries it.
        /// </summary>
        public Byte[] SerializedSCT(Byte[] LogId)
            => TLS.SerializedSCT(LogId, Timestamp, Signature);

        /// <summary>
        /// The signed certificate timestamp, as add-chain of RFC 6962 answers
        /// it.
        /// </summary>
        public JObject SCTJSON(Byte[] LogId)

            => new (
                   new JProperty("sct_version",  0),
                   new JProperty("id",           Convert.ToBase64String(LogId)),
                   new JProperty("timestamp",    Timestamp),
                   new JProperty("extensions",   ""),
                   new JProperty("signature",    Convert.ToBase64String(Signature))
               );

    }


    /// <summary>
    /// A signed tree head: how many certificates the log had, the hash of
    /// the tree of them, when, and the log's signature over the three.
    /// </summary>
    public sealed record SignedTreeHead(Int64   TreeSize,
                                        Int64   Timestamp,
                                        Byte[]  RootHash,
                                        Byte[]  Signature)
    {

        /// <summary>
        /// As get-sth of RFC 6962 answers it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("tree_size",            TreeSize),
                   new JProperty("timestamp",            Timestamp),
                   new JProperty("sha256_root_hash",     Convert.ToBase64String(RootHash)),
                   new JProperty("tree_head_signature",  Convert.ToBase64String(Signature))
               );

        public static SignedTreeHead? TryParse(JToken? JSON)
        {
            try
            {
                return JSON is JObject json
                           ? new SignedTreeHead(json.Value<Int64>("tree_size"),
                                                json.Value<Int64>("timestamp"),
                                                Convert.FromBase64String(json.Value<String>("sha256_root_hash")!),
                                                Convert.FromBase64String(json.Value<String>("tree_head_signature")!))
                           : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

    }


    /// <summary>
    /// The certificate transparency log of a PKI, after RFC 6962: every
    /// certificate it signs, in the order it signed them, in a Merkle tree
    /// the log signs the head of - so that whoever keeps a signed tree head
    /// can ask for proof that a certificate is in the log, and that the log
    /// they see now is the one they saw then, grown and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A directory - "transparency" in the store's - with the log's key,
    /// "log-key.pem", an ECDSA key of P-256 as RFC 6962 has a log sign
    /// with; "entries.jsonl", one line per certificate, only ever appended
    /// to; and "sth.json", the newest tree head it signed.
    /// </para>
    /// <para>
    /// Nothing is ever taken out of it: a certificate deleted from the PKI
    /// is still in its log, which is the point of one. Whoever can write
    /// the directory can still change it - but not without every tree head
    /// signed before saying so: the log checks itself against the newest
    /// one at every start, and every signature in it, and signs nothing
    /// more where they do not hold. A log that is broken stops the PKI from
    /// signing, rather than leave out of the log what it signs.
    /// </para>
    /// <para>
    /// A certificate is in the tree as soon as it is in the log: its maximum
    /// merge delay is none.
    /// </para>
    /// </remarks>
    public sealed class TransparencyLog
    {

        #region Data

        public const  String  KeyFileName      = "log-key.pem";
        public const  String  EntriesFileName  = "entries.jsonl";
        public const  String  TreeHeadFileName = "sth.json";

        /// <summary>
        /// How many entries get-entries hands out at once at most.
        /// </summary>
        public const  Int32   MaxEntriesAtOnce = 1000;

        private readonly  Object                          gate        = new();
        private readonly  ECDsa                           key;
        private readonly  List<LogEntry>                  entries     = [];
        private readonly  List<Byte[]>                    leafHashes  = [];
        private readonly  Dictionary<String, LogEntry>    byId        = new (StringComparer.OrdinalIgnoreCase);
        private readonly  Dictionary<String, Int64>       byLeafHash  = new (StringComparer.Ordinal);
        private readonly  List<String>                    problems    = [];
        private readonly  TimeProvider                    timeProvider;

        private           SignedTreeHead?                 treeHead;

        #endregion

        #region Properties

        /// <summary>
        /// Where the log is.
        /// </summary>
        public String                 Directory      { get; }

        /// <summary>
        /// The public key of the log, as its SubjectPublicKeyInfo, DER.
        /// </summary>
        public Byte[]                 PublicKey      { get; }

        /// <summary>
        /// The public key of the log, as PEM: what a monitor is told to check
        /// its signatures with.
        /// </summary>
        public String                 PublicKeyPEM
            => PemEncoding.WriteString("PUBLIC KEY", PublicKey);

        /// <summary>
        /// The id of the log: SHA-256 of its public key.
        /// </summary>
        public Byte[]                 LogId          { get; }

        /// <summary>
        /// Whether the log was made at this start.
        /// </summary>
        public Boolean                IsNew          { get; }

        /// <summary>
        /// What is wrong with the log, each said in a sentence - none, where
        /// it is fine.
        /// </summary>
        public IReadOnlyList<String>  Problems
        {
            get
            {
                lock (gate)
                    return problems.ToList();
            }
        }

        /// <summary>
        /// Whether the log is broken: what it says does not hold, and it takes
        /// in nothing more.
        /// </summary>
        public Boolean                IsBroken       { get; private set; }

        /// <summary>
        /// How many certificates are in it.
        /// </summary>
        public Int64 Count
        {
            get
            {
                lock (gate)
                    return entries.Count;
            }
        }

        private String KeyFile        => Path.Combine(Directory, KeyFileName);
        private String EntriesFile    => Path.Combine(Directory, EntriesFileName);
        private String TreeHeadFile   => Path.Combine(Directory, TreeHeadFileName);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The log in the given directory, made - with a key of its own - where
        /// there is none yet, and checked where there is.
        /// </summary>
        public TransparencyLog(String         Directory,
                               TimeProvider?  TimeProvider   = null)
        {

            this.Directory     = Path.GetFullPath(Directory);
            this.timeProvider  = TimeProvider ?? TimeProvider.System;

            System.IO.Directory.CreateDirectory(this.Directory);

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(this.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            #region Its key

            key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            if (File.Exists(KeyFile))
            {
                try
                {
                    key.ImportFromPem(File.ReadAllText(KeyFile));
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException($"The key of the transparency log, '{KeyFile}', could not be read: {e.Message}");
                }
            }
            else
            {

                if (File.Exists(EntriesFile))
                    throw new InvalidOperationException($"The transparency log in '{this.Directory}' has entries and no key '{KeyFileName}': " +
                                                        "a new key would be a different log. Put its key back.");

                WritePrivately(KeyFile, key.ExportPkcs8PrivateKeyPem() + "\n");
                IsNew = true;

            }

            PublicKey  = key.ExportSubjectPublicKeyInfo();
            LogId      = SHA256.HashData(PublicKey);

            #endregion

            Load();

        }

        #endregion


        #region Reading

        /// <summary>
        /// The entry of a certificate, or null where it is not in the log.
        /// </summary>
        public LogEntry? Find(String CertificateId)
        {
            lock (gate)
                return byId.TryGetValue(CertificateId, out var entry) ? entry : null;
        }

        /// <summary>
        /// The entries from <paramref name="Start"/> up to and including
        /// <paramref name="End"/>, as many of them as there are - and at most
        /// <see cref="MaxEntriesAtOnce"/>.
        /// </summary>
        public IReadOnlyList<LogEntry> Entries(Int64 Start, Int64 End)
        {

            lock (gate)
            {

                if (Start < 0 || Start >= entries.Count || End < Start)
                    return [];

                var last = Math.Min(Math.Min(End, entries.Count - 1), Start + MaxEntriesAtOnce - 1);

                return entries.GetRange((Int32) Start, (Int32) (last - Start + 1));

            }

        }

        /// <summary>
        /// Where the leaf of the given hash is, or null where none is.
        /// </summary>
        public Int64? IndexOf(Byte[] LeafHash)
        {
            lock (gate)
                return byLeafHash.TryGetValue(Convert.ToHexString(LeafHash), out var index) ? index : null;
        }

        /// <summary>
        /// The hash of the tree of the first <paramref name="TreeSize"/>
        /// entries.
        /// </summary>
        public Byte[] RootHash(Int64 TreeSize)
        {
            lock (gate)
                return MerkleTree.RootHash(leafHashes, Checked(TreeSize));
        }

        /// <summary>
        /// The audit path of the entry at <paramref name="Index"/> in the tree
        /// of the first <paramref name="TreeSize"/> entries.
        /// </summary>
        public IReadOnlyList<Byte[]> InclusionProof(Int64 Index, Int64 TreeSize)
        {
            lock (gate)
                return MerkleTree.InclusionProof(leafHashes, (Int32) Index, Checked(TreeSize));
        }

        /// <summary>
        /// The proof that the tree of <paramref name="Second"/> entries grew
        /// from the tree of <paramref name="First"/>.
        /// </summary>
        public IReadOnlyList<Byte[]> ConsistencyProof(Int64 First, Int64 Second)
        {
            lock (gate)
                return MerkleTree.ConsistencyProof(leafHashes, (Int32) First, Checked(Second));
        }

        #endregion

        #region TreeHead()

        /// <summary>
        /// The head of the tree as it is now, signed: the newest one signed,
        /// where nothing came in since - a new one, and kept, where something
        /// did. None where the log is broken: it signs nothing it cannot stand
        /// by.
        /// </summary>
        public SignedTreeHead? TreeHead()
        {

            lock (gate)
            {

                if (IsBroken)
                    return null;

                if (treeHead is not null && treeHead.TreeSize == entries.Count)
                    return treeHead;

                // Never before what is in it, whatever the clock says now.
                var timestamp  = Math.Max(timeProvider.GetUtcNow().ToUnixTimeMilliseconds(), entries.Count > 0 ? entries[^1].Timestamp : 0);
                timestamp      = Math.Max(timestamp, treeHead?.Timestamp ?? 0);

                var rootHash   = MerkleTree.RootHash(leafHashes, entries.Count);
                var signed     = new SignedTreeHead(entries.Count, timestamp, rootHash, Sign(TLS.TreeHeadSignatureInput(timestamp, entries.Count, rootHash)));

                try
                {
                    var temporary = TreeHeadFile + ".tmp";
                    File.WriteAllText(temporary, signed.ToJSON().ToString(Formatting.Indented));
                    File.Move(temporary, TreeHeadFile, overwrite: true);
                }
                catch (Exception e)
                {
                    // Said, and signed all the same: a tree head is true
                    // whether it is kept or not, and the next start checks
                    // the log against the one kept before.
                    problems.Add($"The newest tree head could not be written to '{TreeHeadFile}': {e.Message}");
                }

                treeHead = signed;
                return signed;

            }

        }

        #endregion

        #region TryAppend(Certificate, Chain, out Entry, out Error)

        /// <summary>
        /// Take a certificate in, with the chain above it, and sign when -
        /// written to the disk before it is said to be in, and nothing taken in
        /// where the log is broken.
        /// </summary>
        public Boolean TryAppend(X509Certificate2                          Certificate,
                                 IReadOnlyList<X509Certificate2>           Chain,
                                 [NotNullWhen(true)]  out LogEntry?        Entry,
                                 [NotNullWhen(false)] out String?          Error)
        {

            Entry = null;
            Error = null;

            var id = Certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

            lock (gate)
            {

                if (IsBroken)
                {
                    Error = $"The transparency log in '{Directory}' is broken, and takes in nothing until it is repaired: {String.Join(" ", problems)}";
                    return false;
                }

                if (byId.TryGetValue(id, out var already))
                {
                    Entry = already;
                    return true;
                }

                var der        = Certificate.RawData;
                var timestamp  = Math.Max(timeProvider.GetUtcNow().ToUnixTimeMilliseconds(), entries.Count > 0 ? entries[^1].Timestamp : 0);
                var entry      = new LogEntry(
                                     Index:          entries.Count,
                                     Timestamp:      timestamp,
                                     CertificateId:  id,
                                     Certificate:    der,
                                     Chain:          Chain.Select(one => one.RawData).ToList(),
                                     Signature:      Sign(TLS.CertificateTimestampInput(timestamp, der))
                                 );

                try
                {
                    using var file = new FileStream(EntriesFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                    var line       = Encoding.UTF8.GetBytes(ToJSON(entry).ToString(Formatting.None) + "\n");
                    file.Write(line);
                    file.Flush(flushToDisk: true);
                }
                catch (Exception e)
                {
                    Error = $"The certificate could not be written to the transparency log '{EntriesFile}': {e.Message}";
                    return false;
                }

                Add(entry);

                Entry = entry;
                return true;

            }

        }

        #endregion

        #region TryAppendPrecertificate(PreCertificate, Chain, Finish, out Certificate, out Entry, out Error)

        /// <summary>
        /// Take a precertificate in, sign its timestamp, and have the
        /// certificate made with it - which is kept in the log beside the
        /// precertificate, and found by. All of it under the log's lock: no
        /// entry comes between the timestamp and the line written, and a
        /// certificate the log could not write is never handed out.
        /// </summary>
        /// <param name="PreCertificate">The precertificate: the certificate to be, with the poison.</param>
        /// <param name="Chain">The CAs above it up to its root; the first of them signed it.</param>
        /// <param name="Finish">What makes the certificate, given its signed certificate timestamp as TLS writes it.</param>
        public Boolean TryAppendPrecertificate(X509Certificate2                                  PreCertificate,
                                               IReadOnlyList<X509Certificate2>                   Chain,
                                               Func<Byte[], X509Certificate2>                    Finish,
                                               [NotNullWhen(true)]  out X509Certificate2?        Certificate,
                                               [NotNullWhen(true)]  out LogEntry?                Entry,
                                               [NotNullWhen(false)] out String?                  Error)
        {

            Certificate  = null;
            Entry        = null;
            Error        = null;

            if (Chain.Count == 0)
            {
                Error = "A precertificate is signed by a CA, and none was given.";
                return false;
            }

            if (!Precertificate.IsPoisoned(PreCertificate))
            {
                Error = "A precertificate carries the poison extension, critical; this one does not.";
                return false;
            }

            var tbs            = Precertificate.TBSWithout(PreCertificate.RawData, Precertificate.PoisonOID);
            var issuerKeyHash  = Precertificate.IssuerKeyHash(Chain[0]);

            lock (gate)
            {

                if (IsBroken)
                {
                    Error = $"The transparency log in '{Directory}' is broken, and takes in nothing until it is repaired: {String.Join(" ", problems)}";
                    return false;
                }

                var timestamp  = Math.Max(timeProvider.GetUtcNow().ToUnixTimeMilliseconds(), entries.Count > 0 ? entries[^1].Timestamp : 0);
                var signature  = Sign(TLS.PrecertTimestampInput(timestamp, issuerKeyHash, tbs));

                X509Certificate2 certificate;

                try
                {
                    certificate = Finish(TLS.SerializedSCT(LogId, timestamp, signature));
                }
                catch (Exception e)
                {
                    Error = $"The certificate could not be made with its signed certificate timestamp: {e.Message}";
                    return false;
                }

                // What the log signed has to be what the certificate is, but
                // for its timestamps: where it is not, the timestamp it
                // carries holds for nothing.
                if (!Precertificate.TBSWithout(certificate.RawData, Precertificate.SCTListOID).AsSpan().SequenceEqual(tbs))
                {
                    certificate.Dispose();
                    Error = "The certificate is not what its precertificate said it would be, and was not kept.";
                    return false;
                }

                var id = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

                if (byId.ContainsKey(id))
                {
                    certificate.Dispose();
                    Error = $"The log has the certificate {id} already.";
                    return false;
                }

                var entry = new LogEntry(
                                Index:           entries.Count,
                                Timestamp:       timestamp,
                                CertificateId:   id,
                                Certificate:     certificate.RawData,
                                Chain:           Chain.Select(one => one.RawData).ToList(),
                                Signature:       signature,
                                PreCertificate:  PreCertificate.RawData
                            );

                try
                {
                    using var file = new FileStream(EntriesFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                    var line       = Encoding.UTF8.GetBytes(ToJSON(entry).ToString(Formatting.None) + "\n");
                    file.Write(line);
                    file.Flush(flushToDisk: true);
                }
                catch (Exception e)
                {
                    certificate.Dispose();
                    Error = $"The precertificate could not be written to the transparency log '{EntriesFile}': {e.Message}";
                    return false;
                }

                Add(entry);

                Certificate  = certificate;
                Entry        = entry;
                return true;

            }

        }

        #endregion

        #region Verifying

        /// <summary>
        /// Whether the log's signature over the timestamp of an entry holds.
        /// </summary>
        public Boolean Verify(LogEntry Entry)

            => Verify(Entry.SignatureInput, Entry.Signature);

        /// <summary>
        /// Whether a signed certificate timestamp a certificate carries is one
        /// of this log, and holds for the certificate - signed by its CA, the
        /// given one: checked as whoever reads the certificate checks it,
        /// from the certificate alone.
        /// </summary>
        public Boolean Verify(SignedCertificateTimestamp  SCT,
                              X509Certificate2            Certificate,
                              X509Certificate2            Issuer)

            => SCT.LogId.AsSpan().SequenceEqual(LogId) &&
               Verify(TLS.PrecertTimestampInput(SCT.Timestamp,
                                                Precertificate.IssuerKeyHash(Issuer),
                                                Precertificate.TBSWithout(Certificate.RawData, Precertificate.SCTListOID)),
                      SCT.Signature);

        /// <summary>
        /// Whether the log's signature over a tree head holds.
        /// </summary>
        public Boolean Verify(SignedTreeHead TreeHead)

            => Verify(TLS.TreeHeadSignatureInput(TreeHead.Timestamp, TreeHead.TreeSize, TreeHead.RootHash), TreeHead.Signature);

        private Boolean Verify(Byte[] Input, Byte[] DigitallySigned)
            => TLS.TryReadDigitallySigned(DigitallySigned, out var signature) &&
               key.VerifyData(Input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        #endregion


        #region (private) Load()

        /// <summary>
        /// Every entry, each checked: where it is, and its signature - and the
        /// tree of them against the newest tree head signed.
        /// </summary>
        private void Load()
        {

            if (File.Exists(EntriesFile))
            {

                var bytes = File.ReadAllBytes(EntriesFile);

                // A process that died mid-write leaves half a line at the end:
                // a certificate it never said was in, and never kept.
                var end = Array.LastIndexOf(bytes, (Byte) '\n') + 1;

                if (end < bytes.Length)
                {
                    try
                    {
                        using var file = new FileStream(EntriesFile, FileMode.Open, FileAccess.Write);
                        file.SetLength(end);
                        problems.Add($"Half an entry at the end of '{EntriesFile}', written when the PKI stopped, was cut off.");
                    }
                    catch (Exception e)
                    {
                        Break($"Half an entry at the end of '{EntriesFile}' could not be cut off: {e.Message}");
                    }
                }

                var number = 0;

                foreach (var line in Encoding.UTF8.GetString(bytes, 0, end).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {

                    number++;

                    var entry = TryParse(line);

                    if (entry is null)
                    {
                        Break($"Line {number} of '{EntriesFile}' is no entry of the log.");
                        break;
                    }

                    if (entry.Index != entries.Count)
                    {
                        Break($"Line {number} of '{EntriesFile}' says it is entry {entry.Index}, where entry {entries.Count} belongs.");
                        break;
                    }

                    if (!Verify(entry))
                    {
                        Break($"The signature of entry {entry.Index} of '{EntriesFile}' does not hold: it is not what the log signed.");
                        break;
                    }

                    Add(entry);

                }

            }

            if (File.Exists(TreeHeadFile))
            {

                SignedTreeHead? kept = null;

                try
                {
                    kept = SignedTreeHead.TryParse(JObject.Parse(File.ReadAllText(TreeHeadFile)));
                }
                catch (Exception)
                { }

                if (kept is null)
                    Break($"The newest tree head, '{TreeHeadFile}', could not be read.");

                else if (!Verify(kept))
                    Break($"The signature of the newest tree head, '{TreeHeadFile}', does not hold.");

                else if (kept.TreeSize > entries.Count)
                    Break($"The log signed a tree of {kept.TreeSize} entries, and has {entries.Count}: entries were taken out of it.");

                else if (!MerkleTree.RootHash(leafHashes, (Int32) kept.TreeSize).AsSpan().SequenceEqual(kept.RootHash))
                    Break($"The first {kept.TreeSize} entries are not what the log signed the tree of: they were changed.");

                else
                    treeHead = kept;

            }

        }

        #endregion

        #region (private) Add(Entry) / Break(Problem) / Sign(Input)

        private void Add(LogEntry Entry)
        {

            var leafHash = Entry.LeafHash;

            entries.   Add(Entry);
            leafHashes.Add(leafHash);

            byId[Entry.CertificateId]                    = Entry;
            byLeafHash[Convert.ToHexString(leafHash)]   = Entry.Index;

        }

        private void Break(String Problem)
        {
            problems.Add(Problem);
            IsBroken = true;
        }

        private Byte[] Sign(Byte[] Input)

            => TLS.DigitallySigned(key.SignData(Input, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

        private Int32 Checked(Int64 TreeSize)
        {
            if (TreeSize < 0 || TreeSize > entries.Count)
                throw new ArgumentOutOfRangeException(nameof(TreeSize), $"The log has {entries.Count} entries, and no tree of {TreeSize}.");
            return (Int32) TreeSize;
        }

        #endregion

        #region (private static) An entry as a line, and back

        private static JObject ToJSON(LogEntry Entry)
        {

            var json = new JObject(
                           new JProperty("index",          Entry.Index),
                           new JProperty("timestamp",      Entry.Timestamp),
                           new JProperty("id",             Entry.CertificateId),
                           new JProperty("certificate",    Convert.ToBase64String(Entry.Certificate)),
                           new JProperty("chain",          new JArray(Entry.Chain.Select(Convert.ToBase64String))),
                           new JProperty("signature",      Convert.ToBase64String(Entry.Signature))
                       );

            if (Entry.PreCertificate is not null)
                json.Add(new JProperty("precertificate", Convert.ToBase64String(Entry.PreCertificate)));

            return json;

        }

        private static LogEntry? TryParse(String Line)
        {
            try
            {

                var json = JObject.Parse(Line);

                return new LogEntry(
                           Index:           json.Value<Int64>("index"),
                           Timestamp:       json.Value<Int64>("timestamp"),
                           CertificateId:   json.Value<String>("id")!.ToLowerInvariant(),
                           Certificate:     Convert.FromBase64String(json.Value<String>("certificate")!),
                           Chain:           json["chain"]!.Values<String>().Select(one => Convert.FromBase64String(one!)).ToList(),
                           Signature:       Convert.FromBase64String(json.Value<String>("signature")!),
                           PreCertificate:  json.Value<String>("precertificate") is String precertificate
                                                ? Convert.FromBase64String(precertificate)
                                                : null
                       );

            }
            catch (Exception)
            {
                return null;
            }
        }

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

        #endregion

    }


    /// <summary>
    /// The structures of RFC 6962 as TLS writes them - RFC 5246, section 4:
    /// numbers big-endian, and every variable length preceded by its length
    /// in as many bytes as its largest could need.
    /// </summary>
    public static class TLS
    {

        private const Byte  Version_V1                   = 0;
        private const Byte  SignatureType_Certificate    = 0;
        private const Byte  SignatureType_TreeHash       = 1;
        private const Byte  LeafType_TimestampedEntry    = 0;
        private const Byte  HashAlgorithm_SHA256         = 4;
        private const Byte  SignatureAlgorithm_ECDSA     = 3;
        private const UInt16 EntryType_Precert           = 1;

        /// <summary>
        /// MerkleTreeLeaf of a precertificate: version, leaf type, and the
        /// TimestampedEntry of a PreCert - its timestamp, its entry type, the
        /// hash of its CA's key, its TBSCertificate without the poison, and no
        /// extensions.
        /// </summary>
        public static Byte[] PrecertMerkleTreeLeaf(Int64 Timestamp, Byte[] IssuerKeyHash, Byte[] TBSCertificate)
        {

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.WriteByte(LeafType_TimestampedEntry);
            WritePreCert(output, Timestamp, IssuerKeyHash, TBSCertificate);

            return output.ToArray();

        }

        /// <summary>
        /// What the log signs of a precertificate: version, signature type, its
        /// timestamp, entry type, the hash of its CA's key, its TBSCertificate
        /// without the poison, and no extensions.
        /// </summary>
        public static Byte[] PrecertTimestampInput(Int64 Timestamp, Byte[] IssuerKeyHash, Byte[] TBSCertificate)
        {

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.WriteByte(SignatureType_Certificate);
            WritePreCert(output, Timestamp, IssuerKeyHash, TBSCertificate);

            return output.ToArray();

        }

        private static void WritePreCert(Stream Output, Int64 Timestamp, Byte[] IssuerKeyHash, Byte[] TBSCertificate)
        {

            if (IssuerKeyHash.Length != 32)
                throw new ArgumentException("The hash of a CA's key is SHA-256: 32 bytes.", nameof(IssuerKeyHash));

            WriteUInt64 (Output, (UInt64) Timestamp);
            WriteUInt16 (Output, EntryType_Precert);
            Output.Write(IssuerKeyHash);
            WriteOpaque24(Output, TBSCertificate);
            WriteUInt16 (Output, 0);                    // no extensions

        }

        /// <summary>
        /// PrecertChainEntry: the precertificate, and the chain above it.
        /// </summary>
        public static Byte[] PrecertChainEntry(Byte[] PreCertificate, IReadOnlyList<Byte[]> Chain)
        {

            using var output = new MemoryStream();

            WriteOpaque24(output, PreCertificate);
            output.Write(CertificateChain(Chain));

            return output.ToArray();

        }

        /// <summary>
        /// SignedCertificateTimestamp: version, the log's id, the timestamp, no
        /// extensions, and the DigitallySigned of the log.
        /// </summary>
        public static Byte[] SerializedSCT(Byte[] LogId, Int64 Timestamp, Byte[] DigitallySigned)
        {

            if (LogId.Length != 32)
                throw new ArgumentException("The id of a log is SHA-256 of its key: 32 bytes.", nameof(LogId));

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.Write(LogId);
            WriteUInt64(output, (UInt64) Timestamp);
            WriteUInt16(output, 0);                     // no extensions
            output.Write(DigitallySigned);

            return output.ToArray();

        }

        /// <summary>
        /// SignedCertificateTimestampList: every timestamp after its length in
        /// two bytes, and all of them after theirs.
        /// </summary>
        public static Byte[] SCTList(IEnumerable<Byte[]> SerializedSCTs)
        {

            using var list = new MemoryStream();

            foreach (var sct in SerializedSCTs)
            {
                WriteUInt16(list, checked((UInt16) sct.Length));
                list.Write(sct);
            }

            using var output = new MemoryStream();

            WriteUInt16(output, checked((UInt16) list.Length));
            list.WriteTo(output);

            return output.ToArray();

        }

        /// <summary>
        /// The timestamps of a SignedCertificateTimestampList - those of
        /// version 1; others are passed over.
        /// </summary>
        public static IReadOnlyList<SignedCertificateTimestamp> ReadSCTList(ReadOnlySpan<Byte> List)
        {

            var scts = new List<SignedCertificateTimestamp>();

            if (List.Length < 2 || BinaryPrimitives.ReadUInt16BigEndian(List) != List.Length - 2)
                throw new FormatException("This is no list of signed certificate timestamps.");

            var rest = List[2..];

            while (rest.Length > 0)
            {

                var length = BinaryPrimitives.ReadUInt16BigEndian(rest);
                var sct    = rest.Slice(2, length);
                rest       = rest[(2 + length)..];

                if (sct[0] != Version_V1)
                    continue;

                var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(sct[41..]);

                scts.Add(new SignedCertificateTimestamp(
                             LogId:       sct.Slice(1, 32).ToArray(),
                             Timestamp:   (Int64) BinaryPrimitives.ReadUInt64BigEndian(sct[33..]),
                             Extensions:  sct.Slice(43, extensionsLength).ToArray(),
                             Signature:   sct[(43 + extensionsLength)..].ToArray()
                         ));

            }

            return scts;

        }

        /// <summary>
        /// MerkleTreeLeaf: version, leaf type, and the TimestampedEntry of an
        /// X.509 certificate - its timestamp, its entry type, the certificate
        /// and no extensions.
        /// </summary>
        public static Byte[] MerkleTreeLeaf(Int64 Timestamp, Byte[] Certificate)
        {

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.WriteByte(LeafType_TimestampedEntry);
            WriteUInt64 (output, (UInt64) Timestamp);
            WriteUInt16 (output, 0);                    // x509_entry
            WriteOpaque24(output, Certificate);
            WriteUInt16 (output, 0);                    // no extensions

            return output.ToArray();

        }

        /// <summary>
        /// What the log signs of a certificate: version, signature type, its
        /// timestamp, entry type, the certificate and no extensions.
        /// </summary>
        public static Byte[] CertificateTimestampInput(Int64 Timestamp, Byte[] Certificate)
        {

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.WriteByte(SignatureType_Certificate);
            WriteUInt64 (output, (UInt64) Timestamp);
            WriteUInt16 (output, 0);                    // x509_entry
            WriteOpaque24(output, Certificate);
            WriteUInt16 (output, 0);                    // no extensions

            return output.ToArray();

        }

        /// <summary>
        /// What the log signs of a tree head: version, signature type, its
        /// timestamp, its size and the hash of its tree.
        /// </summary>
        public static Byte[] TreeHeadSignatureInput(Int64 Timestamp, Int64 TreeSize, Byte[] RootHash)
        {

            using var output = new MemoryStream();

            output.WriteByte(Version_V1);
            output.WriteByte(SignatureType_TreeHash);
            WriteUInt64(output, (UInt64) Timestamp);
            WriteUInt64(output, (UInt64) TreeSize);
            output.Write(RootHash);

            return output.ToArray();

        }

        /// <summary>
        /// A chain of certificates: their lengths together in three bytes, and
        /// each of them after its own.
        /// </summary>
        public static Byte[] CertificateChain(IReadOnlyList<Byte[]> Chain)
        {

            using var certificates = new MemoryStream();

            foreach (var certificate in Chain)
                WriteOpaque24(certificates, certificate);

            using var output = new MemoryStream();

            WriteOpaque24(output, certificates.ToArray());

            return output.ToArray();

        }

        /// <summary>
        /// DigitallySigned: SHA-256, ECDSA, and the signature after its length.
        /// </summary>
        public static Byte[] DigitallySigned(Byte[] Signature)
        {

            var output = new Byte[4 + Signature.Length];

            output[0] = HashAlgorithm_SHA256;
            output[1] = SignatureAlgorithm_ECDSA;
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(2), (UInt16) Signature.Length);
            Signature.CopyTo(output, 4);

            return output;

        }

        /// <summary>
        /// The signature in a DigitallySigned of SHA-256 and ECDSA - and false
        /// for anything else.
        /// </summary>
        public static Boolean TryReadDigitallySigned(Byte[] DigitallySigned, [NotNullWhen(true)] out Byte[]? Signature)
        {

            Signature = null;

            if (DigitallySigned.Length < 4 ||
                DigitallySigned[0] != HashAlgorithm_SHA256 ||
                DigitallySigned[1] != SignatureAlgorithm_ECDSA ||
                BinaryPrimitives.ReadUInt16BigEndian(DigitallySigned.AsSpan(2)) != DigitallySigned.Length - 4)
            {
                return false;
            }

            Signature = DigitallySigned[4..];
            return true;

        }

        private static void WriteUInt16(Stream Output, UInt16 Value)
        {
            Span<Byte> bytes = stackalloc Byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(bytes, Value);
            Output.Write(bytes);
        }

        private static void WriteUInt64(Stream Output, UInt64 Value)
        {
            Span<Byte> bytes = stackalloc Byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(bytes, Value);
            Output.Write(bytes);
        }

        private static void WriteOpaque24(Stream Output, Byte[] Value)
        {

            if (Value.Length > 0xFFFFFF)
                throw new ArgumentException("Longer than three bytes can say.", nameof(Value));

            Output.WriteByte((Byte) (Value.Length >> 16));
            Output.WriteByte((Byte) (Value.Length >>  8));
            Output.WriteByte((Byte)  Value.Length);
            Output.Write(Value);

        }

    }

}
