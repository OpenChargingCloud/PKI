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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Transparency;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The certificate transparency log: its Merkle tree against the test
    /// vectors of RFC 6962's reference implementation, every proof of every
    /// tree up to a size checked as RFC 9162 checks one, what the log signs
    /// written out byte for byte here rather than taken from the log - and
    /// what it makes of a directory somebody changed.
    /// </summary>
    public class TransparencyLogTests
    {

        #region Data

        private String  directory  = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-ct-" + Guid.NewGuid().ToString("N")[..12]);
        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }
        }

        #endregion


        #region (helpers)

        /// <summary>
        /// The leaves of the tests of RFC 6962's reference implementation, and
        /// the hash of the tree of the first one, two, ... eight of them.
        /// </summary>
        private static readonly String[] Leaves = [ "", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f" ];

        private static readonly String[] Roots  = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
        ];

        private static List<Byte[]> LeafHashes(Int32 Count)
            => Enumerable.Range(0, Count).Select(i => MerkleTree.LeafHash(BitConverter.GetBytes(i))).ToList();

        private static X509Certificate2 ACertificate(String CommonName)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new CertificateRequest($"CN={CommonName}", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        private LogEntry Append(TransparencyLog Log, String CommonName)
        {
            using var certificate = ACertificate(CommonName);
            Assert.That(Log.TryAppend(certificate, [], out var entry, out var error), Is.True, error);
            return entry!;
        }

        /// <summary>
        /// The log's public key, read from its PEM as a monitor reads it.
        /// </summary>
        private static ECDsa PublicKeyOf(TransparencyLog Log)
        {
            var key = ECDsa.Create();
            key.ImportFromPem(Log.PublicKeyPEM);
            return key;
        }

        /// <summary>
        /// The signature in a DigitallySigned, after checking it says SHA-256
        /// and ECDSA.
        /// </summary>
        private static Byte[] SignatureIn(Byte[] DigitallySigned)
        {
            Assert.That(DigitallySigned[0],                                            Is.EqualTo(4), "SHA-256");
            Assert.That(DigitallySigned[1],                                            Is.EqualTo(3), "ECDSA");
            Assert.That(BinaryPrimitives.ReadUInt16BigEndian(DigitallySigned.AsSpan(2)), Is.EqualTo(DigitallySigned.Length - 4));
            return DigitallySigned[4..];
        }

        private static Byte[] UInt64(Int64 Value)
        {
            var bytes = new Byte[8];
            BinaryPrimitives.WriteInt64BigEndian(bytes, Value);
            return bytes;
        }

        private static Byte[] Opaque24(Byte[] Value)
            => [ (Byte) (Value.Length >> 16), (Byte) (Value.Length >> 8), (Byte) Value.Length, .. Value ];

        #endregion


        #region The Merkle tree

        [Test]
        public void TheTreeHashesAreThoseOfRFC6962sReferenceImplementation()
        {

            var leafHashes = Leaves.Select(leaf => MerkleTree.LeafHash(Convert.FromHexString(leaf))).ToList();

            Assert.Multiple(() => {

                Assert.That(Convert.ToHexString(MerkleTree.RootHash(leafHashes, 0)).ToLowerInvariant(),
                            Is.EqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "the tree of no leaf");

                for (var size = 1; size <= Leaves.Length; size++)
                    Assert.That(Convert.ToHexString(MerkleTree.RootHash(leafHashes, size)).ToLowerInvariant(), Is.EqualTo(Roots[size - 1]), $"the tree of {size}");

            });

        }

        [Test]
        public void EveryLeafOfEveryTreeIsProvedInIt()
        {

            var leafHashes = LeafHashes(33);

            for (var size = 1; size <= leafHashes.Count; size++)
            {

                var root = MerkleTree.RootHash(leafHashes, size);

                for (var index = 0; index < size; index++)
                {

                    var path = MerkleTree.InclusionProof(leafHashes, index, size);

                    Assert.That(MerkleTree.VerifyInclusion(leafHashes[index], index, size, path, root), Is.True, $"leaf {index} of {size}");

                    // Another leaf, another place, the tree it grew into: none
                    // of them holds with this path. (A size with the hash of
                    // another tree is what a signed tree head never says, and
                    // RFC 9162 takes the two as the head says them.)
                    Assert.That(MerkleTree.VerifyInclusion(leafHashes[(index + 1) % leafHashes.Count], index, size, path, root), Is.False, $"another leaf at {index} of {size}");
                    Assert.That(MerkleTree.VerifyInclusion(leafHashes[index], index + 1, size, path, root),                      Is.False, $"leaf {index} at {index + 1} of {size}");

                    if (size < leafHashes.Count)
                        Assert.That(MerkleTree.VerifyInclusion(leafHashes[index], index, size + 1, path, MerkleTree.RootHash(leafHashes, size + 1)), Is.False, $"leaf {index} of {size} in {size + 1}");

                }

            }

        }

        [Test]
        public void EveryTreeIsProvedToHaveGrownFromEverySmallerOne()
        {

            var leafHashes = LeafHashes(33);

            for (var second = 1; second <= leafHashes.Count; second++)
            {

                var secondRoot = MerkleTree.RootHash(leafHashes, second);

                for (var first = 1; first <= second; first++)
                {

                    var firstRoot  = MerkleTree.RootHash(leafHashes, first);
                    var proof      = MerkleTree.ConsistencyProof(leafHashes, first, second);

                    Assert.That(MerkleTree.VerifyConsistency(first, second, firstRoot, secondRoot, proof), Is.True, $"{first} to {second}");

                    // A tree that was not the first one did not grow into this one.
                    if (first < second)
                        Assert.That(MerkleTree.VerifyConsistency(first, second, MerkleTree.RootHash(leafHashes, first + 1), secondRoot, proof), Is.False, $"{first + 1} for {first}");

                }

            }

        }

        [Test]
        public void ATreeWithALeafChangedDidNotGrowFromTheOneBefore()
        {

            var leafHashes  = LeafHashes(12);
            var firstRoot   = MerkleTree.RootHash(leafHashes, 7);

            leafHashes[3]   = MerkleTree.LeafHash([ 0xff ]);

            var proof       = MerkleTree.ConsistencyProof(leafHashes, 7, 12);

            Assert.That(MerkleTree.VerifyConsistency(7, 12, firstRoot, MerkleTree.RootHash(leafHashes, 12), proof), Is.False);

        }

        #endregion

        #region What the log signs

        [Test]
        public void AnEntryIsSignedAsRFC6962SaysAndItsLeafIsWhatIsHashed()
        {

            var log    = new TransparencyLog(directory);
            var entry  = Append(log, "CS-0001");

            // Written out here, byte for byte: version, signature type
            // certificate_timestamp, the timestamp, entry type x509_entry, the
            // certificate after its length in three bytes, and no extensions.
            Byte[] signed = [ 0, 0, .. UInt64(entry.Timestamp), 0, 0, .. Opaque24(entry.Certificate), 0, 0 ];
            Byte[] leaf   = [ 0, 0, .. UInt64(entry.Timestamp), 0, 0, .. Opaque24(entry.Certificate), 0, 0 ];

            using var publicKey = PublicKeyOf(log);

            Assert.Multiple(() => {
                Assert.That(publicKey.VerifyData(signed, SignatureIn(entry.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), Is.True);
                Assert.That(entry.MerkleTreeLeaf,  Is.EqualTo(leaf));
                Assert.That(entry.LeafHash,        Is.EqualTo(SHA256.HashData([ 0, .. leaf ])));
                Assert.That(log.LogId,             Is.EqualTo(SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo())));
                Assert.That(entry.SCTJSON(log.LogId)["id"]!.ToString(), Is.EqualTo(Convert.ToBase64String(log.LogId)));
            });

        }

        [Test]
        public void ATreeHeadIsSignedAsRFC6962SaysAndOverTheTreeOfEveryEntry()
        {

            var log = new TransparencyLog(directory);

            var entries = Enumerable.Range(1, 5).Select(i => Append(log, $"CS-{i:D4}")).ToList();
            var sth     = log.TreeHead()!;

            // Version, signature type tree_hash, the timestamp, the size and
            // the hash of the tree.
            Byte[] signed = [ 0, 1, .. UInt64(sth.Timestamp), .. UInt64(sth.TreeSize), .. sth.RootHash ];

            using var publicKey = PublicKeyOf(log);

            Assert.Multiple(() => {
                Assert.That(sth.TreeSize,  Is.EqualTo(5));
                Assert.That(sth.RootHash,  Is.EqualTo(MerkleTree.RootHash(entries.Select(entry => entry.LeafHash).ToList(), 5)));
                Assert.That(sth.Timestamp, Is.GreaterThanOrEqualTo(entries[^1].Timestamp));
                Assert.That(publicKey.VerifyData(signed, SignatureIn(sth.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), Is.True);
                Assert.That(log.TreeHead(), Is.SameAs(sth), "nothing came in, and no new tree head was signed");
            });

            // Every entry is proved in it, and it grew from every tree before.
            foreach (var entry in entries)
                Assert.That(MerkleTree.VerifyInclusion(entry.LeafHash, entry.Index, 5, log.InclusionProof(entry.Index, 5), sth.RootHash), Is.True);

            for (var first = 1; first < 5; first++)
                Assert.That(MerkleTree.VerifyConsistency(first, 5, log.RootHash(first), sth.RootHash, log.ConsistencyProof(first, 5)), Is.True);

        }

        [Test]
        public void ACertificateIsTakenInOnceAndAChainIsWrittenAsRFC6962SaysIt()
        {

            var log = new TransparencyLog(directory);

            using var root    = ACertificate("Root");
            using var client  = ACertificate("CS-0001");

            Assert.That(log.TryAppend(client, [ root ], out var first,  out _), Is.True);
            Assert.That(log.TryAppend(client, [ root ], out var second, out _), Is.True);

            Assert.Multiple(() => {
                Assert.That(log.Count,          Is.EqualTo(1));
                Assert.That(second,             Is.SameAs(first));
                Assert.That(first!.ExtraData,   Is.EqualTo(Opaque24(Opaque24(root.RawData))));
            });

        }

        #endregion

        #region What is left of it after a restart, and after somebody changed it

        [Test]
        public void TheLogIsTheSameAfterARestart()
        {

            var log = new TransparencyLog(directory);

            Append(log, "CS-0001");
            Append(log, "CS-0002");

            var sth     = log.TreeHead()!;
            var again   = new TransparencyLog(directory);

            Assert.Multiple(() => {
                Assert.That(again.IsNew,                Is.False);
                Assert.That(again.IsBroken,             Is.False, String.Join(" ", again.Problems));
                Assert.That(again.LogId,                Is.EqualTo(log.LogId));
                Assert.That(again.Count,                Is.EqualTo(2));
                Assert.That(again.TreeHead()!.RootHash, Is.EqualTo(sth.RootHash));
                Assert.That(again.TreeHead()!.Timestamp,Is.EqualTo(sth.Timestamp), "the tree head kept, not a new one");
            });

            Append(again, "CS-0003");

            Assert.That(MerkleTree.VerifyConsistency(2, 3, sth.RootHash, again.TreeHead()!.RootHash, again.ConsistencyProof(2, 3)), Is.True);

        }

        [Test]
        public void AnEntryChangedBreaksTheLogAndItTakesInNothingMore()
        {

            var log = new TransparencyLog(directory);

            Append(log, "CS-0001");
            Append(log, "CS-0002");
            log.TreeHead();

            var file   = Path.Combine(directory, TransparencyLog.EntriesFileName);
            var lines  = File.ReadAllLines(file);

            // Another certificate in the place of the first.
            using var other = ACertificate("Rogue");
            var first = Newtonsoft.Json.Linq.JObject.Parse(lines[0]);
            first["certificate"] = Convert.ToBase64String(other.RawData);
            lines[0] = first.ToString(Newtonsoft.Json.Formatting.None);
            File.WriteAllLines(file, lines);

            var broken = new TransparencyLog(directory);

            using var next = ACertificate("CS-0003");

            Assert.Multiple(() => {
                Assert.That(broken.IsBroken,   Is.True);
                Assert.That(broken.Problems,   Has.Some.Contains("does not hold"));
                Assert.That(broken.TreeHead(), Is.Null, "a broken log signs no tree head");
                Assert.That(broken.TryAppend(next, [], out _, out var error), Is.False);
            });

        }

        [Test]
        public void AnEntryTakenOutBreaksTheLog()
        {

            var log = new TransparencyLog(directory);

            Append(log, "CS-0001");
            Append(log, "CS-0002");
            log.TreeHead();

            var file = Path.Combine(directory, TransparencyLog.EntriesFileName);
            File.WriteAllLines(file, File.ReadAllLines(file).Take(1));

            var broken = new TransparencyLog(directory);

            Assert.That(broken.IsBroken, Is.True);
            Assert.That(broken.Problems, Has.Some.Contains("taken out"));

        }

        [Test]
        public void HalfAnEntryAtTheEndIsCutOffAndTheLogGoesOn()
        {

            var log = new TransparencyLog(directory);

            Append(log, "CS-0001");
            log.TreeHead();

            File.AppendAllText(Path.Combine(directory, TransparencyLog.EntriesFileName), "{\"index\":1,\"timest");

            var again = new TransparencyLog(directory);

            Assert.Multiple(() => {
                Assert.That(again.IsBroken,   Is.False);
                Assert.That(again.Count,      Is.EqualTo(1));
                Assert.That(again.Problems,   Has.Some.Contains("cut off"));
            });

            Assert.That(Append(again, "CS-0002").Index, Is.EqualTo(1));
            Assert.That(new TransparencyLog(directory).Count, Is.EqualTo(2));

        }

        [Test]
        public void EntriesWithoutTheirKeyAreNoLog()
        {

            var log = new TransparencyLog(directory);

            Append(log, "CS-0001");

            File.Delete(Path.Combine(directory, TransparencyLog.KeyFileName));

            Assert.That(() => new TransparencyLog(directory), Throws.InvalidOperationException.With.Message.Contains("Put its key back"));

        }

        #endregion

        #region The log of a PKI

        [Test]
        public void EveryCertificateThePKISignsIsInItsLogAndStaysThere()
        {

            var store = new PKIStore(directory);

            Assert.That(store.TryCreateRootCA(new SubjectName("Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);
            Assert.That(store.TryIssue(root!.Id, null, CertificateProfile.Client, new SubjectName("CS-0001"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                       out var client, out error, out _), Is.True, error);

            var log    = store.Transparency;
            var entry  = log.Find(client!.Id)!;

            Assert.Multiple(() => {
                // The root, its OCSP responder, and the client.
                Assert.That(log.Count,                       Is.EqualTo(3));
                Assert.That(log.Find(root.Id)!.Index,        Is.EqualTo(0));
                Assert.That(entry.Index,                     Is.EqualTo(2));
                Assert.That(entry.Chain.Single(),            Is.EqualTo(store.Load(root.Id)!.RawData), "the chain above it, up to its root");
                Assert.That(log.Verify(entry),               Is.True);
            });

            Assert.That(store.TryRemove(client.Id, false, out _, out error, out _, out _), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(store.Get(client.Id),            Is.Null);
                Assert.That(log.Find(client.Id),             Is.Not.Null, "deleted from the PKI, and still in its log");
                Assert.That(new PKIStore(directory).Transparency.Count, Is.EqualTo(3));
            });

        }

        [Test]
        public void TheCertificatesOfAPKIWithoutALogAreTakenInCAsFirst()
        {

            var store = new PKIStore(directory);

            Assert.That(store.TryCreateRootCA(new SubjectName("Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);
            Assert.That(store.TryIssue(root!.Id, null, CertificateProfile.Server, new SubjectName("csms.example.org"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                       out var server, out error, out _), Is.True, error);

            // A PKI from before its log.
            Directory.Delete(Path.Combine(directory, PKIStore.TransparencyDirectory), recursive: true);

            var again = new PKIStore(directory);

            Assert.Multiple(() => {
                Assert.That(again.Transparency.IsNew,               Is.True);
                Assert.That(again.TakenIntoTheLog,                  Is.EqualTo(2));
                Assert.That(again.Transparency.Find(root.Id)!.Index,   Is.EqualTo(0));
                Assert.That(again.Transparency.Find(server!.Id)!.Index, Is.EqualTo(1));
                Assert.That(again.PassedOver,                       Is.Empty, "a log made now has every certificate taken in, and says nothing of it");
            });

        }

        [Test]
        public void ABrokenLogStopsThePKIFromSigning()
        {

            var store = new PKIStore(directory);

            Assert.That(store.TryCreateRootCA(new SubjectName("Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);

            store.Transparency.TreeHead();

            File.WriteAllText(Path.Combine(directory, PKIStore.TransparencyDirectory, TransparencyLog.EntriesFileName), "");

            var again = new PKIStore(directory);

            Assert.Multiple(() => {
                Assert.That(again.Transparency.IsBroken,  Is.True);
                Assert.That(again.PassedOver,             Has.Some.Contains("Transparency log"));
                Assert.That(again.TryIssue(root!.Id, null, CertificateProfile.Client, new SubjectName("CS-0001"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                           out _, out error, out var notSaved), Is.False);
                Assert.That(error,                        Does.Contain("transparency log"));
                Assert.That(notSaved,                     Is.True);
                Assert.That(again.Count,                  Is.EqualTo(1), "nothing was kept that the log does not have");
            });

        }

        #endregion

    }

}
