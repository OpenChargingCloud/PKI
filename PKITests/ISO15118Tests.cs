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

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Revocation;
using cloud.charging.open.PKI.Transparency;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The certificates of ISO 15118-2, Plug &amp; Charge: a V2G root, the two
    /// sub-CAs of a charging station operator and its SECC certificate, made
    /// as the profiles have them - and what they have not refused.
    /// </summary>
    public class ISO15118Tests
    {

        #region Data

        private String     directory  = "";
        private PKIStore?  store;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory  = Path.Combine(Path.GetTempPath(), "pki-v2g-" + Guid.NewGuid().ToString("N")[..12]);
            store      = new PKIStore(directory);

            // Revocation asked for, as a V2G PKI is: its CRL and its responder
            // count towards the 800 bytes.
            Assert.That(RevocationAddresses.TryParse("https://pki.charging.example.org", "api", out var addresses, out var error), Is.True, error);
            store.Addresses = addresses;

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

        private IssuedCertificate Root(String CommonName, V2GDomain Domain)
        {
            Assert.That(store!.TryCreateRootCA(new SubjectName(CommonName, "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 3650, null, null, null,
                                               out var root, out var error, out _, Domain), Is.True, error);
            return root!;
        }

        private IssuedCertificate Below(IssuedCertificate Issuer, CertificateProfile Profile, String CommonName, V2GDomain Domain, Int32 Days = 365)
        {
            Assert.That(store!.TryIssue(Issuer.Id, null, Profile, new SubjectName(CommonName, "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, Days, [], null, null, null,
                                        out var certificate, out var error, out _, Domain), Is.True, error);
            return certificate!;
        }

        private String? Refused(IssuedCertificate Issuer, CertificateProfile Profile, SubjectName Subject, V2GDomain? Domain,
                                KeyAlgorithm? Key = null, IReadOnlyList<String>? Names = null, Int32? PathLength = null)
        {
            Assert.That(store!.TryIssue(Issuer.Id, null, Profile, Subject, Key ?? KeyAlgorithm.ECC_P256, 30, Names ?? [], PathLength, null, null,
                                        out _, out var error, out _, Domain), Is.False);
            return error;
        }

        /// <summary>
        /// The attributes of a distinguished name in the order they are
        /// written, each as "type=value".
        /// </summary>
        private static List<String> Attributes(X500DistinguishedName Name)

            => Name.EnumerateRelativeDistinguishedNames(reversed: false).
                    Select(part => $"{part.GetSingleElementType().FriendlyName ?? part.GetSingleElementType().Value}={part.GetSingleElementValue()}").
                    ToList();

        private static X509KeyUsageExtension KeyUsage(X509Certificate2 Certificate)
            => Certificate.Extensions.OfType<X509KeyUsageExtension>().Single();

        private static X509BasicConstraintsExtension BasicConstraints(X509Certificate2 Certificate)
            => Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single();

        #endregion


        #region AV2GChainIsMadeAsISO15118HasIt()

        [Test]
        public void AV2GChainIsMadeAsISO15118HasIt()
        {

            var root  = Root("V2G Root CA", V2GDomain.V2G);
            var sub1  = Below(root, CertificateProfile.SubCA,  "CPO Sub-CA 1", V2GDomain.V2G, 1460);
            var sub2  = Below(sub1, CertificateProfile.SubCA,  "CPO Sub-CA 2", V2GDomain.V2G);
            var secc  = Below(sub2, CertificateProfile.Server, "DE*ABC*E1234567*1", V2GDomain.CPO, 60);

            using var rootCertificate  = store!.Load(root.Id)!;
            using var sub1Certificate  = store.Load(sub1.Id)!;
            using var sub2Certificate  = store.Load(sub2.Id)!;
            using var seccCertificate  = store.Load(secc.Id)!;

            Assert.Multiple(() => {

                #region Every one: P-256 and SHA-256, the domain first, and 800 bytes at most

                foreach (var certificate in new[] { rootCertificate, sub1Certificate, sub2Certificate, seccCertificate })
                {
                    Assert.That(certificate.SignatureAlgorithm.Value,                          Is.EqualTo("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
                    Assert.That(certificate.GetECDsaPublicKey()!.ExportParameters(false).Curve.Oid.Value, Is.EqualTo("1.2.840.10045.3.1.7"), "secp256r1");
                    Assert.That(certificate.RawData.Length,                                    Is.LessThanOrEqualTo(ISO15118.MaxCertificateSize));
                    Assert.That(certificate.Extensions[Precertificate.SCTListOID],             Is.Null, "no signed certificate timestamps");
                    Assert.That(certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>(), Is.Empty, "no extended key usage");
                    Assert.That(certificate.Extensions["2.5.29.17"],                           Is.Null, "no alternative names");
                    Assert.That(KeyUsage(certificate).Critical,                                Is.True);
                    Assert.That(BasicConstraints(certificate).Critical,                        Is.True);
                }

                Assert.That(Attributes(rootCertificate.SubjectName),   Is.EqualTo(new[] { "0.9.2342.19200300.100.1.25=V2G", "C=DE", "O=OpenChargingCloud", "CN=V2G Root CA" }).
                                                                          Or.EqualTo(new[] { "DC=V2G", "C=DE", "O=OpenChargingCloud", "CN=V2G Root CA" }),
                            "the domain first, the common name last");
                Assert.That(Attributes(seccCertificate.SubjectName)[0], Does.EndWith("=CPO"));

                #endregion

                #region The root: signs, names no revocation

                Assert.That(KeyUsage(rootCertificate).KeyUsages,                               Is.EqualTo(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign));
                Assert.That(BasicConstraints(rootCertificate).CertificateAuthority,            Is.True);
                Assert.That(rootCertificate.Extensions["2.5.29.31"],                           Is.Null, "a root names no CRL");
                Assert.That(rootCertificate.Extensions["1.3.6.1.5.5.7.1.1"],                   Is.Null, "a root names no responder");

                #endregion

                #region Two sub-CAs, of path length 1 and 0

                Assert.That(BasicConstraints(sub1Certificate).HasPathLengthConstraint,          Is.True);
                Assert.That(BasicConstraints(sub1Certificate).PathLengthConstraint,             Is.EqualTo(1));
                Assert.That(BasicConstraints(sub2Certificate).PathLengthConstraint,             Is.EqualTo(0));
                Assert.That(sub2.PathLength,                                                    Is.EqualTo(0));

                #endregion

                #region The SECC: signs and agrees on keys, and names its CRL and responder

                Assert.That(KeyUsage(seccCertificate).KeyUsages,                               Is.EqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement));
                Assert.That(BasicConstraints(seccCertificate).CertificateAuthority,            Is.False);
                Assert.That(seccCertificate.Extensions["2.5.29.31"],                           Is.Not.Null, "its CRL");
                Assert.That(seccCertificate.Extensions.OfType<X509AuthorityInformationAccessExtension>().Single().EnumerateOcspUris(), Has.Exactly(1).Items);
                Assert.That(seccCertificate.Extensions.OfType<X509AuthorityInformationAccessExtension>().Single().EnumerateCAIssuersUris(), Is.Empty,
                            "the responder alone: every byte counts");

                Assert.That(secc.V2G,                                                          Is.EqualTo(V2GDomain.CPO));
                Assert.That(secc.Profile,                                                      Is.EqualTo(CertificateProfile.Server));
                Assert.That(secc.InWords,                                                      Is.EqualTo("SECC certificate"));
                Assert.That(sub1.InWords,                                                      Is.EqualTo("V2G sub-CA"));
                Assert.That(store.Transparency.Find(secc.Id)!.IsPrecertificate,                Is.False, "in the log as itself");

                #endregion

            });

            #region The chain holds, as a TLS stack checks it

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode     = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
            chain.ChainPolicy.ExtraStore.AddRange(new[] { sub1Certificate, sub2Certificate });

            Assert.That(chain.Build(seccCertificate), Is.True, String.Join(" ", chain.ChainStatus.Select(status => status.StatusInformation)));

            #endregion

            #region And it is what the next start reads

            var again = new PKIStore(directory).Get(secc.Id)!;

            Assert.That(again.V2G, Is.EqualTo(V2GDomain.CPO));

            #endregion

        }

        #endregion

        #region AContractCertificateIsSignedForACSRWithItsDomain()

        [Test]
        public void AContractCertificateIsSignedForACSRWithItsDomain()
        {

            var root  = Root("MO Root CA", V2GDomain.MO);
            var sub1  = Below(root, CertificateProfile.SubCA, "MO Sub-CA 1", V2GDomain.MO, 1460);
            var sub2  = Below(sub1, CertificateProfile.SubCA, "MO Sub-CA 2", V2GDomain.MO);

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var rsa = RSA.Create(2048);

            var csr      = new CertificateRequest("CN=DEABCC12345678, O=OpenChargingCloud, C=DE", key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
            var asCPO    = new CertificateRequest("DC=CPO, CN=DEABCC12345678",                    key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
            var withRSA  = new CertificateRequest("CN=DEABCC12345678",                            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();

            Assert.That(store!.TryIssueFromCSR(sub2.Id, null, CertificateProfile.Client, csr, 300, [], true, null, null,
                                               out var contract, out var error, out _, V2GDomain.MO), Is.True, error);

            using var certificate = store.Load(contract!.Id)!;

            Assert.Multiple(() => {

                Assert.That(Attributes(certificate.SubjectName)[0],    Does.EndWith("=MO"), "the domain added, first");
                Assert.That(Attributes(certificate.SubjectName)[^1],   Is.EqualTo("CN=DEABCC12345678"));
                Assert.That(KeyUsage(certificate).KeyUsages,           Is.EqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                                                                                  X509KeyUsageFlags.KeyEncipherment  | X509KeyUsageFlags.KeyAgreement));
                Assert.That(contract.InWords,                          Is.EqualTo("contract certificate"));

                Assert.That(store.TryIssueFromCSR(sub2.Id, null, CertificateProfile.Client, asCPO, 300, [], true, null, null,
                                                  out _, out error, out _, V2GDomain.MO), Is.False);
                Assert.That(error,                                     Does.Contain("'CPO'"), "a subject of another domain is not made one of this");

                Assert.That(store.TryIssueFromCSR(sub2.Id, null, CertificateProfile.Client, withRSA, 300, [], true, null, null,
                                                  out _, out error, out _, V2GDomain.MO), Is.False);
                Assert.That(error,                                     Does.Contain("secp256r1"));

            });

        }

        #endregion

        #region WhatISO15118HasNotIsRefused()

        [Test]
        public void WhatISO15118HasNotIsRefused()
        {

            var root     = Root("V2G Root CA", V2GDomain.V2G);
            var sub1     = Below(root, CertificateProfile.SubCA, "CPO Sub-CA 1", V2GDomain.V2G, 1460);
            var sub2     = Below(sub1, CertificateProfile.SubCA, "CPO Sub-CA 2", V2GDomain.V2G);
            var moRoot   = Root("MO Root CA",  V2GDomain.MO);
            var moSub    = Below(root, CertificateProfile.SubCA, "MO Sub-CA 1", V2GDomain.MO);

            Assert.That(store!.TryCreateRootCA(new SubjectName("Plain Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var plain, out var error, out _), Is.True, error);

            var station = new SubjectName("DE*ABC*E1234567*1");

            Assert.Multiple(() => {

                Assert.That(store.TryCreateRootCA(new SubjectName("RSA Root"), KeyAlgorithm.RSA_2048, 365, null, null, null, out _, out error, out _, V2GDomain.V2G), Is.False);
                Assert.That(error, Does.Contain("secp256r1"));

                Assert.That(store.TryCreateRootCA(new SubjectName("CPO Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out _, out error, out _, V2GDomain.CPO), Is.False);
                Assert.That(error, Does.Contain("V2G, MO or OEM"));

                Assert.That(Refused(sub2,   CertificateProfile.Server, station, V2GDomain.CPO, Key: KeyAlgorithm.ECC_P384),  Does.Contain("secp256r1"));
                Assert.That(Refused(sub2,   CertificateProfile.Server, station, V2GDomain.CPO, Names: [ "secc.example.org" ]), Does.Contain("no alternative names"));
                Assert.That(Refused(sub2,   CertificateProfile.Client, station, null),                                       Does.Contain("ISO 15118 only"));
                Assert.That(Refused(plain!, CertificateProfile.SubCA,  station, V2GDomain.V2G),                              Does.Contain("is none"));
                Assert.That(Refused(sub2,   CertificateProfile.SubCA,  station, V2GDomain.V2G),                              Does.Contain("path length is 0"), "two sub-CAs at most");
                Assert.That(Refused(root,   CertificateProfile.SubCA,  station, V2GDomain.V2G, PathLength: 3),               Does.Contain("path length 1"));
                Assert.That(Refused(moSub,  CertificateProfile.Server, station, V2GDomain.CPO),                              Does.Contain("domain V2G"), "a SECC below a CA of V2G");
                Assert.That(Refused(sub2,   CertificateProfile.Client, station, V2GDomain.MO),                               Does.Contain("domain MO"));
                Assert.That(Refused(moRoot, CertificateProfile.SubCA,  station, V2GDomain.CPS),                              Does.Contain("only a V2G root"));
                Assert.That(Refused(sub2,   CertificateProfile.Server, station, V2GDomain.MO),                               Does.Contain("SECC"));

            });

            #region 800 bytes at most

            var longest = new SubjectName(new String('C', 64), new String('O', 64), new String('U', 64), "DE", new String('S', 64), new String('L', 64));

            Assert.That(Refused(sub2, CertificateProfile.Server, longest, V2GDomain.CPO), Does.Contain("800"));
            Assert.That(store.Find(longest.CommonName),                                  Is.Empty, "nothing kept that ISO 15118 does not carry");

            #endregion

        }

        #endregion

    }

}
