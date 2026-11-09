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
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// The domain of a certificate of ISO 15118-2 - Plug &amp; Charge - as
    /// the DomainComponent of its subject says it.
    /// </summary>
    public enum V2GDomain
    {

        /// <summary>
        /// The V2G root, and the sub-CAs of a charging station operator below it.
        /// </summary>
        V2G,

        /// <summary>
        /// A charging station operator's SECC: the TLS server of the
        /// charging station towards the car.
        /// </summary>
        CPO,

        /// <summary>
        /// A mobility operator: its root, its sub-CAs and its contract
        /// certificates.
        /// </summary>
        MO,

        /// <summary>
        /// A car maker: its root, its sub-CAs and the provisioning certificates
        /// of its cars.
        /// </summary>
        OEM,

        /// <summary>
        /// The certificate provisioning service, which signs the contract
        /// data a car is given.
        /// </summary>
        CPS

    }


    /// <summary>
    /// The certificates of ISO 15118-2 - its PKI of Plug &amp; Charge - as
    /// this PKI makes them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every key ECDSA on secp256r1, every signature ECDSA with SHA-256; a
    /// DomainComponent first in every subject, saying the domain; at most two
    /// sub-CAs below a root, the first of path length 1, the second 0; and no
    /// certificate larger than 800 bytes, which is what the message of ISO
    /// 15118-2 carries one in. The extensions are those the profiles name and
    /// nothing else: basic constraints and key usage, both critical, the key
    /// identifiers, and below a root the CRL and the OCSP responder - no
    /// extended key usage, no alternative names, and no signed certificate
    /// timestamps.
    /// </para>
    /// <para>
    /// | Certificate | Profile | Domain | Key usage |
    /// |---|---|---|---|
    /// | V2G, MO or OEM root CA | root CA | V2G, MO, OEM | keyCertSign, cRLSign |
    /// | sub-CA | sub-CA | V2G (a CPO's), MO, OEM, CPS | keyCertSign, cRLSign |
    /// | SECC certificate | server | CPO | digitalSignature, keyAgreement |
    /// | contract certificate | client | MO | digitalSignature, nonRepudiation, keyEncipherment, keyAgreement |
    /// | OEM provisioning certificate | client | OEM | digitalSignature, keyAgreement |
    /// | CPS certificate | client | CPS | digitalSignature |
    /// </para>
    /// <para>
    /// Below a CA of ISO 15118 only certificates of ISO 15118 are signed, and
    /// a certificate of ISO 15118 only below one: a chain is of the one or of
    /// the other. A sub-CA below a V2G root may be of any domain but CPO; below
    /// any other CA, of the domain of its CA. A SECC certificate stands below
    /// a CA of the domain V2G, every other below one of its own domain.
    /// </para>
    /// </remarks>
    public static class ISO15118
    {

        /// <summary>
        /// The largest certificate ISO 15118-2 carries: its schema has a
        /// certificate as base64Binary of 800 bytes at most.
        /// </summary>
        public const Int32   MaxCertificateSize    = 800;

        /// <summary>
        /// The DomainComponent of a distinguished name, RFC 4519.
        /// </summary>
        public const String  DomainComponentOID    = "0.9.2342.19200300.100.1.25";

        /// <summary>
        /// The one key ISO 15118-2 signs with.
        /// </summary>
        public static KeyAlgorithm KeyAlgorithm
            => Issuance.KeyAlgorithm.ECC_P256;

        #region AsText / TryParse

        /// <summary>
        /// "V2G", "CPO", "MO", "OEM", "CPS": as the DomainComponent, and the
        /// JSON API, write it.
        /// </summary>
        public static String AsText(this V2GDomain Domain)
            => Domain.ToString();

        /// <summary>
        /// A domain by its name, whatever its case.
        /// </summary>
        public static Boolean TryParse(String?                             Text,
                                       [NotNullWhen(true)] out V2GDomain?  Domain)
        {

            Domain = Enum.GetValues<V2GDomain>().
                          Cast<V2GDomain?>().
                          FirstOrDefault(domain => domain!.Value.AsText().Equals(Text?.Trim(), StringComparison.OrdinalIgnoreCase));

            return Domain is not null;

        }

        #endregion

        #region InWords(Profile, Domain)

        /// <summary>
        /// What a certificate of the given profile and domain is called:
        /// "V2G root CA", "SECC certificate", "contract certificate".
        /// </summary>
        public static String InWords(CertificateProfile Profile, V2GDomain Domain)

            => (Profile, Domain) switch {
                   (CertificateProfile.RootCA, _)              => $"{Domain} root CA",
                   (CertificateProfile.SubCA,  _)              => $"{Domain} sub-CA",
                   (CertificateProfile.Server, V2GDomain.CPO)  => "SECC certificate",
                   (CertificateProfile.Client, V2GDomain.MO)   => "contract certificate",
                   (CertificateProfile.Client, V2GDomain.OEM)  => "OEM provisioning certificate",
                   (CertificateProfile.Client, V2GDomain.CPS)  => "CPS certificate",
                   _                                           => $"{Domain} {Profile.InWords()}"
               };

        #endregion

        #region ProfileOf(Domain)

        /// <summary>
        /// What a certificate of the given domain below a sub-CA is: a server's
        /// for the SECC, a client's for every other.
        /// </summary>
        public static CertificateProfile LeafProfileOf(V2GDomain Domain)

            => Domain == V2GDomain.CPO
                   ? CertificateProfile.Server
                   : CertificateProfile.Client;

        #endregion

        #region IsAllowed(Profile, Domain, out Error)

        /// <summary>
        /// Whether ISO 15118-2 has a certificate of the given profile in the
        /// given domain.
        /// </summary>
        public static Boolean IsAllowed(CertificateProfile                Profile,
                                        V2GDomain                         Domain,
                                        [NotNullWhen(false)] out String?  Error)
        {

            var allowed = Profile switch {
                              CertificateProfile.RootCA  => Domain is V2GDomain.V2G or V2GDomain.MO or V2GDomain.OEM,
                              CertificateProfile.SubCA   => Domain is not V2GDomain.CPO,
                              CertificateProfile.Server  => Domain is V2GDomain.CPO,
                              _                          => Domain is V2GDomain.MO or V2GDomain.OEM or V2GDomain.CPS
                          };

            Error = allowed
                        ? null
                        : Profile switch {
                              CertificateProfile.RootCA  => "A root CA of ISO 15118 is one of V2G, MO or OEM.",
                              CertificateProfile.SubCA   => "A sub-CA of ISO 15118 is one of V2G, MO, OEM or CPS: CPO is the domain of the SECC certificate.",
                              CertificateProfile.Server  => "The server's certificate of ISO 15118 is the SECC certificate, of the domain CPO.",
                              _                          => "A client's certificate of ISO 15118 is a contract certificate (MO), an OEM provisioning certificate (OEM) or a CPS certificate (CPS)."
                          };

            return allowed;

        }

        #endregion

        #region MaySignBelow(Issuer, IssuerDomain, Profile, Domain, out Error)

        /// <summary>
        /// Whether a CA of the given domain signs a certificate of the given
        /// profile and domain.
        /// </summary>
        public static Boolean MaySignBelow(IssuedCertificate                 Issuer,
                                           V2GDomain                         IssuerDomain,
                                           CertificateProfile                Profile,
                                           V2GDomain                         Domain,
                                           [NotNullWhen(false)] out String?  Error)
        {

            var allowed = Profile == CertificateProfile.SubCA
                              ? Domain == IssuerDomain || (Issuer.Profile == CertificateProfile.RootCA && IssuerDomain == V2GDomain.V2G)
                              : Domain == V2GDomain.CPO
                                    ? IssuerDomain == V2GDomain.V2G
                                    : Domain == IssuerDomain;

            Error = allowed
                        ? null
                        : $"The {InWords(Issuer.Profile, IssuerDomain)} '{Issuer.CommonName}' signs no {InWords(Profile, Domain)}: " +
                          (Profile == CertificateProfile.SubCA
                               ? "a sub-CA is of the domain of its CA, and only a V2G root signs sub-CAs of other domains."
                               : Domain == V2GDomain.CPO
                                     ? "a SECC certificate stands below a CA of the domain V2G."
                                     : $"it stands below a CA of the domain {Domain}.");

            return allowed;

        }

        #endregion

        #region KeyUsageOf(Profile, Domain)

        /// <summary>
        /// What the key of a certificate of the given profile and domain may
        /// be used for.
        /// </summary>
        public static X509KeyUsageFlags KeyUsageOf(CertificateProfile Profile, V2GDomain Domain)

            => Profile.IsCA()
                   ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                   : Domain switch {
                         V2GDomain.MO   => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                                           X509KeyUsageFlags.KeyEncipherment  | X509KeyUsageFlags.KeyAgreement,
                         V2GDomain.CPS  => X509KeyUsageFlags.DigitalSignature,
                         _              => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement
                     };

        #endregion

        #region WithDomainComponent(Name, Domain, out WithIt, out Error)

        /// <summary>
        /// A distinguished name with the DomainComponent of the given domain
        /// first: as it is, where it says that domain already, with it added
        /// where it says none - and none at all where it says another.
        /// </summary>
        public static Boolean TryWithDomainComponent(X500DistinguishedName                            Name,
                                                     V2GDomain                                        Domain,
                                                     [NotNullWhen(true)]  out X500DistinguishedName?  WithIt,
                                                     [NotNullWhen(false)] out String?                 Error)
        {

            WithIt = null;
            Error  = null;

            var others = new List<String>();

            foreach (var part in Name.EnumerateRelativeDistinguishedNames())
            {
                if (!part.HasMultipleElements && part.GetSingleElementType().Value == DomainComponentOID)
                    others.Add(part.GetSingleElementValue() ?? "");
            }

            if (others.Count > 0)
            {

                if (others.Count == 1 && others[0].Equals(Domain.AsText(), StringComparison.Ordinal))
                {
                    WithIt = Name;
                    return true;
                }

                Error = $"The subject says the domain {String.Join(", ", others.Select(one => $"'{one}'"))}, and the certificate is one of the domain '{Domain.AsText()}'.";
                return false;

            }

            // The DomainComponent first, then the name as it was: a name is a
            // SEQUENCE of RDNs, each a SET - copied one by one.
            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {

                using (writer.PushSetOf())
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(DomainComponentOID);
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, Domain.AsText());
                }

                var rdns = new AsnReader(Name.RawData, AsnEncodingRules.DER).ReadSequence();

                while (rdns.HasData)
                    writer.WriteEncodedValue(rdns.ReadEncodedValue().Span);

            }

            WithIt = new X500DistinguishedName(writer.Encode());
            return true;

        }

        #endregion

    }

}
