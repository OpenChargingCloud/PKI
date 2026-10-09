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

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// The kind of key a certificate of this PKI is made with: three curves
    /// and three lengths of RSA, by the names the JSON API and the web
    /// interface write them with - "ecc-p256", "rsa-2048".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Six and no more, because each of them is one somebody can be told to
    /// use: P-256 is what most TLS stacks of charging stations speak, P-384
    /// what a CA of ISO 15118 is made with, RSA 2048 what an older OCPP
    /// station still asks for. A curve nobody's TLS speaks would be a
    /// certificate nobody can use.
    /// </para>
    /// <para>
    /// The hash a key signs with follows from it: SHA-256 for P-256 and for
    /// RSA, SHA-384 for P-384 and SHA-512 for P-521 - the strength of the
    /// hash to the strength of the curve, as RFC 5480 recommends. RSA stays
    /// with SHA-256 at every length, because that is what every verifier on
    /// a charging station's side can check.
    /// </para>
    /// </remarks>
    public sealed class KeyAlgorithm
    {

        #region Properties

        /// <summary>
        /// "ecc-p256", "rsa-2048": how it is written.
        /// </summary>
        public String  Name       { get; }

        /// <summary>
        /// Whether it is an elliptic curve rather than RSA.
        /// </summary>
        public Boolean IsECC      { get; }

        /// <summary>
        /// The length of the key in bits: the size of the curve, or of the
        /// RSA modulus.
        /// </summary>
        public Int32   KeySize    { get; }

        #endregion

        #region The six

        public static readonly KeyAlgorithm  ECC_P256  = new ("ecc-p256", true,   256);
        public static readonly KeyAlgorithm  ECC_P384  = new ("ecc-p384", true,   384);
        public static readonly KeyAlgorithm  ECC_P521  = new ("ecc-p521", true,   521);
        public static readonly KeyAlgorithm  RSA_2048  = new ("rsa-2048", false, 2048);
        public static readonly KeyAlgorithm  RSA_3072  = new ("rsa-3072", false, 3072);
        public static readonly KeyAlgorithm  RSA_4096  = new ("rsa-4096", false, 4096);

        /// <summary>
        /// Every one of them, in the order a list offers them.
        /// </summary>
        public static readonly IReadOnlyList<KeyAlgorithm>  All = [ ECC_P256, ECC_P384, ECC_P521, RSA_2048, RSA_3072, RSA_4096 ];

        #endregion

        #region Constructor(s)

        private KeyAlgorithm(String   Name,
                             Boolean  IsECC,
                             Int32    KeySize)
        {
            this.Name     = Name;
            this.IsECC    = IsECC;
            this.KeySize  = KeySize;
        }

        #endregion


        #region TryParse(Text, out KeyAlgorithm)

        /// <summary>
        /// One of the six by its name, whatever its case.
        /// </summary>
        public static Boolean TryParse(String?                                Text,
                                       [NotNullWhen(true)] out KeyAlgorithm?  KeyAlgorithm)
        {

            KeyAlgorithm = All.FirstOrDefault(algorithm => algorithm.Name.Equals(Text?.Trim(), StringComparison.OrdinalIgnoreCase));

            return KeyAlgorithm is not null;

        }

        #endregion

        #region Of(PublicKey)

        /// <summary>
        /// The kind of key a public key is, where it is one of the six - or
        /// null for anything else: a curve nobody here signs with, RSA below
        /// 2048 bits.
        /// </summary>
        public static KeyAlgorithm? Of(PublicKey PublicKey)
        {

            using var ecdsa = PublicKey.GetECDsaPublicKey();

            if (ecdsa is not null)
                return All.FirstOrDefault(algorithm => algorithm.IsECC && algorithm.KeySize == ecdsa.KeySize);

            using var rsa = PublicKey.GetRSAPublicKey();

            if (rsa is not null)
                return All.FirstOrDefault(algorithm => !algorithm.IsECC && algorithm.KeySize == rsa.KeySize);

            return null;

        }

        #endregion

        #region Describe(PublicKey)

        /// <summary>
        /// What a public key is, said for a person - "ECC P-256", "RSA 1024" -
        /// one of the six or not.
        /// </summary>
        public static String Describe(PublicKey PublicKey)
        {

            using var ecdsa = PublicKey.GetECDsaPublicKey();

            if (ecdsa is not null)
                return $"ECC P-{ecdsa.KeySize}";

            using var rsa = PublicKey.GetRSAPublicKey();

            if (rsa is not null)
                return $"RSA {rsa.KeySize}";

            return PublicKey.Oid.FriendlyName ?? PublicKey.Oid.Value ?? "unknown";

        }

        #endregion

        #region NewKey()

        /// <summary>
        /// A new key pair of this kind.
        /// </summary>
        public AsymmetricAlgorithm NewKey()

            => IsECC
                   ? ECDsa.Create(KeySize switch {
                                      256 => ECCurve.NamedCurves.nistP256,
                                      384 => ECCurve.NamedCurves.nistP384,
                                      _   => ECCurve.NamedCurves.nistP521
                                  })
                   : RSA.Create(KeySize);

        #endregion

        #region Hash

        /// <summary>
        /// The hash this kind of key signs with.
        /// </summary>
        public HashAlgorithmName Hash

            => IsECC
                   ? KeySize switch {
                         256 => HashAlgorithmName.SHA256,
                         384 => HashAlgorithmName.SHA384,
                         _   => HashAlgorithmName.SHA512
                     }
                   : HashAlgorithmName.SHA256;

        #endregion


        public override String ToString()
            => Name;

    }

}
