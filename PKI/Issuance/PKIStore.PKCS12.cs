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

    public sealed partial class PKIStore
    {

        #region TryExportPKCS12(Id, KeyPassword, FilePassword, Legacy, out PKCS12, out Error, out NotFound)

        /// <summary>
        /// A certificate of a server or a client with its private key and the
        /// sub-CAs above it, as one PKCS#12 file - what Windows, Java and many
        /// a charging station import - encrypted with the given password.
        /// </summary>
        /// <remarks>
        /// Encrypted with AES-256 and a key derived from the password by PBKDF2
        /// with SHA-256 - with the 2,000 iterations of .NET's PBES2 export, not the
        /// 600,000 a key here is kept with: Windows and .NET themselves refuse a
        /// PKCS#12 file of that many, so its password is to be a long one - unless <paramref name="Legacy"/> asks for Triple-DES
        /// and SHA-1 - what an older device or Windows before 10 1709 opens
        /// and nothing newer should be given. The root is not in it, as it is
        /// not in the chain a server presents: whoever imports the file
        /// believes its root, or does not, on their own account.
        ///
        /// Never the key of a CA, as the key itself is never handed out.
        /// </remarks>
        /// <param name="Id">The certificate.</param>
        /// <param name="KeyPassword">The password of its key, where that has one.</param>
        /// <param name="FilePassword">The password the file is encrypted with.</param>
        /// <param name="Legacy">Whether it is encrypted as an older device reads it.</param>
        public Boolean TryExportPKCS12(String                             Id,
                                       String?                            KeyPassword,
                                       String?                            FilePassword,
                                       Boolean                            Legacy,
                                       [NotNullWhen(true)]  out Byte[]?   PKCS12,
                                       [NotNullWhen(false)] out String?   Error,
                                       out Boolean                        NotFound)
        {

            PKCS12    = null;
            Error     = null;
            NotFound  = false;

            if (String.IsNullOrEmpty(FilePassword) || FilePassword.Length < MinKeyPasswordLength)
            {
                Error = $"A PKCS#12 file is encrypted with a password of {MinKeyPasswordLength} characters at least: it holds the private key.";
                return false;
            }

            var certificate = Get(Id);

            if (certificate is null)
            {
                NotFound = true;
                Error    = $"There is no certificate '{Id}' in this PKI.";
                return false;
            }

            if (certificate.Profile.IsCA())
            {
                Error = $"The private key of the {certificate.Profile.InWords()} '{certificate.CommonName}' does not leave this PKI, in a PKCS#12 file or otherwise.";
                return false;
            }

            var keyPEM = PrivateKeyPEM(certificate.Id);

            if (keyPEM is null)
            {
                NotFound = true;
                Error    = certificate.FromCSR
                               ? $"'{certificate.CommonName}' was signed for a CSR: its private key never was here, and is in no PKCS#12 file of this PKI."
                               : $"The private key of '{certificate.CommonName}' is not in this PKI any more.";
                return false;
            }

            using var x509 = Load(certificate.Id)!;

            if (!TryLoadKey(keyPEM, x509.PublicKey, KeyPassword, out var key, out var keyError))
            {
                Error = $"No PKCS#12 file of '{certificate.CommonName}': {keyError}";
                return false;
            }

            using (key)
            {

                using var withKey  = key switch {
                                         ECDsa  ecdsa  => x509.CopyWithPrivateKey(ecdsa),
                                         RSA    rsa    => x509.CopyWithPrivateKey(rsa),
                                         _             => throw new NotSupportedException($"A key of {key.GetType().Name} goes into no PKCS#12 file here.")
                                     };

                var collection     = new X509Certificate2Collection(withKey);
                var above          = Chain(certificate.Id).
                                         Skip (1).
                                         Where(one => one.Profile != CertificateProfile.RootCA).
                                         Select(one => Load(one.Id)).
                                         OfType<X509Certificate2>().
                                         ToList();

                try
                {

                    collection.AddRange(above.ToArray());

                    PKCS12 = Legacy
                                 ? collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, FilePassword)
                                 : collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, FilePassword);

                    return true;

                }
                finally
                {
                    foreach (var one in above)
                        one.Dispose();
                }

            }

        }

        #endregion

    }

}
