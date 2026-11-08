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
using System.Globalization;
using System.Numerics;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Revocation
{

    /// <summary>
    /// What a CRL says of itself: its number, when it was signed, until when
    /// it is to be believed, and how many certificates it names.
    /// </summary>
    public sealed record CRLInfo(BigInteger      Number,
                                 DateTimeOffset  ThisUpdate,
                                 DateTimeOffset? NextUpdate,
                                 Int32           Entries)
    {

        /// <summary>
        /// The CRL number extension, RFC 5280, section 5.2.3.
        /// </summary>
        public const String CRLNumberOID = "2.5.29.20";

        #region ToJSON()

        public JObject ToJSON()

            => new (
                   new JProperty("number",      Number.ToString(CultureInfo.InvariantCulture)),
                   new JProperty("thisUpdate",  ThisUpdate.ToString("o", CultureInfo.InvariantCulture)),
                   new JProperty("nextUpdate",  NextUpdate?.ToString("o", CultureInfo.InvariantCulture)),
                   new JProperty("entries",     Entries)
               );

        #endregion

        #region (static) TryRead(DER)

        /// <summary>
        /// What the CRL of the given DER says of itself, or null where it is
        /// none. Its signature is not checked: the CRLs read here are the
        /// PKI's own.
        /// </summary>
        public static CRLInfo? TryRead(Byte[] DER)
        {

            try
            {

                var certificateList  = new AsnReader(DER, AsnEncodingRules.DER).ReadSequence();
                var tbs              = certificateList.ReadSequence();

                if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
                    tbs.ReadInteger();                                    // version

                tbs.ReadSequence();                                       // signature
                tbs.ReadEncodedValue();                                   // issuer

                var thisUpdate  = ReadTime(tbs);
                var nextUpdate  = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : (DateTimeOffset?) null;
                var entries     = 0;
                var number      = BigInteger.Zero;

                if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                {
                    var revoked = tbs.ReadSequence();
                    while (revoked.HasData)
                    {
                        revoked.ReadEncodedValue();
                        entries++;
                    }
                }

                if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {

                    var extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();

                    while (extensions.HasData)
                    {

                        var extension = extensions.ReadSequence();
                        var oid       = extension.ReadObjectIdentifier();

                        if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                            extension.ReadBoolean();

                        var value     = extension.ReadOctetString();

                        if (oid == CRLNumberOID)
                            number = new AsnReader(value, AsnEncodingRules.DER).ReadInteger();

                    }

                }

                return new CRLInfo(number, thisUpdate, nextUpdate, entries);

            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion

        #region (private static) Times

        private static Boolean IsTime(Asn1Tag Tag)

            => Tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.UtcTime)) ||
               Tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.GeneralizedTime));

        private static DateTimeOffset ReadTime(AsnReader Reader)

            => Reader.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.UtcTime))
                   ? Reader.ReadUtcTime()
                   : Reader.ReadGeneralizedTime();

        #endregion

    }

}
