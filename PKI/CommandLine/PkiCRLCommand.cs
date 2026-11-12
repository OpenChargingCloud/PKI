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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    /// <summary>
    /// The CRL of every CA of this PKI: its number, until when it is to be
    /// believed, how many certificates it names, and where it is fetched.
    /// </summary>
    /// <remarks>
    /// What Revocation in the web interface says of each CA, at its
    /// permission. A CRL past its time is said to be: whoever checks a
    /// certificate below that CA believes nothing until it is signed anew -
    /// 'pkiSignCRL'.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiCRLCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                             ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiCRLCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(PKIAccess.Issuance), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var store = cli.PKI.Store;
            var now   = cli.PKI.TimeProvider.GetUtcNow();
            var cas   = store.Find().Where(certificate => certificate.Profile.IsCA()).ToList();

            if (cas.Count == 0)
                return Task.FromResult<String[]>([ "This PKI has no CA yet, and so no CRL." ]);

            var width = cas.Max(ca => ca.CommonName.Length);

            String CRLOf(IssuedCertificate ca)
            {

                if (store.CRLInfoOf(ca.Id) is not { } crl)
                    return "no CRL yet";

                var until = crl.NextUpdate is DateTimeOffset next
                                ? next < now
                                      ? $"OUT OF DATE since {next.ToLocalTime():yyyy-MM-dd HH:mm}"
                                      : $"until {next.ToLocalTime():yyyy-MM-dd HH:mm}"
                                : "without an end";

                return $"number {crl.Number}, {crl.Entries} revoked, {until}" +
                       (store.Addresses is { } at ? $", at {at.CRL(ca.Id)}" : "");

            }

            return Task.FromResult<String[]>([
                       .. cas.Select(ca => $"{ca.CommonName.PadRight(width)}  {ca.Id[..16]}  {CRLOf(ca)}" +
                                           (ca.HasPrivateKey
                                                ? ca.KeyEncrypted ? "  (its key has a password)" : ""
                                                : "  (its key is not here)")),
                       store.Addresses is { } addresses
                           ? $"The OCSP responder is at {addresses.OCSP}."
                           : "No certificate names a CRL or an OCSP responder: the PKI has no address it is reached at."
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - the CRL of every CA of this PKI: its number, until when it is believed, and where it is fetched";

        #endregion

    }

}
