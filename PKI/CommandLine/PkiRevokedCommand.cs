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
using cloud.charging.open.PKI.Revocation;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    /// <summary>
    /// The certificates this PKI revoked, the latest first: when, why, by
    /// whom, below which CA - and whether the PKI still has them.
    /// </summary>
    /// <remarks>
    /// What Revocation in the web interface lists, at its permission. A
    /// certificate deleted after it was revoked is still here, as it is still
    /// in the CRL of its CA, until it expires.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiRevokedCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                                 ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiRevokedCommand)[..^7].ToLowerFirstChar();

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

            var store   = cli.PKI.Store;
            var revoked = store.Revoked().OrderByDescending(revocation => revocation.RevokedAt).ToList();

            if (revoked.Count == 0)
                return Task.FromResult<String[]>([ "This PKI revoked no certificate." ]);

            var width = revoked.Max(revocation => revocation.CommonName.Length);

            return Task.FromResult<String[]>([
                       .. revoked.Select(revocation => $"{revocation.RevokedAt.ToLocalTime():yyyy-MM-dd HH:mm}  {revocation.CommonName.PadRight(width)}  " +
                                                       $"{RevocationReasons.AsText(revocation.Reason),-20}  " +
                                                       $"below '{store.Get(revocation.IssuerId)?.CommonName ?? revocation.IssuerId[..16]}'" +
                                                       (revocation.RevokedBy is null ? "" : $", by '{revocation.RevokedBy}'") +
                                                       $"  {revocation.Id[..16]}" +
                                                       (store.Get(revocation.Id) is null ? "  (deleted)" : "")),
                       $"{revoked.Count} certificate(s) revoked."
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - the certificates this PKI revoked, the latest first";

        #endregion

    }

}
