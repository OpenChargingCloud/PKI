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
    /// The certificates of this PKI, one line each - or those whose common
    /// name holds a text, as the list on the PKI page filters them.
    /// </summary>
    /// <remarks>
    /// What the list of the web interface shows, at the permission it is
    /// shown with: what it is, who it is about, until when it holds, and the
    /// beginning of its fingerprint, which is enough to find it there.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                          ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: "PkiCommand" without its last seven
        /// characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiCommand)[..^7].ToLowerFirstChar();

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

            var text  = Arguments.Length > 1 ? String.Join(" ", Arguments[1..]) : null;
            var found = cli.PKI.Store.Find(text);

            if (found.Count == 0)
                return Task.FromResult<String[]>([
                           text is null
                               ? $"This PKI has no certificate yet. Its directory is '{cli.PKI.Store.Directory}'."
                               : $"No certificate of this PKI has '{text}' in its common name."
                       ]);

            var now   = cli.PKI.TimeProvider.GetUtcNow();
            var width = found.Max(certificate => certificate.CommonName.Length);

            return Task.FromResult<String[]>([
                       .. found.Select(certificate => $"{certificate.Profile.AsText(),-7} {certificate.CommonName.PadRight(width)}  " +
                                                      $"until {certificate.NotAfter.ToLocalTime():yyyy-MM-dd}  {certificate.StatusAt(now),-11}  {certificate.Id[..16]}"),
                       $"{found.Count} of {cli.PKI.Store.Count} certificate(s)."
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [<text>] - the certificates of this PKI, or those with <text> in their common name";

        #endregion

    }

}
