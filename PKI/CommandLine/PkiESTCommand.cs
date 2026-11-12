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
using cloud.charging.open.PKI.Enrollment;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    /// <summary>
    /// What EST signs: where it is, what a CSR without a label becomes and
    /// what one at each label, below which CA and for how long.
    /// </summary>
    /// <remarks>
    /// What EST in the web interface shows, at its permission. What EST signs
    /// is changed there, or in the configuration file.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiESTCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                             ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiESTCommand)[..^7].ToLowerFirstChar();

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

            var pki = cli.PKI;
            var est = pki.EST;

            if (!est.Enabled)
                return Task.FromResult<String[]>([ $"EST at {pki.ESTPathAt()} signs nothing: no CA is named for it." ]);

            String Signs(ESTProfile profile)

                => pki.Store.Get(profile.IssuerId) is { } ca
                       ? $"a {profile.InWords} of {profile.ValidDays} days below '{ca.CommonName}' ({ca.Id[..16]})" +
                         (ca.KeyEncrypted ? " - whose key has a password, so that it signs nothing" : "")
                       : $"a {profile.InWords} of {profile.ValidDays} days below {profile.IssuerId[..Math.Min(16, profile.IssuerId.Length)]}, which is not in this PKI";

            const String NoLabel = "without a label";

            var width = Math.Max(NoLabel.Length,
                                 est.Labels.Keys.Select(label => label.Length + 2).DefaultIfEmpty(0).Max());

            return Task.FromResult<String[]>([
                       $"EST at {pki.ESTPathAt()}[/<label>]/ signs:",
                       .. est.Default is { } byDefault
                              ? new[] { $"  {NoLabel.PadRight(width)}  {Signs(byDefault)}" }
                              : [],
                       .. est.Labels.OrderBy(label => label.Key, StringComparer.OrdinalIgnoreCase).
                              Select(label => $"  {$"'{label.Key}'".PadRight(width)}  {Signs(label.Value)}"),
                       est.TLSClientCertificates
                           ? pki.HTTPS ? "A certificate of this PKI renews itself, signed in with it as its TLS client certificate."
                                       : "No TLS client certificate is asked for, since this PKI speaks no HTTPS of its own."
                           : "No TLS client certificate is asked for.",
                       est.ServerKeyGeneration
                           ? "serverkeygen makes keys for whoever asks over HTTPS."
                           : "serverkeygen makes no keys."
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - what EST signs: without a label and at each label, below which CA and for how long";

        #endregion

    }

}
