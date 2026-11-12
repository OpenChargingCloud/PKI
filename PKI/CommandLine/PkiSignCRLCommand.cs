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
    /// Sign the CRL of a CA of this PKI anew, to be believed for the days
    /// given, or for what a CA of its key is given.
    /// </summary>
    /// <remarks>
    /// What "Sign the CRL anew" in the web interface does, at its permission:
    /// the one to make a CA. Not for a CA whose key has a password: a command
    /// line keeps what was typed at it, and a password belongs in neither its
    /// history nor on its screen - the web interface asks for it.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiSignCRLCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                                 ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiSignCRLCommand)[..^7].ToLowerFirstChar();

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

            if (!cli.MayDo(Permission.Edit(PKIAccess.Authorities), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            if (Arguments.Length < 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            // The last word is the days where it is a number and something is
            // left to name the CA with - a CA may be called "2026".
            Int32? validDays = null;
            var    words     = Arguments[1..];

            if (words.Length > 1 && Int32.TryParse(words[^1], out var days))
            {
                validDays = days;
                words     = words[..^1];
            }

            if (!cli.TryFind(String.Join(" ", words), out var ca, out var error))
                return Task.FromResult<String[]>([ error ]);

            if (ca.KeyEncrypted)
                return Task.FromResult<String[]>([ PKICLI.PasswordsAreNotTyped($"The CRL of the {ca.InWords} '{ca.CommonName}' was not signed") ]);

            if (!cli.PKI.Store.TrySignCRL(ca.Id, null, validDays, out var crl, out error, out _, out _))
                return Task.FromResult<String[]>([ error ]);

            cli.PKI.Log.Notice($"{cli.Caller.Asker} signed the CRL of the {ca.InWords} '{ca.CommonName}' ({ca.Id}) anew: number {crl.Number}, until {crl.NextUpdate:u}.",
                               cli.Caller.Tags("pki", "security"));

            return Task.FromResult<String[]>([
                       $"The CRL of the {ca.InWords} '{ca.CommonName}' is signed anew: number {crl.Number}, {crl.Entries} revoked, until {crl.NextUpdate?.ToLocalTime():yyyy-MM-dd HH:mm}."
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <fingerprint | common name of a CA> [<days>] - sign the CRL of a CA anew, to be believed for <days>";

        #endregion

    }

}
