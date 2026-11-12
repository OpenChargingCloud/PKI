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
    /// Revoke a certificate of this PKI for good, for the reason given: it is
    /// in the CRL of its CA from now on, signed anew at once, and its CA's
    /// OCSP responder says "revoked".
    /// </summary>
    /// <remarks>
    /// <para>
    /// What Revoke in the web interface does, at its permission: a CA at the
    /// permission to make one, a server's or a client's certificate at the
    /// permission to sign one. The reason is not left out: what cannot be
    /// taken back is not done by a word too few.
    /// </para>
    /// <para>
    /// The CRL is signed with the key of the CA. Where that key has a
    /// password, nothing is revoked here: a command line keeps what was typed
    /// at it, in its history and on the screen, and a password belongs in
    /// neither - the web interface asks for it.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiRevokeCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                                ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiRevokeCommand)[..^7].ToLowerFirstChar();

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

            if (Arguments.Length < 3 ||
                !RevocationReasons.All.Any(known => RevocationReasons.AsText(known).Equals(Arguments[^1], StringComparison.OrdinalIgnoreCase)) ||
                !RevocationReasons.TryParse(Arguments[^1], out var reason))
            {
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);
            }

            if (!cli.TryFind(String.Join(" ", Arguments[1..^1]), out var certificate, out var error))
                return Task.FromResult<String[]>([ error ]);

            if (!cli.MayDo(Permission.Edit(certificate.Profile.IsCA() ? PKIAccess.Authorities : PKIAccess.Issuance), CommandName, out refused))
                return Task.FromResult<String[]>([ refused ]);

            if (certificate.IssuerId is String issuerId &&
                issuerId != certificate.Id &&
                cli.PKI.Store.Get(issuerId) is { KeyEncrypted: true } issuer)
            {
                return Task.FromResult<String[]>([
                           PKICLI.PasswordsAreNotTyped($"Nothing was revoked: the CRL of the {issuer.InWords} '{issuer.CommonName}' is signed with its key")
                       ]);
            }

            if (!cli.PKI.Store.TryRevoke(certificate.Id, reason.Value, null, cli.Caller.Account?.Id.ToString(),
                                         out var revoked, out error, out var warning, out _, out _))
            {
                return Task.FromResult<String[]>([ error ]);
            }

            cli.PKI.Log.Notice($"{cli.Caller.Asker} revoked the {revoked.InWords} '{revoked.CommonName}' ({revoked.Id}) for {RevocationReasons.AsText(reason.Value)}.",
                               cli.Caller.Tags("pki", "security"));

            if (warning is not null)
                cli.PKI.Log.Warning($"PKI: {warning}", "pki", "security");

            return Task.FromResult<String[]>([
                       $"The {revoked.InWords} '{revoked.CommonName}' ({revoked.Id[..16]}) is revoked for {RevocationReasons.AsText(reason.Value)}, for good.",
                       .. warning is null ? Array.Empty<String>() : [ warning ]
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <fingerprint | common name> <{String.Join(" | ", RevocationReasons.All.Select(RevocationReasons.AsText))}> - revoke a certificate of this PKI for good";

        #endregion

    }

}
