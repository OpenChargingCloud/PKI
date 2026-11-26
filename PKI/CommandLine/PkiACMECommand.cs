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

using System.Buffers.Text;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Enrollment;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    /// <summary>
    /// What ACME signs - by default and as each profile, below which CA, for
    /// how long and for which names - its accounts, and a new key of an
    /// external account binding for a client to open its account with.
    /// </summary>
    /// <remarks>
    /// What ACME signs is changed in the web interface, or in the
    /// configuration file.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiACMECommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                              ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiACMECommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                           : [];

            if (Arguments.Length == 2 && Arguments[0].Equals(CommandName, StringComparison.OrdinalIgnoreCase))
                return new[] { "accounts", "newKey" }.
                           Where (word => word.StartsWith(Arguments[1], StringComparison.OrdinalIgnoreCase)).
                           Select(word => SuggestionResponse.ParameterCompleted($"{CommandName} {word}"));

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(PKIAccess.Issuance), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var what = Arguments.Length > 1 ? Arguments[1] : "";

            return Task.FromResult(what.ToLowerInvariant() switch {
                                       ""          => Settings(),
                                       "accounts"  => Accounts(),
                                       "newkey"    => NewKey(String.Join(" ", Arguments.Skip(2))),
                                       _           => [ $"Usage: {Help()}" ]
                                   });

        }

        #endregion

        #region (private) Settings()

        private String[] Settings()
        {

            var pki   = cli.PKI;
            var acme  = pki.ACME;

            if (!acme.Enabled)
                return [ $"ACME at {pki.ACMEDirectoryAt()} signs nothing: no CA is named for it." ];

            String Signs(ACMEProfile profile)

                => pki.Store.Get(profile.IssuerId) is { } ca
                       ? $"a {profile.Profile.InWords()} of {profile.ValidDays} days below '{ca.CommonName}' ({ca.Id[..16]})" +
                         (ca.KeyEncrypted ? " - whose key has a password, so that it signs nothing" : "")
                       : $"a {profile.Profile.InWords()} of {profile.ValidDays} days below {profile.IssuerId[..Math.Min(16, profile.IssuerId.Length)]}, which is not in this PKI";

            const String ByDefault = "by default";

            var width = Math.Max(ByDefault.Length,
                                 acme.Profiles.Keys.Select(name => name.Length + 2).DefaultIfEmpty(0).Max());

            return [
                       $"ACME at {pki.ACMEDirectoryAt()} signs:",
                       .. acme.Default is { } byDefault
                              ? new[] { $"  {ByDefault.PadRight(width)}  {Signs(byDefault)}" }
                              : [],
                       .. acme.Profiles.OrderBy(profile => profile.Key, StringComparer.OrdinalIgnoreCase).
                              Select(profile => $"  {$"'{profile.Key}'".PadRight(width)}  {Signs(profile.Value)}"),
                       acme.AllowedNames.Count == 0
                           ? "for every name whoever asks proves to be theirs"
                           : $"for {String.Join(", ", acme.AllowedNames)} and the names below them",
                       $"proven by {String.Join(" or ", acme.Challenges)}{(acme.Challenges.Contains("http-01") && acme.HTTP01Port != 80 ? $", http-01 on port {acme.HTTP01Port}" : "")},",
                       acme.ExternalAccountRequired
                           ? $"to accounts opened with a key of an external account binding only - {pki.ACMEState.ExternalAccountKeys().Count(key => key.BoundTo is null)} not used yet."
                           : "to every account whoever opens one.",
                       $"It has {pki.ACMEState.Accounts().Count(account => account.Status == "valid")} account(s); '{CommandName} accounts' lists them.",
                       .. pki.ACMEState.LoadError is String problem ? new[] { problem } : []
                   ];

        }

        #endregion

        #region (private) Accounts()

        private String[] Accounts()
        {

            var accounts = cli.PKI.ACMEState.Accounts();

            if (accounts.Count == 0)
                return [ "ACME has no account yet." ];

            return [.. accounts.Select(account => $"{account.Id}  {account.Status,-11}  {account.CreatedAt:yyyy-MM-dd}  " +
                                                  $"{cli.PKI.ACMEState.IssuedFor(account.Id).Count,3} certificate(s)  " +
                                                  $"{(account.Contacts.Count == 0 ? "-" : String.Join(", ", account.Contacts.Select(contact => contact.Replace("mailto:", "", StringComparison.OrdinalIgnoreCase))))}" +
                                                  (account.VouchedForBy is null ? "" : $"  (vouched for by '{account.VouchedForBy}')"))];

        }

        #endregion

        #region (private) NewKey(Description)

        private String[] NewKey(String Description)
        {

            if (!cli.MayDo(Permission.Edit(PKIAccess.Issuance), CommandName, out var refused))
                return [ refused ];

            var pki = cli.PKI;

            if (!pki.ACMEState.TryNewExternalAccountKey(Description, cli.Caller.Account?.Id.ToString() ?? "the console", out var key, out var error))
                return [ error ];

            pki.Log.Notice($"{cli.Caller.Asker} made the key '{key.KeyId}' of an external account binding of ACME{(key.Description is null ? "" : $" ({key.Description})")}.",
                           cli.Caller.Tags("pki", "acme", "security"));

            var hmac = Base64Url.EncodeToString(key.MACKey);

            return [
                       $"A key of an external account binding, which opens one account, once:",
                       $"  kid       {key.KeyId}",
                       $"  hmacKey   {hmac}",
                       $"  server    {pki.ACMEDirectoryAt()}",
                       "The MAC key is said this once. With certbot:",
                       $"  certbot register --server {pki.ACMEDirectoryAt()} --eab-kid {key.KeyId} --eab-hmac-key {hmac}",
                       .. pki.ACME.ExternalAccountRequired
                              ? Array.Empty<String>()
                              : [ "ACME opens accounts without such a key, too: \"externalAccountRequired\" is not set." ]
                   ];

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [accounts | newKey [<description>]] - what ACME signs, its accounts, or a new key of an external account binding";

        #endregion

    }

}
