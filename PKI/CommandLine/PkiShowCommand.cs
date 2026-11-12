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
    /// One certificate of this PKI, with what its details in the web
    /// interface say - but neither its PEM nor its key.
    /// </summary>
    /// <remarks>
    /// Named by the beginning of its fingerprint, as 'pki' writes it, or by
    /// its common name. At the permission its details are shown with.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class PkiShowCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                              ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: the name of the class without its last
        /// seven characters.
        /// </summary>
        public static readonly String CommandName = nameof(PkiShowCommand)[..^7].ToLowerFirstChar();

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

            if (Arguments.Length < 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (!cli.TryFind(String.Join(" ", Arguments[1..]), out var certificate, out var error))
                return Task.FromResult<String[]>([ error ]);

            var store   = cli.PKI.Store;
            var now     = cli.PKI.TimeProvider.GetUtcNow();
            var issuer  = certificate.IssuerId is null || certificate.IssuerId == certificate.Id ? null : store.Get(certificate.IssuerId);

            var signer  = certificate.Profile == CertificateProfile.RootCA
                              ? "itself"
                              : issuer is null
                                    ? $"{certificate.Issuer}, which is not in this PKI"
                                    : $"{certificate.Issuer} ({issuer.Id[..16]})";

            var key     = certificate.HasPrivateKey
                              ? certificate.KeyEncrypted ? "kept here with a password" : "kept here without a password"
                              : certificate.FromCSR      ? "of a CSR, not kept here"   : "not kept here";

            var lines   = new List<String> {
                              $"{certificate.InWords} '{certificate.CommonName}'",
                              $"  fingerprint  {certificate.Id}",
                              $"  subject      {certificate.Subject}",
                              $"  issuer       {signer}",
                              $"  serial       {certificate.SerialNumber}",
                              $"  valid        {certificate.NotBefore:u} until {certificate.NotAfter:u}, {certificate.StatusAt(now)}",
                              $"  key          {certificate.KeyAlgorithm}, {key}"
                          };

            if (certificate.SubjectAlternativeNames.Count > 0)
                lines.Add($"  names        {String.Join(", ", certificate.SubjectAlternativeNames)}");

            if (certificate.PathLength is Int32 pathLength)
                lines.Add($"  path length  {pathLength}");

            lines.Add($"  made         {certificate.CreatedAt:u}{(certificate.CreatedBy is null ? "" : $" by '{certificate.CreatedBy}'")}");

            if (store.RevocationOf(certificate.Id) is { } revocation)
                lines.Add($"  revoked      {revocation.RevokedAt:u} for {RevocationReasons.AsText(revocation.Reason)}{(revocation.RevokedBy is null ? "" : $" by '{revocation.RevokedBy}'")}");

            var chain = store.Chain(certificate.Id);

            if (chain.Count > 1)
                lines.Add($"  chain        {String.Join(" < ", chain.Select(one => one.CommonName))}");

            if (certificate.Profile.IsCA())
            {

                lines.Add($"  signed       {store.IssuedBy(certificate.Id).Count} certificate(s) of this PKI");

                lines.Add(store.CRLInfoOf(certificate.Id) is { } crl
                              ? $"  CRL          number {crl.Number} of {crl.ThisUpdate:u}{(crl.NextUpdate is DateTimeOffset next ? $", until {next:u}" : "")}, {crl.Entries} revoked" +
                                (store.Addresses is { } at ? $", at {at.CRL(certificate.Id)}" : "")
                              : "  CRL          none yet");

                if (store.Addresses is { } addresses)
                    lines.Add($"  OCSP         {addresses.OCSP}");

            }

            return Task.FromResult<String[]>([.. lines]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <fingerprint | common name> - one certificate of this PKI: who it is about, who signed it, until when it holds, its key, its chain and its revocation";

        #endregion

    }

}
