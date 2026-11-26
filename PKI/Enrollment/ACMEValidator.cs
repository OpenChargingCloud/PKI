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
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    /// <summary>
    /// What looks at a challenge of ACME (RFC 8555, section 8): http-01 by a
    /// GET of the key authorization from the name, dns-01 by its digest in a
    /// TXT record below it.
    /// </summary>
    /// <remarks>
    /// The answer is never shown to whoever asked, but for whether it was
    /// right: what a server on the other side said is no business of the
    /// client's, which might have pointed the PKI anywhere.
    /// </remarks>
    public sealed class ACMEValidator : IDisposable
    {

        #region Data

        /// <summary>
        /// How much of an answer to http-01 is read at most: a key
        /// authorization is less than a hundred characters.
        /// </summary>
        public const Int32 MaxHTTP01Answer = 8192;

        private readonly HttpClient httpClient;

        #endregion

        #region Properties

        /// <summary>
        /// The TXT records of a name - what dns-01 looks into. Through the name
        /// servers of the node by default; something else on a bench.
        /// </summary>
        public Func<String, CancellationToken, Task<IReadOnlyList<String>>>  LookupTXT  { get; set; }

        /// <summary>
        /// How long a look at a challenge may take.
        /// </summary>
        public TimeSpan                                                       Timeout    { get; set; } = TimeSpan.FromSeconds(15);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// What looks at challenges, asking the given client for TXT records.
        /// </summary>
        public ACMEValidator(DNSClient DNSClient)
        {

            // Redirects are followed, to HTTPS as well, as Let's Encrypt
            // follows them; the certificate of HTTPS is not looked at, since it
            // is what is to be made. No proxy of the machine is asked: it is the
            // name itself that answers.
            httpClient = new HttpClient(new SocketsHttpHandler {
                                            AllowAutoRedirect          = true,
                                            MaxAutomaticRedirections   = 10,
                                            UseProxy                   = false,
                                            UseCookies                 = false,
                                            ConnectTimeout             = TimeSpan.FromSeconds(10),
                                            SslOptions                 = { RemoteCertificateValidationCallback = (_, _, _, _) => true }
                                        }) {
                             Timeout = System.Threading.Timeout.InfiniteTimeSpan
                         };

            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("OpenChargingCloud-PKI-ACME/1.0");

            LookupTXT = async (name, cancellationToken) => {

                var info = await DNSClient.Query(DomainName.Parse(name),
                                                 [ DNSResourceRecordTypes.TXT ],
                                                 ForceUpdate:        true,
                                                 CancellationToken:  cancellationToken);

                return [.. info.Answers.OfType<TXT>().Select(txt => String.Concat(txt.Strings))];

            };

        }

        #endregion


        #region ValidateAsync(Type, Identifier, Token, KeyAuthorization, HTTP01Port, CancellationToken = default)

        /// <summary>
        /// Look at a challenge: null where it was answered as it should be, and
        /// the problem otherwise.
        /// </summary>
        /// <param name="Type">"http-01" or "dns-01".</param>
        /// <param name="Identifier">The name to prove.</param>
        /// <param name="Token">The token of the challenge.</param>
        /// <param name="KeyAuthorization">The token and the thumbprint of the account's key.</param>
        /// <param name="HTTP01Port">Where http-01 asks: port 80 but on a bench.</param>
        /// <param name="CancellationToken">To give up.</param>
        public async Task<ACMEProblem?> ValidateAsync(String             Type,
                                                      ACMEIdentifier     Identifier,
                                                      String             Token,
                                                      String             KeyAuthorization,
                                                      UInt16             HTTP01Port,
                                                      CancellationToken  CancellationToken = default)
        {

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            timeout.CancelAfter(Timeout);

            try
            {
                return Type switch {
                           "http-01" => await HTTP01(Identifier, Token, KeyAuthorization, HTTP01Port, timeout.Token),
                           "dns-01"  => await DNS01 (Identifier, KeyAuthorization, timeout.Token),
                           _         => new ACMEProblem(400, "malformed", $"'{Type}' is no challenge this PKI looks at.")
                       };
            }
            catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
            {
                return new ACMEProblem(400, "connection", $"{Type}: no answer for '{Identifier.Proven}' within {Timeout.TotalSeconds:0} seconds.");
            }

        }

        #endregion

        #region (private) HTTP01(Identifier, Token, KeyAuthorization, Port, CancellationToken)

        /// <summary>
        /// http-01, RFC 8555, section 8.3: the key authorization at
        /// "/.well-known/acme-challenge/{token}" of the name, over plain HTTP.
        /// </summary>
        private async Task<ACMEProblem?> HTTP01(ACMEIdentifier     Identifier,
                                                String             Token,
                                                String             KeyAuthorization,
                                                UInt16             Port,
                                                CancellationToken  CancellationToken)
        {

            var host = Identifier.Type == "ip" && IPAddress.Parse(Identifier.Value).AddressFamily == AddressFamily.InterNetworkV6
                           ? $"[{Identifier.Value}]"
                           : Identifier.Value;

            var url  = $"http://{host}{(Port == 80 ? "" : $":{Port}")}/.well-known/acme-challenge/{Token}";

            try
            {

                using var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, CancellationToken);

                if (!response.IsSuccessStatusCode)
                    return new ACMEProblem(403, "unauthorized", $"http-01: {url} answered {(Int32) response.StatusCode}.");

                await using var stream = await response.Content.ReadAsStreamAsync(CancellationToken);

                var buffer = new Byte[MaxHTTP01Answer];
                var length = 0;

                while (length < buffer.Length)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(length), CancellationToken);
                    if (read == 0)
                        break;
                    length += read;
                }

                // "The server SHOULD ignore whitespace characters at the end of
                // the body" - RFC 8555, section 8.3.
                var body = Encoding.ASCII.GetString(buffer, 0, length).TrimEnd();

                return body == KeyAuthorization
                           ? null
                           : new ACMEProblem(403, "incorrectResponse", $"http-01: what {url} answered is not the key authorization of the challenge.");

            }
            catch (HttpRequestException e)
            {
                return new ACMEProblem(400, "connection", $"http-01: {url} could not be reached: {e.Message}");
            }

        }

        #endregion

        #region (private) DNS01(Identifier, KeyAuthorization, CancellationToken)

        /// <summary>
        /// dns-01, RFC 8555, section 8.4: the SHA-256 digest of the key
        /// authorization, base64url, as a TXT record of "_acme-challenge" below
        /// the name.
        /// </summary>
        private async Task<ACMEProblem?> DNS01(ACMEIdentifier     Identifier,
                                               String             KeyAuthorization,
                                               CancellationToken  CancellationToken)
        {

            var name      = $"_acme-challenge.{Identifier.Proven}";
            var expected  = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(KeyAuthorization)));

            IReadOnlyList<String> records;

            try
            {
                records = await LookupTXT(name, CancellationToken);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                return new ACMEProblem(400, "dns", $"dns-01: the TXT records of '{name}' could not be read: {e.Message}");
            }

            if (records.Count == 0)
                return new ACMEProblem(400, "dns", $"dns-01: '{name}' has no TXT record.");

            return records.Any(record => record.Trim() == expected)
                       ? null
                       : new ACMEProblem(403, "incorrectResponse", $"dns-01: no TXT record of '{name}' is the digest of the key authorization of the challenge.");

        }

        #endregion


        #region Dispose()

        public void Dispose()
            => httpClient.Dispose();

        #endregion

    }

}
