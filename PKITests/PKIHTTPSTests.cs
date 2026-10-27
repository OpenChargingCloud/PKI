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

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The PKI served over HTTPS of its own, as the node's "web" section and
    /// its switches say it: with the identity the command line put into its
    /// store, its web interface, its sign-in and its JSON API alike - where
    /// the private keys it hands out would otherwise cross the network in the
    /// clear.
    /// </summary>
    public class PKIHTTPSTests
    {

        #region Data

        private const String  NoTimeServers  = """{ "nts": { "groups": { "legal": { "enabled": false } } } }""";

        private String  directory  = "";
        private PKI?    pki;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-https-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task TearDown()
        {

            if (pki is not null)
                await pki.DisposeAsync();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) AnIdentityFile()

        /// <summary>
        /// A TLS server identity for 127.0.0.1 in a PKCS#12 file without a
        /// password, as --import-certificate takes it, and its thumbprint.
        /// </summary>
        private (String File, String Thumbprint) AnIdentityFile()
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request   = new CertificateRequest("CN=PKI web interface", key, HashAlgorithmName.SHA256);
            var names     = new SubjectAlternativeNameBuilder();

            names.AddIpAddress(System.Net.IPAddress.Loopback);
            names.AddDnsName("localhost");

            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));

            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            var file = Path.Combine(directory, "pki-web.p12");

            File.WriteAllBytes(file, certificate.Export(X509ContentType.Pkcs12));

            return (file, CertificateEntry.ThumbprintOf(certificate));

        }

        #endregion


        #region ThePKIServesItsWebInterfaceAndAPIOverHTTPS()

        /// <summary>
        /// --https with --import-certificate tlsServerIdentity=&lt;file&gt;, as
        /// PKICLI passes them on: the PKI keeps the identity, shows it, and
        /// serves its web interface with HSTS, its sign-in with a secure cookie
        /// and its JSON API - all over HTTPS - and says nothing about plain
        /// HTTP.
        /// </summary>
        [Test]
        public async Task ThePKIServesItsWebInterfaceAndAPIOverHTTPS()
        {

            var (file, thumbprint)  = AnIdentityFile();
            var arguments           = NodeArguments.Parse([ "--https", "--import-certificate", $"tlsServerIdentity={file}" ]);

            Assert.That(arguments.Problem, Is.Null);

            pki = await TestPorts.StartedOnFreshPorts(() => {

                var configFile  = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, NoTimeServers);

                var made        = new PKI(HTTPPort:        IPPort.Parse(TestPorts.Free()),
                                          AccountsPath:    Path.Combine(directory, "accounts"),
                                          ConfigFile:      new WWCPConfigFile(configFile),
                                          LogToConsole:    false,
                                          BridgeDebugLog:  false,
                                          Web:             arguments.Web);

                Assert.That(made.ImportCertificates(arguments, out _, new StringWriter(), new StringWriter()), Is.Null);

                return made;

            });

            String? shown           = null;

            using var http          = new HttpClient(new HttpClientHandler {
                                                         CookieContainer                            = new CookieContainer(),
                                                         UseCookies                                 = true,
                                                         ServerCertificateCustomValidationCallback  = (message, served, chain, errors) => {
                                                                                                          shown = served is null ? null : CertificateEntry.ThumbprintOf(served);
                                                                                                          return true;
                                                                                                      }
                                                     }) {
                                          BaseAddress  = new Uri(pki.WebInterfaceURL.ToString()),
                                          Timeout      = TimeSpan.FromSeconds(30)
                                      };

            using var page          = await http.GetAsync("");
            using var signIn        = await http.PostAsync("ext/login", new FormUrlEncodedContent([
                                                                            new KeyValuePair<String, String>("login",     PKI.DefaultAdminUser),
                                                                            new KeyValuePair<String, String>("password",  pki.GeneratedPassword!)
                                                                        ]));
            using var certificates  = await http.GetAsync("api/v1/pki/certificates");

            var session             = signIn.Headers.TryGetValues("Set-Cookie", out var cookies)
                                          ? cookies.FirstOrDefault(cookie => cookie.StartsWith($"{pki.ExtAPI.SessionCookieName}=", StringComparison.Ordinal))
                                          : null;

            Assert.Multiple(() => {

                Assert.That(PKI.CertificateKinds,                                    Does.Contain(CertificateKind.TLSServerIdentity));
                Assert.That(pki.Certificates.ByKind(CertificateKind.TLSServerIdentity).Select(entry => entry.Thumbprint),
                                                                                     Is.EqualTo(new[] { thumbprint }));

                Assert.That(pki.HTTPS,                                               Is.True);
                Assert.That(pki.WebInterfaceURL.ToString(),                          Does.StartWith("https://"));
                Assert.That(shown,                                                   Is.EqualTo(thumbprint));
                Assert.That(pki.PlainHTTPWarning,                                    Is.Null);

                Assert.That(page.StatusCode,                                         Is.EqualTo(HttpStatusCode.OK));
                Assert.That(page.Headers.TryGetValues("Strict-Transport-Security", out var hsts) ? hsts.Single() : null,
                                                                                     Is.EqualTo("max-age=31536000"));

                Assert.That(signIn.IsSuccessStatusCode,                              Is.True, $"{(Int32) signIn.StatusCode}");
                Assert.That(session,                                                 Does.Contain("secure").IgnoreCase);

                Assert.That(certificates.StatusCode,                                 Is.EqualTo(HttpStatusCode.OK), "the JSON API, with the session over HTTPS");

            });

            var configuration = JObject.Parse(await http.GetStringAsync("api/v1/configuration"));

            Assert.That(configuration["http"]?["tls"]?.Value<String>("thumbprint"),  Is.EqualTo(thumbprint));

        }

        #endregion

    }

}
