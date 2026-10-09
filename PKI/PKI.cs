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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// One public key infrastructure: a WWCP node that makes the X.509
    /// certificates every other program of this family is known by - root
    /// CAs, sub-CAs, and certificates for servers and clients below them -
    /// with its JSON API at "/api" and its web interface at "/".
    /// </summary>
    /// <remarks>
    /// <para>
    /// The web interface is a bundle of HTML, CSS and JavaScript built by
    /// webpack from Frontend/ and embedded into this assembly, so that the PKI
    /// is one file to deploy and needs nothing installed beside it. The
    /// browser and the PKI talk over the JSON API and one Server-Sent Events
    /// stream; nothing is rendered on the server.
    /// </para>
    /// <para>
    /// What is the PKI's own is its store of certificates - see
    /// <see cref="PKIStore"/> - and what makes more of them: a root CA, a
    /// sub-CA below a CA, a certificate for a server or a client with a key
    /// made here, and one for the key of a certificate signing request, such
    /// as a charging station sends when it wants a new client certificate for
    /// its CSMS. What every program of this family has - the sign-in, the name
    /// servers, the time servers, the certificates they are held to, the SSH
    /// server and the log - is the node below.
    /// </para>
    /// </remarks>
    public class PKI : WWCPNode
    {

        #region Data

        /// <summary>
        /// The manifest resource prefix of the embedded frontend bundle
        /// (see the EmbedFrontend target of PKI.csproj).
        /// </summary>
        public const            String    HTTPRoot         = "cloud.charging.open.PKI.HTTPRoot.";

        /// <summary>
        /// The directory the certificates of the PKI live in, beside the
        /// configuration file, unless another is given.
        /// </summary>
        public const            String    DefaultPKIDirectory  = "pki";

        /// <summary>
        /// The TCP port the web interface listens on, unless another is given.
        /// </summary>
        /// <remarks>
        /// Clear of the ports of its siblings - the vehicle's 2347, the
        /// station's 2348, the local controller's 2350, the CSMS's 2351, the
        /// gateway's 2353 and the e-mobility provider's and the hub's above it
        /// - so that the PKI started on the same bench as everything it makes
        /// certificates for does not fight any of them over a port.
        /// </remarks>
        public static new readonly  IPPort    DefaultHTTPPort  = IPPort.Parse(2360);

        /// <summary>
        /// What kind of node a PKI is.
        /// </summary>
        /// <remarks>
        /// "PKI" after "OpenChargingCloud" in the Server header,
        /// "pki-2026-10-09.log" for a day's log file, and "PKI" as the
        /// organization its accounts are in - which a first start writes into
        /// the accounts file and every start after it reads back, so it is the
        /// one that must never change.
        /// </remarks>
        public static readonly      NodeKind  PKIKind          = new (
                                                                     Name:           "PKI",
                                                                     Tag:            "pki",
                                                                     Product:        "PKI",
                                                                     Organization:   "PKI",
                                                                     LogFilePrefix:  "pki"
                                                                 );

        /// <summary>
        /// The kinds of certificate the node's own store keeps: the four of
        /// TLS, and none of the seven of ISO 15118, which are a vehicle's.
        /// </summary>
        /// <remarks>
        /// The roots a time server or a name server of this PKI may chain to
        /// where the machine knows no root of theirs, and the certificates they
        /// present, kept to hold them to by their fingerprints. Not the
        /// certificates the PKI makes: those are in a store of their own, see
        /// <see cref="Store"/>.
        /// </remarks>
        public static readonly      IReadOnlyList<CertificateKind>  CertificateKinds  = CertificateKindExtensions.TLS;

        #endregion

        #region Properties

        /// <summary>
        /// The JSON API the browser talks to.
        /// </summary>
        public PKIHTTPAPI  API    { get; }

        /// <summary>
        /// The certificates this PKI made, and what makes more of them.
        /// </summary>
        public PKIStore    Store  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// One PKI, with its web interface.
        /// </summary>
        /// <param name="HTTPHostname">The address the web interface listens on; 127.0.0.1 by default.</param>
        /// <param name="HTTPPort">The TCP port it listens on; <see cref="DefaultHTTPPort"/> by default.</param>
        /// <param name="HTTPServer">An HTTP server to register within, or null to make one.</param>
        /// <param name="BasePath">What everything of this PKI sits below; the root by default. Something else only where several of these programs share one HTTP server.</param>
        /// <param name="HTTPRootPath">Where the JSON API sits; "/api" below <paramref name="BasePath"/> by default.</param>
        /// <param name="ExtAPI">An HTTPExt API to sign in against, or null for one of this PKI's own. Handing one in is what makes one sign-in open several of these programs at once.</param>
        /// <param name="AccountsPath">The directory the accounts live in between starts.</param>
        /// <param name="ConfigFile">Where the configuration lives between starts: one file, whose sections the node below reads.</param>
        /// <param name="DNSClient">How to resolve names, or null to make a client.</param>
        /// <param name="NTSClient">Where to read the time, or null to make a client.</param>
        /// <param name="Frontend">Where the web interface comes from, or null for the embedded bundle.</param>
        /// <param name="CertificatesPath">The directory the node's own certificate store lives in between starts; what the configuration file says, or "certificates" beside it, by default.</param>
        /// <param name="PKIPath">The directory the certificates this PKI makes live in, with their keys; "pki" beside the configuration file by default.</param>
        /// <param name="Log">Where everything that happens is written, or null to make a log.</param>
        /// <param name="LogToConsole">Whether the log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">How much of it reaches the console.</param>
        /// <param name="LogPath">The directory the log files are written to, or null to write none.</param>
        /// <param name="BridgeDebugLog">Whether what the libraries below write with DebugX is picked up.</param>
        /// <param name="TimeProvider">The clock, or null for the system one.</param>
        /// <param name="SSH">What the program says about serving the command line over SSH; nothing by default - see SSHSettings.</param>
        public PKI(IIPAddress?            HTTPHostname       = null,
                   IPPort?                HTTPPort           = null,
                   HTTPServer?            HTTPServer         = null,
                   HTTPPath?              BasePath           = null,
                   HTTPPath?              HTTPRootPath       = null,
                   HTTPExtAPI?            ExtAPI             = null,
                   String?                AccountsPath       = null,
                   WWCPConfigFile?        ConfigFile         = null,
                   DNSClient?             DNSClient          = null,
                   NTSClient?             NTSClient          = null,
                   IStaticContentSource?  Frontend           = null,
                   String?                CertificatesPath   = null,
                   String?                PKIPath            = null,
                   EventLog?              Log                = null,
                   Boolean                LogToConsole       = true,
                   LogLevel               ConsoleLogLevel    = LogLevel.Info,
                   String?                LogPath            = null,
                   Boolean                BridgeDebugLog     = true,
                   TimeProvider?          TimeProvider       = null,
                   SSHSettings?           SSH                = null)

            : base(Kind:               PKIKind,
                   Version:            typeof(PKI).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
                   HTTPPort:           HTTPPort ?? DefaultHTTPPort,
                   HTTPHostname:       HTTPHostname,
                   HTTPServer:         HTTPServer,
                   BasePath:           BasePath,
                   HTTPRootPath:       HTTPRootPath,
                   ExtAPI:             ExtAPI,
                   AccountsPath:       AccountsPath,
                   Resources:          PKIAccess.Resources,
                   RoleDefinitions:    PKIAccess.Roles,
                   ConfigFile:         ConfigFile,
                   DNSClient:          DNSClient,
                   NTSClient:          NTSClient,
                   Frontend:           Frontend ?? new EmbeddedContentSource(HTTPRoot, typeof(PKI).Assembly),
                   CertificatesPath:   CertificatesPath,
                   CertificateKinds:   CertificateKinds,
                   Log:                Log,
                   LogToConsole:       LogToConsole,
                   ConsoleLogLevel:    ConsoleLogLevel,
                   LogPath:            LogPath,
                   BridgeDebugLog:     BridgeDebugLog,
                   TimeProvider:       TimeProvider,
                   SSH:                SSH)

        {

            #region The certificates this PKI made

            // Beside the configuration file rather than below the working
            // directory, for the reason the node's own store is: a PKI that
            // moved when somebody typed "dotnet run" from somewhere else would
            // be a different PKI - with different CAs.
            this.Store = new PKIStore(
                             PKIPath ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(this.ConfigFile.Path)) ?? ".", DefaultPKIDirectory),
                             this.TimeProvider
                         );

            foreach (var passedOver in Store.PassedOver)
                this.Log.Warning($"PKI: {passedOver}", "pki", "security");

            this.Log.Info($"The PKI keeps {Store.Count} certificate(s) in '{Store.Directory}'. " +
                           "The private keys of its CAs are kept there unencrypted: whoever can read that directory can sign as every one of them.",
                          "pki", "security");

            #endregion

            #region The JSON API

            this.Log.Info(
                OwnsExtAPI
                    ? $"The accounts of this PKI are in '{this.ExtAPI.DatabaseFileName}', its HTTPExt API at '{this.ExtAPI.RootPath}'."
                    : $"This PKI signs in against accounts it shares, at '{this.ExtAPI.RootPath}'.",
                "web", "http"
            );

            // The JSON API at "/api", beside the web interface the node below
            // has already put at "/". The more specific of the two, so that an
            // unknown /api path never reaches the single-page-application
            // stub.
            this.API = new PKIHTTPAPI(
                           HTTPServer:  this.HTTPServer,
                           PKI:         this,
                           ExtAPI:      this.ExtAPI,
                           Log:         this.Log,
                           APIPath:     this.HTTPRootPath,
                           Version:     Version
                       );

            #endregion

        }

        #endregion


        #region (protected override) OnStarted()

        /// <summary>
        /// What a PKI says once it is up: where its API is.
        /// </summary>
        protected override Task OnStarted()
        {

            Log.Info($"The JSON API is at {APIURL}v1/status", "web", "http");

            return Task.CompletedTask;

        }

        #endregion


        #region ConfigurationJSON()

        /// <summary>
        /// What this PKI is, as the Configuration page of the web interface
        /// reads it: what the node below says of itself - the assemblies it was
        /// built from, one line per repository - and on top the PKI and its
        /// store.
        /// </summary>
        public override JObject ConfigurationJSON()
        {

            var json = base.ConfigurationJSON();

            var all  = Store.Find();

            // First, because it is the card the page leads with.
            json.AddFirst(new JProperty("pki",        new JObject(
                              new JProperty("version",        Version),
                              new JProperty("createdAt",      CreatedAt.ToString("o")),
                              new JProperty("machine",        Environment.MachineName),
                              new JProperty("runtime",        Environment.Version.ToString()),
                              new JProperty("os",             Environment.OSVersion.ToString())
                          )));

            json.Property("pki")!.AddAfterSelf(new JProperty("store", new JObject(
                              new JProperty("directory",      Store.Directory),
                              new JProperty("rootCAs",        all.Count(certificate => certificate.Profile == CertificateProfile.RootCA)),
                              new JProperty("subCAs",         all.Count(certificate => certificate.Profile == CertificateProfile.SubCA)),
                              new JProperty("servers",        all.Count(certificate => certificate.Profile == CertificateProfile.Server)),
                              new JProperty("clients",        all.Count(certificate => certificate.Profile == CertificateProfile.Client))
                          )));

            return json;

        }

        #endregion

    }

}
