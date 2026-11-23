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

using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.PKI;
using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Enrollment;
using cloud.charging.open.PKI.Revocation;
using cloud.charging.open.PKI.Configuration;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// The registration authorities of this PKI - a CSMS, say - that connect
    /// over a WebSocket of the messages of a PKI, on a port of its own, or over
    /// the SSH subsystem of those messages of the node's SSH server, to have the
    /// CSR of a charging station signed, and to ask what this PKI knows of its
    /// certificates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What connects is written down as a connection</b> of the type
    /// "RegistrationAuthority", one the other end makes, in the store of
    /// connections beside the configuration file. Nothing that is not written
    /// down gets in, whatever it signs in with.
    /// </para>
    /// <para>
    /// <b>Who signs in is decided as at the WebSocket port of OpenADR of a grid
    /// operator</b>, by the same checks (<see cref="WebSocketSignIns"/>) and the
    /// same kind of logins (<see cref="WebSocketLogins"/>): a password, a one-time
    /// password, a TLS client certificate of a chain this PKI accepts or the key
    /// pin of one - and over SSH a password, a one-time password bound to the
    /// session or an SSH key. A login of a registration authority over SSH gets
    /// the subsystem of the messages, and nothing else: no command line.
    /// </para>
    /// <para>
    /// <b>What it may sign is what EST signs</b>: a CSR is signed at the label of
    /// EST the request names - or without one - below the CA, as the profile and
    /// for as long as the "est" of the "pki" section says, and nothing is signed
    /// where it says nothing. A certificate is revoked by the registration
    /// authority that had it signed, by no other; what is valid, what is
    /// revoked, the CA certificates and the CRLs every one of them may ask.
    /// </para>
    /// </remarks>
    public partial class PKI
    {

        #region Data

        /// <summary>
        /// The listener of the WebSocket port of the messages of a PKI, as the
        /// node's certificate store names it: what a registration authority
        /// connecting to it is shown.
        /// </summary>
        public const String RAListener = "ra";

        /// <summary>
        /// What the messages of a PKI over SSH are called in what the SSH server says.
        /// </summary>
        public const String PKIOverSSHLabel = "PKI";

        /// <summary>
        /// What a certificate signed for a registration authority says it was
        /// created by, before the login: "ra:csms-01". What it may revoke is what
        /// says its own login.
        /// </summary>
        public const String CreatedByPrefix = "ra:";

        /// <summary>
        /// What the port is to the log, where it can not be had.
        /// </summary>
        public static readonly NodePort              RAServerPort  = new ("The WebSocket server of the PKI");

        /// <summary>
        /// What the door of the WebSocket port calls the port and who comes to it.
        /// </summary>
        public static readonly WebSocketSignInWords  RAWords       = new () {
                                                                         Port         = "the WebSocket port of the PKI",
                                                                         Who          = "A registration authority",
                                                                         PinnedLogin  = "a registration authority",
                                                                         Realm        = "PKI",
                                                                         Tags         = [ "pki", "ra" ],
                                                                         InboundTags  = [ "pki", "ra" ]
                                                                     };

        private RAServerConfiguration                         raServerSettings   = new RAServerConfiguration().Effective();
        private StreamWebSocketServer?                        raServer;
        private LoginSSHSignIns?                              raSSHSignIns;

        private volatile Boolean                              raServerStarted;
        private volatile Boolean                              raServerTLS;
        private volatile Boolean                              pkiOverSSHServed;

        /// <summary>
        /// How many channels each connection of the store is in over now, by its id.
        /// </summary>
        private readonly ConcurrentDictionary<String, Int32>  rasIn              = new ();

        /// <summary>
        /// The logins in now, and over how many channels each.
        /// </summary>
        private readonly ConcurrentDictionary<String, Int32>  raLoginsIn         = new ();

        private readonly CancellationTokenSource              rasStopping        = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Which registration authorities may sign in over a WebSocket or over SSH, and with what.
        /// </summary>
        public WebSocketLogins         WebSocketLogins         { get; private set; } = default!;

        /// <summary>
        /// Which chains the certificate of a registration authority connecting
        /// over the WebSocket port of the PKI may lead to.
        /// </summary>
        public ClientTrustStore        ClientTrust             { get; private set; } = default!;

        /// <summary>
        /// Who comes in at the WebSocket port of the PKI: the sign-in checks of its door.
        /// </summary>
        public WebSocketSignIns        RASignIns               { get; private set; } = default!;

        /// <summary>
        /// What the WebSocket port of the PKI presents, out of the node's store:
        /// the listener "ra".
        /// </summary>
        public ListenerCertificate     RAServerCertificate     { get; private set; } = default!;

        /// <summary>
        /// What the WebSocket server of the PKI is configured as, with every
        /// field filled in.
        /// </summary>
        public RAServerConfiguration   RAServerSettings
            => raServerSettings;

        /// <summary>
        /// The WebSocket server of the PKI, once it is built.
        /// </summary>
        public StreamWebSocketServer?  RAServer
            => raServer;

        /// <summary>
        /// Whether the WebSocket server of the PKI is listening right now.
        /// </summary>
        public Boolean                 RAServerRunning
            => raServerStarted;

        /// <summary>
        /// Whether the WebSocket port of the PKI speaks TLS, as decided when it started.
        /// </summary>
        public Boolean                 RAServerTLS
            => raServerTLS;

        /// <summary>
        /// Whether the messages of a PKI are served over SSH right now.
        /// </summary>
        public Boolean                 PKIOverSSHServed
            => pkiOverSSHServed;

        /// <summary>
        /// The logins in over a WebSocket or over SSH now.
        /// </summary>
        public IReadOnlyList<String>   RALoginsIn
            => [.. raLoginsIn.Where(login => login.Value > 0).Select(login => login.Key)];

        #endregion


        #region (private) BuildRAServer()

        /// <summary>
        /// The stores of who connects as a registration authority over a
        /// WebSocket or over SSH, the WebSocket server and the subsystem over
        /// SSH. Nothing listens yet.
        /// </summary>
        private void BuildRAServer()
        {

            var directory = Path.GetDirectoryName(Path.GetFullPath(ConfigFile.Path)) ?? ".";

            raServerSettings = (ReadTheRAServer() ?? new RAServerConfiguration()).Effective();

            #region The connections: registration authorities that connect

            Connections = new ConnectionStore(
                              Path.Combine(directory, ConnectionStore.DefaultDirectoryName),
                              TimeProvider,
                              NodeNoun
                          ) {

                              // A registration authority, and nothing else: it
                              // connects, and this PKI connects to nothing.
                              Rules = new ConnectionRules {
                                          Types                  = [ ConnectionType.RegistrationAuthority ],
                                          Outbound               = false,
                                          OCPP1_6                = false,
                                          NamesTheNodeItLeadsTo  = false
                                      }

                          };

            Connections.OnConnectionsChanged += SayWhichRAIsWaitedFor;
            Connections.OnNotice             += (level, message) => Log.Log(level, message, "pki", "connections");

            // What every node that keeps connections has, though this one makes
            // none: the key its connections would sign in over SSH with.
            SshKey = new SshClientKey(
                         Path.Combine(Connections.Path, SshClientKey.DirectoryName),
                         $"pki@{Environment.MachineName}",
                         NodeNoun:  NodeNoun
                     );

            SshKey.OnNotice += (level, message) => Log.Log(level, message, "pki", "connections", "ssh", "security");

            #endregion

            #region What it presents, out of the node's store

            ListenerCertificates.KeepServingLast(RAListener);

            RAServerCertificate = ListenerCertificates.For(RAListener, "the WebSocket port of the PKI");

            #endregion

            #region The two stores of who signs in

            ClientTrust      = new ClientTrustStore(
                                   Path.Combine(directory, ClientTrustStore.DefaultDirectoryName),
                                   TimeProvider,
                                   NodeNoun,
                                   "registration authority"
                               );

            ClientTrust.OnNotice += (level, message) => Log.Log(level, message, "pki", "tls", "trust");

            ClientTrust.KeepToItsOwner();

            WebSocketLogins  = new WebSocketLogins(
                                   Path.Combine(directory, WebSocketLogins.DefaultFileName),
                                   TimeProvider,
                                   NodeNoun
                               );

            WebSocketLogins.OnNotice += (level, message) => Log.Log(level, message, "pki", "ra", "auth");

            if (!WebSocketLogins.TryLoad(out var loginsError))
                throw new InvalidOperationException($"{loginsError} Repair or remove it and start again.");

            WebSocketLogins.OnChanged += () => {

                if (raServer is not null)
                    RASignIns.ApplyLogins(raServer);

                RecheckSSHSessions();

            };

            #endregion

            #region The door of the WebSocket port

            RASignIns = new WebSocketSignIns(
                            Logins:               WebSocketLogins,
                            ClientTrust:          ClientTrust,
                            SignInBrake:          SignInBrake,
                            Log:                  Log,
                            Authentications:      () => raServerSettings.ClientAuthentication ?? RAServerConfiguration.DefaultClientAuthentication,
                            OverTLS:              () => raServerTLS,
                            ChecksRevocation:     () => raServerSettings.CheckCertificateRevocation == true,
                            SaysSignIns:          () => true,
                            InboundConnectionOf:  (server, name) => InboundConnectionOf(ProtocolVersion.PKI, name),
                            LetInAsInbound:       LetInAsInbound,
                            LetInOthers:          (connection, login, how, detail, byCertificate) =>
                                                      $"'{login}' is no registration authority that connects here: no connection is written down that comes under that name",
                            Words:                RAWords
                        );

            #endregion

            #region The server

            raServer = new StreamWebSocketServer(
                           raServerSettings.Address,
                           raServerSettings.TCPPort ?? RAServerConfiguration.DefaultTCPPort,
                           [ PKIWireNames.Subprotocol ],
                           $"OpenChargingCloud {Kind.Product} v{Version}",
                           I18NString.Create($"The registration authorities of this {NodeNoun}"),
                           null,
                           RASignIns.ValidateCertificate,
                           true,
                           raServerSettings.CheckCertificateRevocation,
                           TextLines: true
                       );

            // A UDP port is opened by nobody who did not ask for it.
            raServer.AcceptHTTP3 = false;

            raServer.OnValidateWebSocketConnection += RASignIns.Validate;
            RASignIns.ApplyLogins(raServer);

            raServer.OnStreamConnection += (connection, stream) => _ = ServeOverWebSocket(connection, stream);

            #endregion

            #region The messages over SSH, on the node's SSH server

            raSSHSignIns = new LoginSSHSignIns(
                               WebSocketLogins,
                               PKIWireNames.SshSubsystem,
                               () => pkiOverSSHServed,
                               TimeProvider,
                               () => SSHSubsystems.Select(subsystem => subsystem.Name)
                           );

            raSSHSignIns.OnNotice += (level, message) => Log.Log(level, message, "pki", "ra", "auth", "ssh");

            AddSSHSignIns(raSSHSignIns);

            #endregion

            Log.Info(
                raServerSettings.IsEnabled
                    ? $"The WebSocket server of the PKI will listen on {raServerSettings.Address}:{raServerSettings.TCPPort}, " +
                      $"speaking {PKIWireNames.Subprotocol}" +
                      (raServerSettings.TakesSSH ? $", and over the SSH subsystem {PKIWireNames.SshSubsystem} as well." : ".")
                    : "The WebSocket server of the PKI is switched off; no registration authority connects over a WebSocket or over SSH.",
                "pki", "ra"
            );

        }

        #endregion

        #region (private) ReadTheRAServer()

        /// <summary>
        /// The "webSocketServer" section of the configuration file, as it is when
        /// the PKI starts.
        /// </summary>
        /// <exception cref="InvalidOperationException">When the section says something this PKI cannot do.</exception>
        private RAServerConfiguration? ReadTheRAServer()
        {

            if (!ConfigFile.TryLoadDocument(out var document, out _) ||
                document[RAServerConfiguration.SectionName] is not JToken section ||
                section.Type == JTokenType.Null)
                return null;

            if (section is not JObject json)
                throw new InvalidOperationException($"'{ConfigFile.Path}': '{RAServerConfiguration.SectionName}' must be an object: the WebSocket server of the PKI.");

            if (!RAServerConfiguration.TryParse(json, out var configuration, out var error))
                throw new InvalidOperationException($"'{ConfigFile.Path}': {error}");

            return configuration;

        }

        #endregion

        #region (private) StartRAServer() / StopRAServer()

        /// <summary>
        /// Start listening for the registration authorities, where it is meant
        /// to - and serve the messages over SSH, where the section says so.
        /// </summary>
        private async Task StartRAServer()
        {

            if (raServerStarted || !raServerSettings.IsEnabled || raServer is null)
            {
                SayWhichRAIsWaitedFor();
                return;
            }

            var wantsTLS = (raServerSettings.ClientAuthentication ?? RAServerConfiguration.DefaultClientAuthentication).Any(authentication => authentication.IsOverTLS());

            raServerTLS = wantsTLS && RAServerCertificate.Choose() is not null;

            raServer.ServerCertificateChainSelector = raServerTLS
                                                          ? (server, client) => RAServerCertificate.Current
                                                          : null;

            if (wantsTLS && !raServerTLS)
                Log.Warning(
                    "HTTP authentication over TLS or a TLS client certificate is configured, but there is no server certificate - so the " +
                    "WebSocket port of the PKI is unencrypted and only HTTP authentication without TLS can be used on it. Make a TLS server " +
                    $"identity for the listener '{RAListener}'; the port encrypts from the next start.",
                    "pki", "ra", "tls"
                );

            try
            {
                await raServer.Start();
            }
            catch (SocketException problem)
            {
                throw new PortUnavailableException(
                          raServerSettings.TCPPort ?? RAServerConfiguration.DefaultTCPPort,
                          problem,
                          RAServerPort
                      );
            }

            raServerStarted = true;

            Log.Notice(
                $"The registration authorities connect to {(raServerTLS ? "wss" : "ws")}://{raServerSettings.Address}:{raServerSettings.TCPPort}/<its name> " +
                $"({(raServerTLS ? "TLS" : "unencrypted")}, {WebSocketLogins.EnabledCount} login(s), {ClientTrust.EnabledCount} accepted chain(s)).",
                "pki", "ra"
            );

            if (raServerSettings.TakesSSH)
                ServePKIOverSSH();

            SayWhichRAIsWaitedFor();

        }

        /// <summary>
        /// Stop listening for the registration authorities: whoever is in is let go of.
        /// </summary>
        private async Task StopRAServer()
        {

            await rasStopping.CancelAsync();

            if (!raServerStarted)
                return;

            raServerStarted = false;

            StopServingPKIOverSSH();

            if (raServer is not null)
                await raServer.Shutdown($"The {NodeNoun} is shutting down.");

            Log.Info("The WebSocket server of the PKI has stopped listening.", "pki", "ra");

        }

        #endregion

        #region (private) ServePKIOverSSH() / StopServingPKIOverSSH()

        private void ServePKIOverSSH()
        {

            if (pkiOverSSHServed)
                return;

            pkiOverSSHServed = true;

            try
            {
                AddSSHSubsystem(new SSHSubsystem(
                                    PKIWireNames.SshSubsystem,
                                    PKIOverSSHLabel,
                                    ServeOverSSH
                                ));
            }
            catch (Exception e)
            {
                pkiOverSSHServed = false;
                Log.Critical($"The messages of the PKI could not be served over SSH: {e.Message}", "pki", "ra", "ssh");
                return;
            }

            if (!SSHEnabled)
                Log.Warning($"The messages of the PKI over SSH are switched on, but the SSH server of this {NodeNoun} is off - so no registration authority can connect over SSH.",
                            "pki", "ra", "ssh");

            else
                Log.Notice($"The registration authorities may connect over SSH as well: {SSHURL}, subsystem {PKIWireNames.SshSubsystem}, host key {SSHHostKey ?? "not known yet"}.",
                           "pki", "ra", "ssh");

        }

        private void StopServingPKIOverSSH()
        {

            if (!pkiOverSSHServed)
                return;

            pkiOverSSHServed = false;

            RemoveSSHSubsystem(PKIWireNames.SshSubsystem);

        }

        #endregion


        #region (private) ServeOverSSH(Context, CancellationToken)

        /// <summary>
        /// One session of the subsystem of the messages of a PKI: let in where
        /// its login is written down as a registration authority that connects
        /// over SSH, and served until it ends.
        /// </summary>
        private async ValueTask ServeOverSSH(SshSubsystemContext  Context,
                                             CancellationToken    CancellationToken)
        {

            var login  = Context.Session.Username;
            var from   = Context.Session.Peer?.ToString() ?? "somewhere";

            if (InboundConnectionOf(ProtocolVersion.PKI, login.ToString()) is not ConnectionEntry entry)
            {
                Log.Warning($"'{login}' asked for the messages of the PKI over SSH from {from}, and is no registration authority that connects here: no connection is written down that comes under that name.",
                            "pki", "ra", "ssh", "auth");
                return;
            }

            if (!entry.IsSSH)
            {
                Log.Warning($"'{login}' connects to this {NodeNoun} over a WebSocket, and came over SSH from {from}.", "pki", "ra", "ssh", "auth");
                return;
            }

            if (!entry.AutoConnect)
            {
                Log.Warning($"'{login}' is the name '{entry.Description.FirstText()}' comes under, a connection that is switched off.", "pki", "ra", "ssh", "auth");
                return;
            }

            using var both = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, rasStopping.Token);

            await Serve(entry, login, Context.Channel.AsStream(), from, "SSH", both.Token);

        }

        #endregion

        #region (private) ServeOverWebSocket(Connection, Stream)

        /// <summary>
        /// One WebSocket of the messages of a PKI, let in by its door as the
        /// connection it came under: served until it ends.
        /// </summary>
        private async Task ServeOverWebSocket(WebSocketServerConnection  Connection,
                                              WebSocketMessageStream     Stream)
        {

            if (Connection.TryGetCustomData(InboundConnectionKey) is not String id ||
                Connections.Connections.FirstOrDefault(entry => entry.Id == id) is not ConnectionEntry entry ||
                entry.InboundName is not String name)
            {
                // The door lets in nothing else; should it ever, nothing is served.
                Log.Warning($"A WebSocket of the PKI from {Connection.RemoteSocket} came in as no registration authority that connects here, and is closed.", "pki", "ra", "auth");
                Stream.Dispose();
                return;
            }

            await Serve(entry,
                        User_Id.Parse(name),
                        Stream,
                        Connection.RemoteSocket.ToString(),
                        raServerTLS ? "WebSocket TLS" : "WebSocket",
                        rasStopping.Token);

        }

        #endregion

        #region (private) Serve(Entry, Login, Stream, From, Transport, CancellationToken)

        /// <summary>
        /// Answer the messages of a PKI over the given stream of lines to what
        /// came in as the given connection, until it ends.
        /// </summary>
        private async Task Serve(ConnectionEntry    Entry,
                                 User_Id            Login,
                                 Stream             Stream,
                                 String             From,
                                 String             Transport,
                                 CancellationToken  CancellationToken)
        {

            await using var channel = new PKIMessageChannel(
                                          Stream,
                                          (action, payload, cancellationToken) => Answer(Entry, Login, action, payload)
                                      );

            rasIn.     AddOrUpdate(Entry.Id,          1, (_, count) => count + 1);
            raLoginsIn.AddOrUpdate(Login.ToString(),  1, (_, count) => count + 1);

            Record(Entry, ConnectionStatus.Connected, $"'{Login}' is connected over {Transport}, speaking the messages of a PKI.");

            Log.Info($"The registration authority '{Login}' connected from {From} over {Transport}.", "pki", "ra", "connections");

            try
            {
                await channel.Ended.WaitAsync(CancellationToken);
            }
            catch (OperationCanceledException)
            { }
            finally
            {

                raLoginsIn.AddOrUpdate(Login.ToString(), 0, (_, count) => Math.Max(count - 1, 0));
                var left = rasIn.AddOrUpdate(Entry.Id, 0, (_, count) => Math.Max(count - 1, 0));

                Log.Info($"The registration authority '{Login}' is no longer connected over {Transport}.", "pki", "ra", "connections");

                if (left == 0)
                {
                    rasIn.TryRemove(KeyValuePair.Create(Entry.Id, 0));
                    SayWhichRAIsWaitedFor();
                }

            }

        }

        #endregion


        #region (private) Answer(Entry, Login, Action, Payload)

        /// <summary>
        /// The answer to one request of a registration authority.
        /// </summary>
        private Task<JObject> Answer(ConnectionEntry  Entry,
                                     User_Id          Login,
                                     String           Action,
                                     JObject          Payload)
        {

            // Switched off since it came in: asked nothing more.
            if (Connections.Connections.FirstOrDefault(entry => entry.Id == Entry.Id) is not ConnectionEntry now || !now.AutoConnect)
                throw new PKIException(PKIErrorCodes.SecurityError, $"'{Login}' is no registration authority of this {NodeNoun} any more.");

            return Task.FromResult(Action switch {
                       PKIActions.SignCertificate       => SignCertificate     (Login, SignCertificateRequest.     Parse(Payload)).ToJSON(),
                       PKIActions.GetCACertificates     => GetCACertificates   (       GetCACertificatesRequest.   Parse(Payload)).ToJSON(),
                       PKIActions.GetCertificateStatus  => GetCertificateStatus(       GetCertificateStatusRequest.Parse(Payload)).ToJSON(),
                       PKIActions.GetCRL                => GetCRL              (       GetCRLRequest.              Parse(Payload)).ToJSON(),
                       PKIActions.RevokeCertificate     => RevokeCertificate   (Login, RevokeCertificateRequest.   Parse(Payload)).ToJSON(),
                       _                                => throw new PKIException(PKIErrorCodes.NotImplemented, $"'{Action}' is nothing a PKI is asked: {String.Join(", ", PKIActions.All)}.")
                   });

        }

        #endregion

        #region (private) SignCertificate(Login, Request)

        private SignCertificateResponse SignCertificate(User_Id                 Login,
                                                        SignCertificateRequest  Request)
        {

            var at = Request.Label is null ? "without a label" : $"at the label '{Request.Label}'";

            if (EST.For(Request.Label) is not ESTProfile profile)
                return new SignCertificateResponse(PKIStatus.Rejected,
                                                   StatusInfo: new PKIStatusInfo("UnknownLabel", $"This PKI signs nothing {at}."));

            if (!PKIStore.TryInspectCSR(Request.CSR, out var inspection, out var error))
                return new SignCertificateResponse(PKIStatus.Rejected, StatusInfo: new PKIStatusInfo("InvalidCSR", error));

            if (!inspection.SignatureValid)
                return new SignCertificateResponse(PKIStatus.Rejected, StatusInfo: new PKIStatusInfo("InvalidCSR", "The signature of the CSR does not hold."));

            if (!Store.TryIssueFromCSR(profile.IssuerId, null, profile.Profile, Request.CSR, profile.ValidDays, [], true, null, CreatedByPrefix + Login,
                                       out var certificate, out error, out var notSaved, profile.V2G))
            {

                Log.Warning($"PKI: the registration authority '{Login}' asked to sign the CSR of '{inspection.Subject}' {at}, which was refused: {error}", "pki", "ra", "security");

                return new SignCertificateResponse(PKIStatus.Rejected,
                                                   StatusInfo: new PKIStatusInfo(notSaved ? "NotSaved" : "NotSigned", error));

            }

            Log.Notice($"PKI: the registration authority '{Login}' had the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}) signed " +
                       $"below '{Store.Get(profile.IssuerId)?.CommonName}' {at}, valid until {certificate.NotAfter:u}.",
                       "pki", "ra", "security");

            return new SignCertificateResponse(PKIStatus.Accepted,
                                               Store.ChainPEM(certificate.Id),
                                               certificate.Id);

        }

        #endregion

        #region (private) GetCACertificates(Request)

        private GetCACertificatesResponse GetCACertificates(GetCACertificatesRequest Request)
        {

            if (EST.For(Request.Label) is not ESTProfile profile)
                return new GetCACertificatesResponse(PKIStatus.Rejected,
                                                     StatusInfo: new PKIStatusInfo("UnknownLabel", $"This PKI signs nothing {(Request.Label is null ? "without a label" : $"at the label '{Request.Label}'")}."));

            var pem = String.Concat(Store.Chain(profile.IssuerId).Select(certificate => Store.CertificatePEM(certificate.Id)?.TrimEnd() + "\n"));

            return new GetCACertificatesResponse(PKIStatus.Accepted, pem);

        }

        #endregion

        #region (private) GetCertificateStatus(Request)

        private GetCertificateStatusResponse GetCertificateStatus(GetCertificateStatusRequest Request)
        {

            if (CertificateNamed(Request.CertificateId, Request.SerialNumber) is not IssuedCertificate certificate)
                return new GetCertificateStatusResponse(PKIStatus.Accepted, "unknown");

            var revocation = Store.RevocationOf(certificate.Id);

            return new GetCertificateStatusResponse(PKIStatus.Accepted,
                                                    revocation is not null ? "revoked" : certificate.StatusAt(TimeProvider.GetUtcNow()),
                                                    certificate.Id,
                                                    revocation?.RevokedAt,
                                                    revocation is null ? null : RevocationReasons.AsText(revocation.Reason));

        }

        #endregion

        #region (private) GetCRL(Request)

        private GetCRLResponse GetCRL(GetCRLRequest Request)
        {

            var issuerId = Request.IssuerId is not null
                               ? PKIStore.Normalized(Request.IssuerId)
                               : EST.For(Request.Label)?.IssuerId;

            if (issuerId is null || Store.Get(issuerId) is not IssuedCertificate ca || !ca.Profile.IsCA())
                return new GetCRLResponse(PKIStatus.Rejected,
                                          StatusInfo: new PKIStatusInfo("UnknownCA", Request.IssuerId is not null
                                                                                         ? $"There is no CA '{Request.IssuerId}' in this PKI."
                                                                                         : $"This PKI signs nothing {(Request.Label is null ? "without a label" : $"at the label '{Request.Label}'")}."));

            if (Store.CRL(ca.Id) is not Byte[] crl)
                return new GetCRLResponse(PKIStatus.Rejected, IssuerId: ca.Id,
                                          StatusInfo: new PKIStatusInfo("NoCRL", $"The CA '{ca.CommonName}' has no CRL yet."));

            return new GetCRLResponse(PKIStatus.Accepted, new String(PemEncoding.Write("X509 CRL", crl)) + "\n", ca.Id);

        }

        #endregion

        #region (private) RevokeCertificate(Login, Request)

        private RevokeCertificateResponse RevokeCertificate(User_Id                   Login,
                                                            RevokeCertificateRequest  Request)
        {

            if (!RevocationReasons.TryParse(Request.Reason, out var reason))
                return new RevokeCertificateResponse(PKIStatus.Rejected,
                                                     new PKIStatusInfo("UnknownReason", $"'{Request.Reason}' is no reason of RFC 5280 a certificate is revoked for here: {String.Join(", ", RevocationReasons.All.Select(RevocationReasons.AsText))}."));

            if (CertificateNamed(Request.CertificateId, Request.SerialNumber) is not IssuedCertificate certificate)
                return new RevokeCertificateResponse(PKIStatus.Rejected, new PKIStatusInfo("NotFound", "There is no certificate of that name in this PKI."));

            // What it had signed, and nothing else: one CSMS revokes no station
            // of another, and none of what the people of the PKI signed.
            if (certificate.CreatedBy != CreatedByPrefix + Login)
            {

                Log.Warning($"PKI: the registration authority '{Login}' asked to revoke the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}), which it had not had signed.",
                            "pki", "ra", "security");

                return new RevokeCertificateResponse(PKIStatus.Rejected,
                                                     new PKIStatusInfo("NotYours", $"The {certificate.InWords} '{certificate.CommonName}' was not signed for '{Login}': it revokes only what it had signed."));

            }

            if (!Store.TryRevoke(certificate.Id, reason.Value, null, CreatedByPrefix + Login, out _, out var error, out var warning, out _, out var notSaved))
                return new RevokeCertificateResponse(PKIStatus.Rejected, new PKIStatusInfo(notSaved ? "NotSaved" : "NotRevoked", error));

            Log.Notice($"PKI: the registration authority '{Login}' revoked the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}) for {RevocationReasons.AsText(reason.Value)}." +
                       (warning is null ? "" : $" {warning}"),
                       "pki", "ra", "security");

            return new RevokeCertificateResponse(PKIStatus.Accepted,
                                                 warning is null ? null : new PKIStatusInfo("Warning", warning));

        }

        #endregion

        #region (private) CertificateNamed(CertificateId, SerialNumber)

        /// <summary>
        /// The certificate of this PKI of the given SHA-256 fingerprint, or of
        /// the given serial number - or null.
        /// </summary>
        private IssuedCertificate? CertificateNamed(String?  CertificateId,
                                                    String?  SerialNumber)
        {

            if (CertificateId is not null)
                return Store.Get(PKIStore.Normalized(CertificateId));

            if (SerialNumber is null)
                return null;

            var serial = RevocationReasons.NormalizedSerial(SerialNumber);

            return Store.Find().FirstOrDefault(certificate => RevocationReasons.NormalizedSerial(certificate.SerialNumber) == serial);

        }

        #endregion


        #region (private) SayWhichRAIsWaitedFor()

        /// <summary>
        /// Say of every connection of a registration authority that is not in
        /// now that it is waited for - or why nothing can come.
        /// </summary>
        private void SayWhichRAIsWaitedFor()
        {

            if (Connections is null)
                return;

            foreach (var entry in Connections.Connections.Where(entry => entry.Inbound).ToArray())
            {

                if (rasIn.ContainsKey(entry.Id))
                    continue;

                var name  = entry.InboundName;

                var what  = !entry.AutoConnect
                                ? $"'{name}' is not let in: this connection is switched off."
                                : entry.IsSSH
                                      ? pkiOverSSHServed && SSHEnabled
                                            ? $"Waiting for '{name}' to connect over SSH."
                                            : $"'{name}' can not connect: this {NodeNoun} serves no messages of a PKI over SSH."
                                      : raServerStarted
                                            ? $"Waiting for '{name}' to connect."
                                            : $"'{name}' can not connect: the WebSocket server of this {NodeNoun} is not listening.";

                if (ConnectionStates.TryGetValue(entry.Id, out var state) && state.Status == ConnectionStatus.Waiting && state.Said == what)
                    continue;

                Record(entry, ConnectionStatus.Waiting, what);

            }

        }

        #endregion

    }

}
