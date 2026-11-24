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
using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    #region RasCommand

    /// <summary>
    /// The registration authorities of this PKI: each with its connection -
    /// where it may connect from and whether it is switched on -, what it
    /// signs in with, whether it is connected now, and how many certificates
    /// it had signed; and the server they connect to.
    /// </summary>
    /// <remarks>
    /// What the pages of the registration authorities show, at their
    /// permission. A registration authority is written down there - or in
    /// the file -, and its keys and key pins with raKeys and raPins.
    /// </remarks>
    /// <param name="CLI">The command line of the PKI to ask.</param>
    public class RasCommand(PKICLI CLI) : ACLICommand<PKICLI>(CLI),
                                          ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "ras";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => Arguments.Length == 1 && CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(PKIAccess.RegistrationAuthorities), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var pki        = cli.PKI;
            var settings   = pki.RAServerSettings;
            var connected  = pki.RALoginsIn.ToHashSet(StringComparer.Ordinal);
            var lines      = new List<String>();

            #region The server

            lines.Add(settings.IsEnabled
                          ? pki.RAServerRunning
                                ? $"The WebSocket server of the registration authorities listens at port {settings.TCPPort?.ToUInt16()}{(pki.RAServerTLS ? ", with TLS" : ", without TLS")}."
                                : $"The WebSocket server of the registration authorities is switched on at port {settings.TCPPort?.ToUInt16()}, and does not listen."
                          : "The WebSocket server of the registration authorities is switched off.");

            lines.Add(pki.PKIOverSSHServed
                          ? $"The messages of a PKI are served over SSH, at port {pki.SSHPort?.ToUInt16()}."
                          : "The messages of a PKI are not served over SSH.");

            #endregion

            #region Every registration authority

            var entries = pki.Connections.Connections.
                              Where  (entry => entry.Inbound && entry.ConnectionType == protocols.WWCP.Node.Connections.ConnectionType.RegistrationAuthority).
                              OrderBy(entry => entry.InboundName, StringComparer.Ordinal).
                              ToArray();

            var named   = entries.Select(entry => entry.InboundName).OfType<String>().ToHashSet(StringComparer.Ordinal);

            if (entries.Length == 0)
                lines.Add("No registration authority is written down: none may connect.");

            foreach (var entry in entries)
            {

                var name    = entry.InboundName ?? "?";
                var signed  = pki.Store.Find().Count(certificate => certificate.CreatedBy == PKI.CreatedByPrefix + name);

                lines.Add($"{name}  {(entry.AutoConnect ? "on" : "off")}  {(connected.Contains(name) ? "connected" : "not connected")}  " +
                          $"{signed} certificate(s) signed  {entry.URL}  {entry.Description.FirstText()}");

                if (User_Id.TryParse(name) is User_Id login && pki.WebSocketLogins.TryGet(login, out var signsIn))
                    lines.Add($"  signs in with {String.Join(", ", WaysIn(signsIn))}, in the group '{signsIn.GroupId}'{(signsIn.Enabled ? "" : ", switched off")}");
                else
                    lines.Add("  has no login: it cannot sign in.");

            }

            // A login without a connection signs in and is let go of.
            foreach (var login in pki.WebSocketLogins.Logins.Where(login => !named.Contains(login.Login.ToString())).OrderBy(login => login.Login))
                lines.Add($"{login.Login}  has a login and no connection: it is let go of when it connects.");

            #endregion

            return Task.FromResult<String[]>([ .. lines ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - the registration authorities of this PKI, what they sign in with, whether they are connected, and what they had signed";

        #endregion


        #region (private static) WaysIn(Login)

        private static IEnumerable<String> WaysIn(WebSocketLogin Login)
        {

            var ways = new List<String>();

            if (Login.HasPassword)
                ways.Add("a password");

            if (Login.HasTOTP)
                ways.Add("TOTP");

            if (Login.HasSSHKey)
                ways.Add($"{Login.Keys.Count} SSH key(s)");

            if (Login.HasKeyPin)
                ways.Add($"{Login.Pins.Count} key pin(s)");

            return ways.Count > 0 ? ways : [ "nothing yet" ];

        }

        #endregion

    }

    #endregion

    #region RaKeysCommand

    /// <summary>
    /// The SSH keys registration authorities sign in with for the messages of
    /// a PKI over SSH: see <see cref="LoginKeysCommand"/>.
    /// </summary>
    /// <param name="CLI">The command line of the PKI.</param>
    public class RaKeysCommand(PKICLI CLI) : LoginKeysCommand(CLI, CommandName, PKIAccess.RegistrationAuthorities)
    {

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "raKeys";

        private PKI PKINode
            => ((PKICLI) cli).PKI;

        protected override WebSocketLogins        Logins      => PKINode.WebSocketLogins;
        protected override String                 LoginNoun   => "registration authority";
        protected override String                 LoginWord   => "login";
        protected override String                 KeysAreFor  => "for the messages of a PKI over SSH";
        protected override IReadOnlyList<String>  LogTags     => [ "pki", "ra" ];

        protected override IEnumerable<String> WhyNoLoginSignsIn()
        {
            if (!PKINode.PKIOverSSHServed)
                yield return "The messages of a PKI are not served over SSH: no registration authority signs in over SSH.";
        }

    }

    #endregion

    #region RaPinsCommand

    /// <summary>
    /// The key pins registration authorities are let in by on the WebSocket
    /// port of the PKI: see <see cref="LoginPinsCommand"/>.
    /// </summary>
    /// <param name="CLI">The command line of the PKI.</param>
    public class RaPinsCommand(PKICLI CLI) : LoginPinsCommand(CLI, CommandName, PKIAccess.RegistrationAuthorities)
    {

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "raPins";

        private PKI PKINode
            => ((PKICLI) cli).PKI;

        protected override WebSocketLogins        Logins      => PKINode.WebSocketLogins;
        protected override String                 LoginNoun   => "registration authority";
        protected override String                 LoginWord   => "login";
        protected override String                 PinsAreFor  => "on the WebSocket port of the PKI";
        protected override IReadOnlyList<String>  LogTags     => [ "pki", "ra" ];

        protected override IEnumerable<String> WhyNoLoginSignsIn()
        {

            if (!PKINode.RAServerSettings.IsEnabled)
                yield return "The WebSocket server of the registration authorities is switched off: no registration authority signs in.";

            else if (PKINode.RAServerRunning && !PKINode.RAServerTLS)
                yield return "The WebSocket port of the PKI is not encrypted: no key pin lets a registration authority in until it is.";

        }

    }

    #endregion

}
