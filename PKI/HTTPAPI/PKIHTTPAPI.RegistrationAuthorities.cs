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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// The part of the JSON API about the registration authorities that
    /// connect over a WebSocket or SSH: their connections, their logins and
    /// what they sign in with, the chains a client certificate may lead to,
    /// and the server they connect to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The routes of the connections and of the logins are every node's - see
    /// <see cref="NodeHTTPAPI.RegisterConnectionRoutes"/> and
    /// <see cref="NodeHTTPAPI.RegisterWebSocketLoginRoutes"/> in WWCP_Node -,
    /// so the PKI's pages and a CSMS's are the same pages. All of them at the
    /// resource <see cref="PKIAccess.RegistrationAuthorities"/>: who may let
    /// a registration authority in may have CSRs signed in its name.
    /// </para>
    /// <para>
    /// A registration authority is written down twice, as everybody who
    /// connects to a node is: as an inbound connection of the type
    /// "RegistrationAuthority" - which says that it may connect, and which is
    /// switched off to shut it out - and as a login, which says what it signs
    /// in with.
    /// </para>
    /// </remarks>
    public partial class PKIHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the routes of the WebSocket server of the PKI and its logins are.
        /// </summary>
        public static readonly HTTPPath RAServerPath = HTTPPath.Root + "v1/configuration/ra-server";

        #endregion


        #region (private) RegisterRegistrationAuthorityURLTemplates()

        private void RegisterRegistrationAuthorityURLTemplates()
        {

            RegisterConnectionRoutes(PKIAccess.RegistrationAuthorities);

            AddHandler(RAServerPath, GetRAServer, HTTPMethod.GET);

            RegisterWebSocketLoginRoutes(
                new WebSocketLoginRoutes(
                    RAServerPath,
                    () => PKI.WebSocketLogins,
                    () => PKI.ClientTrust,
                    PKIAccess.RegistrationAuthorities,
                    "registration authority",
                    [ "pki", "ra" ]
                )
            );

        }

        #endregion

        #region (private) GetRAServer(Request)

        /// <summary>
        /// GET /api/v1/configuration/ra-server: the server the registration
        /// authorities connect to - as the file says it, and as it is -, who
        /// is connected now, and how many certificates each login had signed.
        /// </summary>
        /// <remarks>
        /// The server is changed in the "webSocketServer" section of the file,
        /// and the PKI started again.
        /// </remarks>
        private Task<HTTPResponse> GetRAServer(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(PKIAccess.RegistrationAuthorities), false, out _, out var refused))
                return Task.FromResult(refused);

            var signed = PKI.Store.Find(null, null).
                             Where  (certificate => certificate.CreatedBy?.StartsWith(PKI.CreatedByPrefix, StringComparison.Ordinal) == true).
                             GroupBy(certificate => certificate.CreatedBy![PKI.CreatedByPrefix.Length..]).
                             OrderBy(group       => group.Key, StringComparer.Ordinal);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("configuration",  PKI.RAServerSettings.ToJSON()),
                           new JProperty("state",          new JObject(
                               new JProperty("running",    PKI.RAServerRunning),
                               new JProperty("tls",        PKI.RAServerTLS),
                               new JProperty("ssh",        PKI.PKIOverSSHServed),
                               new JProperty("sshPort",    PKI.SSHPort?.ToUInt16())
                           )),
                           new JProperty("connected",      new JArray(PKI.RALoginsIn.Order(StringComparer.Ordinal))),
                           new JProperty("signed",         new JObject(signed.Select(group => new JProperty(group.Key, group.Count()))))
                       ))
                   );

        }

        #endregion

    }

}
