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

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// What every node has to answer, asked of a PKI - the conformance
    /// suite of WWCP_Node_TestKit.
    /// </summary>
    /// <remarks>
    /// The start, the sign-in and the roles a configuration file adds, the
    /// configuration, name resolution and the time servers, the diagnostics,
    /// the log and its event stream, stopping with browsers watching, the
    /// certificate store and the web interface - none of which a PKI says
    /// differently from any other node.
    /// </remarks>
    public class PKIConformance : NodeConformanceTests
    {

        protected override WWCPNode NewNode(String   Directory,
                                            JObject  Configuration)
        {

            var file = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, Configuration.ToString());

            return new PKI(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(Directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(file),
                       CertificatesPath:  Path.Combine(Directory, "certificates"),
                       PKIPath:           Path.Combine(Directory, "pki"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

    }

}
