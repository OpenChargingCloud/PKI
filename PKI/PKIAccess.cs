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

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// What a PKI adds to the resources every node has, and the roles of the
    /// people around it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two resources, because they are two different things to be trusted
    /// with. Making a CA - a root, or a sub-CA below one - is making something
    /// every charging station and every CSMS that believes it will believe
    /// whatever it signs; deleting one ends everything below it. Signing a
    /// certificate below a CA that is there already - for a server, for a
    /// client, for the CSR a charging station sent - is the day-to-day work
    /// of a PKI, and is what a registration authority is let do.
    /// </para>
    /// <para>
    /// The node brings the viewer, who may look at everything, and the
    /// administrators, who may do everything. The configuration file may add
    /// roles and say differently what one of them may do - see the node's
    /// "roles" section. What is written here is what a PKI is when its file
    /// says nothing.
    /// </para>
    /// </remarks>
    public static class PKIAccess
    {

        #region Resources

        /// <summary>
        /// The certificate authorities: read, the list of every certificate
        /// of this PKI; edited, a root CA or a sub-CA made or deleted.
        /// </summary>
        public const String  Authorities  = "authorities";

        /// <summary>
        /// What the CAs sign: read, the list of every certificate of this PKI;
        /// edited, a certificate for a server or a client signed - with a key
        /// made here, or for a CSR - downloaded with its key, or deleted.
        /// </summary>
        public const String  Issuance     = "issuance";

        /// <summary>
        /// Both.
        /// </summary>
        public static readonly IReadOnlyList<String>  Resources = [ Authorities, Issuance ];

        #endregion

        #region Roles

        /// <summary>
        /// Whoever runs this PKI day to day: may look at everything and ask
        /// whether the network works - but may sign nothing, may not repoint
        /// it at other name and time servers, and may not change the
        /// certificates it holds them to.
        /// </summary>
        public static readonly Role  Operator   = new ("operator",
                                                       [ Permission.Read(Permission.AnyResource),
                                                         Permission.Run (NodeResources.DNS),
                                                         Permission.Run (NodeResources.NTS) ],
                                                       "runs the PKI day to day: looks at everything, and asks whether the network works");

        /// <summary>
        /// A registration authority: everything the operator may do, and on
        /// top of it sign certificates for servers and clients below the CAs
        /// that are there - and delete them again. It makes no CA and
        /// deletes none.
        /// </summary>
        public static readonly Role  Registrar  = new ("registrar",
                                                       [ Permission.Read(Permission.AnyResource),
                                                         Permission.Run (NodeResources.DNS),
                                                         Permission.Run (NodeResources.NTS),
                                                         Permission.Edit(Issuance) ],
                                                       "signs certificates for servers and clients below the CAs that are there, and deletes them");

        /// <summary>
        /// Both, in the order a sentence naming them reads best.
        /// </summary>
        public static readonly IReadOnlyList<Role>  Roles = [ Operator, Registrar ];

        #endregion

    }

}
