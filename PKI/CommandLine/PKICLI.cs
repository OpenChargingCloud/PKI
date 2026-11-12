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

using System.Reflection;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.CommandLine
{

    /// <summary>
    /// The command line of a running PKI.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything a command needs is reachable from here, which is why every
    /// command takes one of these: the PKI itself, and through it its
    /// configuration, its log and everything the JSON API can do. A command is
    /// a third way of asking for the same thing, beside the web interface and
    /// the switches at a start - never an implementation of its own.
    /// </para>
    /// <para>
    /// Commands are not listed anywhere. The commands every node has - syncNTS
    /// among them - are the node's, and NodeCLI, which this derives from,
    /// finds them in WWCP_Node. The constructor registers this type as well,
    /// so that this assembly is walked for anything that implements
    /// ICLICommand and can be built from a PKICLI: a command of the
    /// PKI's own is a new file and nothing else - 'pki' among them.
    /// </para>
    /// <para>
    /// Here, beside the PKI, and not in the program that runs it: what a PKI
    /// can be told is the PKI's, and is told over SSH as well as at the
    /// console. The PKI hands it to whoever signs in over SSH by itself (see
    /// PKI.cs), so that a PKI run by another program - the tests - has the
    /// same commands as one run by the program PKICLI. A program with commands
    /// of its own derives from this one and sets WWCPNode.CommandLines anew.
    /// </para>
    /// </remarks>
    public class PKICLI : NodeCLI
    {

        #region Properties

        /// <summary>
        /// The PKI these commands are about.
        /// </summary>
        public PKI PKI { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the command line of the given PKI.
        /// </summary>
        /// <param name="PKI">The running PKI.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one and WWCP_Node are searched either way.</param>
        public PKICLI(PKI                PKI,
                      params Assembly[]  AssembliesWithCLICommands)

            : base(PKI, AssembliesWithCLICommands)

        {

            this.PKI = PKI;

            RegisterCLIType(typeof(PKICLI));

        }

        /// <summary>
        /// Create the command line of the given PKI on the given terminal,
        /// for the given caller - a session over SSH.
        /// </summary>
        /// <param name="PKI">The running PKI.</param>
        /// <param name="Terminal">What the command line is typed at and written on.</param>
        /// <param name="Caller">Who is typing at it.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one and the node's are searched either way.</param>
        public PKICLI(PKI                PKI,
                      ICLITerminal       Terminal,
                      CLICaller          Caller,
                      params Assembly[]  AssembliesWithCLICommands)

            : base(PKI, Terminal, Caller, AssembliesWithCLICommands)

        {

            this.PKI = PKI;

            RegisterCLIType(typeof(PKICLI));

        }

        #endregion


        #region TryFind(Words, out Certificate, out Error)

        /// <summary>
        /// The one certificate the given words name: by the beginning of its
        /// fingerprint, as 'pki' writes it, or by its whole common name.
        /// </summary>
        /// <remarks>
        /// A fingerprint first, four characters at least, so that a word of
        /// hexadecimal digits finds what 'pki' showed; a common name
        /// otherwise, whatever its case. Where more than one certificate
        /// answers to it, none is taken: what a command does to a certificate
        /// is done to the one that was meant.
        /// </remarks>
        /// <param name="Words">What was typed: the beginning of a fingerprint, or a common name.</param>
        /// <param name="Certificate">The certificate.</param>
        /// <param name="Error">Why there is none, or more than one.</param>
        public Boolean TryFind(String                                       Words,
                               [NotNullWhen(true)]  out IssuedCertificate?  Certificate,
                               [NotNullWhen(false)] out String?             Error)
        {

            Certificate  = null;
            Error        = null;

            var text     = Words.Trim();
            var all      = PKI.Store.Find();
            var prefix   = PKIStore.Normalized(text);

            var found    = prefix.Length >= 4 && text.All(character => Uri.IsHexDigit(character) || character is ':' or '-')
                               ? all.Where(certificate => certificate.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList()
                               : [];

            if (found.Count == 0)
                found = [.. all.Where(certificate => certificate.CommonName.Equals(text, StringComparison.OrdinalIgnoreCase))];

            if (found.Count == 1)
            {
                Certificate = found[0];
                return true;
            }

            Error = found.Count == 0
                        ? $"No certificate of this PKI has a fingerprint beginning with '{text}', and none is called so. 'pki' lists them."
                        : $"{found.Count} certificates of this PKI answer to '{text}': {String.Join(", ", found.Select(certificate => $"{certificate.Id[..16]} ({certificate.InWords})"))}. Say the beginning of the fingerprint of one.";

            return false;

        }

        #endregion

        #region (static) PasswordsAreNotTyped(What)

        /// <summary>
        /// Why something that needs the password of a key is not done at a
        /// command line, and where it is.
        /// </summary>
        /// <remarks>
        /// A command line keeps what was typed at it - in its history, which
        /// outlives the session, and on the screen - and a password belongs in
        /// neither. So no command here takes one.
        /// </remarks>
        /// <param name="What">What was not done, and why the key is needed, as the beginning of a sentence.</param>
        public static String PasswordsAreNotTyped(String What)

            => $"{What}, which has a password - and a command line keeps what is typed at it. The web interface asks for the password.";

        #endregion

        #region (protected override) GetPrompt()

        /// <summary>
        /// Which port this PKI answers on, because a machine that is one of
        /// several on a bench should say which one it is before it asks for a
        /// command.
        /// </summary>
        protected override String GetPrompt()

            => $"pki:{PKI.HTTPPort}> ";

        #endregion

    }

}
