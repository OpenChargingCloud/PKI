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
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    #region ACMEAccount

    /// <summary>
    /// An account of ACME: a key, and who to write to about it.
    /// </summary>
    /// <remarks>
    /// The key is the account - whoever holds it is the account, and nobody
    /// else is - which is why it is found by its thumbprint.
    /// </remarks>
    public sealed class ACMEAccount
    {

        public String           Id                  { get; }
        public JObject          JWK                 { get; internal set; }
        public String           Thumbprint          { get; internal set; }
        public List<String>     Contacts            { get; internal set; }
        public String           Status              { get; internal set; }
        public DateTimeOffset   CreatedAt           { get; }
        public Boolean          AgreedToTerms       { get; }

        /// <summary>The key identifier of the external account binding it was opened with, where there was one.</summary>
        public String?          ExternalAccount     { get; }

        /// <summary>Who made that key: who vouches for the account.</summary>
        public String?          VouchedForBy        { get; }

        public ACMEAccount(String          Id,
                           JObject         JWK,
                           IEnumerable<String> Contacts,
                           String          Status,
                           DateTimeOffset  CreatedAt,
                           Boolean         AgreedToTerms,
                           String?         ExternalAccount,
                           String?         VouchedForBy)
        {
            this.Id               = Id;
            this.JWK              = JWK;
            this.Thumbprint       = ACMEJWS.Thumbprint(JWK);
            this.Contacts         = [.. Contacts];
            this.Status           = Status;
            this.CreatedAt        = CreatedAt;
            this.AgreedToTerms    = AgreedToTerms;
            this.ExternalAccount  = ExternalAccount;
            this.VouchedForBy     = VouchedForBy;
        }

        public JObject ToJSON()

            => new (
                   new JProperty("id",               Id),
                   new JProperty("jwk",              JWK),
                   new JProperty("contact",          new JArray(Contacts)),
                   new JProperty("status",           Status),
                   new JProperty("createdAt",        CreatedAt.ToString("o")),
                   new JProperty("agreedToTerms",    AgreedToTerms),
                   new JProperty("externalAccount",  ExternalAccount),
                   new JProperty("vouchedForBy",     VouchedForBy)
               );

        public static ACMEAccount? TryParse(JToken JSON)
        {
            try
            {
                return new ACMEAccount(
                           JSON.Value<String>("id")!,
                           (JObject) JSON["jwk"]!,
                           (JSON["contact"] as JArray)?.Select(contact => contact.Value<String>()!) ?? [],
                           JSON.Value<String>("status") ?? "valid",
                           DateTimeOffset.Parse(JSON.Value<String>("createdAt")!, null, System.Globalization.DateTimeStyles.RoundtripKind),
                           JSON.Value<Boolean?>("agreedToTerms") ?? false,
                           JSON.Value<String>("externalAccount"),
                           JSON.Value<String>("vouchedForBy")
                       );
            }
            catch (Exception)
            {
                return null;
            }
        }

    }

    #endregion

    #region ACMEExternalAccountKey

    /// <summary>
    /// A key of an external account binding (RFC 8555, section 7.3.4): what
    /// somebody of the PKI made for one ACME client to open its account with,
    /// once.
    /// </summary>
    public sealed class ACMEExternalAccountKey
    {

        public String          KeyId        { get; }
        public Byte[]          MACKey       { get; }
        public String?         Description  { get; }
        public DateTimeOffset  CreatedAt    { get; }
        public String          CreatedBy    { get; }

        /// <summary>The account it opened, once it has.</summary>
        public String?         BoundTo      { get; internal set; }

        public ACMEExternalAccountKey(String          KeyId,
                                      Byte[]          MACKey,
                                      String?         Description,
                                      DateTimeOffset  CreatedAt,
                                      String          CreatedBy,
                                      String?         BoundTo)
        {
            this.KeyId        = KeyId;
            this.MACKey       = MACKey;
            this.Description  = Description;
            this.CreatedAt    = CreatedAt;
            this.CreatedBy    = CreatedBy;
            this.BoundTo      = BoundTo;
        }

        /// <summary>
        /// The key as the PKI keeps it - with its MAC key, which only the file
        /// and the one who made it ever see.
        /// </summary>
        public JObject ToStoredJSON()

            => new (
                   new JProperty("kid",          KeyId),
                   new JProperty("hmacKey",      Base64Url.EncodeToString(MACKey)),
                   new JProperty("description",  Description),
                   new JProperty("createdAt",    CreatedAt.ToString("o")),
                   new JProperty("createdBy",    CreatedBy),
                   new JProperty("boundTo",      BoundTo)
               );

        /// <summary>
        /// The key as it is listed: without its MAC key.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("kid",          KeyId),
                   new JProperty("description",  Description),
                   new JProperty("createdAt",    CreatedAt.ToString("o")),
                   new JProperty("createdBy",    CreatedBy),
                   new JProperty("boundTo",      BoundTo)
               );

        public static ACMEExternalAccountKey? TryParse(JToken JSON)
        {
            try
            {
                return new ACMEExternalAccountKey(
                           JSON.Value<String>("kid")!,
                           Base64Url.DecodeFromChars(JSON.Value<String>("hmacKey")!),
                           JSON.Value<String>("description"),
                           DateTimeOffset.Parse(JSON.Value<String>("createdAt")!, null, System.Globalization.DateTimeStyles.RoundtripKind),
                           JSON.Value<String>("createdBy") ?? "",
                           JSON.Value<String>("boundTo")
                       );
            }
            catch (Exception)
            {
                return null;
            }
        }

    }

    #endregion

    #region ACMEIssued

    /// <summary>
    /// A certificate ACME signed: for which account, and what replaced it.
    /// </summary>
    /// <param name="CertificateId">Its fingerprint, as the store spells it.</param>
    /// <param name="AccountId">The account it was signed for.</param>
    /// <param name="IssuedAt">When.</param>
    /// <param name="Replaces">The fingerprint of the certificate it replaces (RFC 9773), where it said one.</param>
    public sealed record ACMEIssued(String          CertificateId,
                                    String          AccountId,
                                    DateTimeOffset  IssuedAt,
                                    String?         Replaces)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("certificate",  CertificateId),
                   new JProperty("account",      AccountId),
                   new JProperty("issuedAt",     IssuedAt.ToString("o")),
                   new JProperty("replaces",     Replaces)
               );

        public static ACMEIssued? TryParse(JToken JSON)
        {
            try
            {
                return new ACMEIssued(
                           JSON.Value<String>("certificate")!,
                           JSON.Value<String>("account")!,
                           DateTimeOffset.Parse(JSON.Value<String>("issuedAt")!, null, System.Globalization.DateTimeStyles.RoundtripKind),
                           JSON.Value<String>("replaces")
                       );
            }
            catch (Exception)
            {
                return null;
            }
        }

    }

    #endregion


    #region ACMEOrder / ACMEAuthorization / ACMEChallenge

    /// <summary>
    /// An order of ACME: the names of a certificate to be, and what proves
    /// them. Kept in memory only - an order a restart forgets is placed again.
    /// </summary>
    public sealed class ACMEOrder
    {

        public String                         Id              { get; }
        public ACMEAccount                    Account         { get; }
        public IReadOnlyList<ACMEIdentifier>  Identifiers     { get; }
        public String?                        ProfileName     { get; }
        public ACMEProfile                    Profile         { get; }
        public String?                        Replaces        { get; }
        public DateTimeOffset                 Expires         { get; }
        public List<ACMEAuthorization>        Authorizations  { get; } = [];
        public String?                        CertificateId   { get; internal set; }
        public ACMEProblem?                   Error           { get; internal set; }

        public ACMEOrder(String Id, ACMEAccount Account, IReadOnlyList<ACMEIdentifier> Identifiers, String? ProfileName, ACMEProfile Profile, String? Replaces, DateTimeOffset Expires)
        {
            this.Id           = Id;
            this.Account      = Account;
            this.Identifiers  = Identifiers;
            this.ProfileName  = ProfileName;
            this.Profile      = Profile;
            this.Replaces     = Replaces;
            this.Expires      = Expires;
        }

        /// <summary>
        /// "pending", "ready", "valid" or "invalid" (RFC 8555, section 7.1.6) -
        /// never "processing": the PKI signs at once.
        /// </summary>
        public String StatusAt(DateTimeOffset Now)

            => CertificateId is not null                                                       ? "valid"
             : Error is not null || Now > Expires                                              ? "invalid"
             : Authorizations.Any(authorization => authorization.StatusAt(Now) is not ("pending" or "valid"))
                                                                                               ? "invalid"
             : Authorizations.All(authorization => authorization.StatusAt(Now) == "valid")     ? "ready"
             :                                                                                   "pending";

    }

    /// <summary>
    /// A name of an order, and whether it is a wildcard's: { "type", "value" }.
    /// </summary>
    /// <param name="Type">"dns" or "ip".</param>
    /// <param name="Value">A host name - "*.example.org" for a wildcard - or an address.</param>
    public sealed record ACMEIdentifier(String  Type,
                                        String  Value)
    {

        public Boolean IsWildcard
            => Type == "dns" && Value.StartsWith("*.", StringComparison.Ordinal);

        /// <summary>The name proven: without a wildcard's "*.".</summary>
        public String  Proven
            => IsWildcard ? Value[2..] : Value;

        public JObject ToJSON()
            => new (new JProperty("type", Type), new JProperty("value", Value));

    }

    /// <summary>
    /// What proves one name of an order for an account: its challenges, one of
    /// which is to be answered.
    /// </summary>
    public sealed class ACMEAuthorization
    {

        public String                Id          { get; }
        public ACMEAccount           Account     { get; }
        public ACMEIdentifier        Identifier  { get; }
        public List<ACMEChallenge>   Challenges  { get; } = [];
        public DateTimeOffset        Expires     { get; internal set; }

        /// <summary>"pending", "valid", "invalid" or "deactivated", as it was last set.</summary>
        public String                Status      { get; internal set; } = "pending";

        public ACMEAuthorization(String Id, ACMEAccount Account, ACMEIdentifier Identifier, DateTimeOffset Expires)
        {
            this.Id          = Id;
            this.Account     = Account;
            this.Identifier  = Identifier;
            this.Expires     = Expires;
        }

        /// <summary>
        /// Its status, and "expired" where its time is up (RFC 8555, section 7.1.6).
        /// </summary>
        public String StatusAt(DateTimeOffset Now)

            => Status is "pending" or "valid" && Now > Expires
                   ? "expired"
                   : Status;

    }

    /// <summary>
    /// One way of proving a name: "http-01" or "dns-01", with its token.
    /// </summary>
    public sealed class ACMEChallenge
    {

        public String             Id             { get; }
        public ACMEAuthorization  Authorization  { get; }
        public String             Type           { get; }
        public String             Token          { get; }

        /// <summary>"pending", "processing", "valid" or "invalid".</summary>
        public String             Status         { get; internal set; } = "pending";
        public DateTimeOffset?    Validated      { get; internal set; }
        public ACMEProblem?       Error          { get; internal set; }

        public ACMEChallenge(String Id, ACMEAuthorization Authorization, String Type, String Token)
        {
            this.Id             = Id;
            this.Authorization  = Authorization;
            this.Type           = Type;
            this.Token          = Token;
        }

    }

    #endregion


    /// <summary>
    /// What the ACME server of a PKI knows: its accounts, the keys of external
    /// account bindings and the certificates it signed - in "acme/accounts.json"
    /// of the PKI's directory - and, in memory only, its orders, their
    /// authorizations and challenges, and the nonces handed out.
    /// </summary>
    /// <remarks>
    /// Every change is made under <see cref="Gate"/>, and the file written
    /// through a temporary file moved into place, as the store writes its
    /// index: a file half written is never the one read.
    /// </remarks>
    public sealed class ACMEState
    {

        #region Data

        /// <summary>
        /// How long an order, and a pending authorization, is good for.
        /// </summary>
        public static readonly TimeSpan  OrderLifetime          = TimeSpan.FromDays(7);

        /// <summary>
        /// How long a name once proven stays proven for the account - and is
        /// not asked for again in its next order.
        /// </summary>
        public static readonly TimeSpan  AuthorizationLifetime  = TimeSpan.FromDays(30);

        /// <summary>
        /// How long a nonce handed out may be used.
        /// </summary>
        public static readonly TimeSpan  NonceLifetime          = TimeSpan.FromHours(1);

        /// <summary>
        /// How many nonces are kept at most: the oldest go first beyond it.
        /// </summary>
        public const           Int32     MaxNonces              = 100_000;

        /// <summary>
        /// How many orders an account may have pending at once.
        /// </summary>
        public const           Int32     MaxPendingOrders       = 300;

        public  readonly Object                                     Gate            = new();

        private readonly Dictionary<String, ACMEAccount>            accounts        = new (StringComparer.Ordinal);
        private readonly Dictionary<String, ACMEExternalAccountKey> externalKeys    = new (StringComparer.Ordinal);
        private readonly Dictionary<String, ACMEIssued>             issued          = new (StringComparer.Ordinal);

        private readonly Dictionary<String, ACMEOrder>              orders          = new (StringComparer.Ordinal);
        private readonly Dictionary<String, ACMEAuthorization>      authorizations  = new (StringComparer.Ordinal);
        private readonly Dictionary<String, ACMEChallenge>          challenges      = new (StringComparer.Ordinal);

        private readonly Dictionary<String, DateTimeOffset>         nonces          = new (StringComparer.Ordinal);
        private readonly Queue<String>                              nonceQueue      = new ();

        private readonly TimeProvider                               timeProvider;

        #endregion

        #region Properties

        /// <summary>
        /// The file the accounts are kept in.
        /// </summary>
        public String                File          { get; }

        /// <summary>
        /// Why the file could not be read at the start - and the accounts are
        /// none until it is repaired - or null.
        /// </summary>
        public String?               LoadError     { get; }

        public DateTimeOffset        Now
            => timeProvider.GetUtcNow();

        #endregion

        #region Constructor(s)

        /// <summary>
        /// What the ACME server knows, read from the given file where it is.
        /// </summary>
        public ACMEState(String         File,
                         TimeProvider?  TimeProvider = null)
        {

            this.File          = File;
            this.timeProvider  = TimeProvider ?? TimeProvider.System;

            if (!System.IO.File.Exists(File))
                return;

            try
            {

                var json = JObject.Parse(System.IO.File.ReadAllText(File));

                foreach (var account in (json["accounts"] as JArray ?? []).Select(ACMEAccount.TryParse).OfType<ACMEAccount>())
                    accounts[account.Id] = account;

                foreach (var key in (json["externalAccountKeys"] as JArray ?? []).Select(ACMEExternalAccountKey.TryParse).OfType<ACMEExternalAccountKey>())
                    externalKeys[key.KeyId] = key;

                foreach (var one in (json["certificates"] as JArray ?? []).Select(ACMEIssued.TryParse).OfType<ACMEIssued>())
                    issued[one.CertificateId] = one;

            }
            catch (Exception e)
            {
                LoadError = $"'{File}' could not be read: {e.Message}";
            }

        }

        #endregion


        #region Nonces

        /// <summary>
        /// A new nonce, good for one request (RFC 8555, section 6.5).
        /// </summary>
        public String NewNonce()
        {

            var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(18));
            var now   = Now;

            lock (Gate)
            {

                nonces[nonce] = now;
                nonceQueue.Enqueue(nonce);

                while (nonceQueue.Count > 0 &&
                       (nonceQueue.Count > MaxNonces || !nonces.TryGetValue(nonceQueue.Peek(), out var issuedAt) || now - issuedAt > NonceLifetime))
                {
                    nonces.Remove(nonceQueue.Dequeue());
                }

            }

            return nonce;

        }

        /// <summary>
        /// Whether a nonce was handed out, is still good, and was not used
        /// before - which it is from now on.
        /// </summary>
        public Boolean TryUseNonce(String? Nonce)
        {

            if (Nonce is null)
                return false;

            lock (Gate)
                return nonces.Remove(Nonce, out var issuedAt) && Now - issuedAt <= NonceLifetime;

        }

        #endregion

        #region Accounts

        public ACMEAccount? Account(String Id)
        {
            lock (Gate)
                return accounts.TryGetValue(Id, out var account) ? account : null;
        }

        public ACMEAccount? AccountByThumbprint(String Thumbprint)
        {
            lock (Gate)
                return accounts.Values.FirstOrDefault(account => account.Thumbprint == Thumbprint);
        }

        public IReadOnlyList<ACMEAccount> Accounts()
        {
            lock (Gate)
                return [.. accounts.Values.OrderBy(account => account.CreatedAt)];
        }

        /// <summary>
        /// A new account for a key - bound to the key of an external account,
        /// where it was opened with one, which binds nothing again.
        /// </summary>
        /// <remarks>
        /// Whether the key has an account already, and whether the key of the
        /// external account opened one already, is asked again here, under
        /// the gate: two requests at once open one account, and a key of an
        /// external account binding binds one.
        /// </remarks>
        /// <param name="Taken">Whether it was refused because of that - the key, or the key of the binding, taken meanwhile.</param>
        public Boolean TryAdd(ACMEAccount                       Account,
                              out Boolean                       Taken,
                              [NotNullWhen(false)] out String?  Error)
        {

            lock (Gate)
            {

                Taken = false;

                ACMEExternalAccountKey? key = null;

                if (accounts.Values.Any(existing => existing.Thumbprint == Account.Thumbprint))
                {
                    Taken = true;
                    Error = "This key has an account already.";
                    return false;
                }

                if (Account.ExternalAccount is String keyId)
                {

                    if (!externalKeys.TryGetValue(keyId, out key))
                    {
                        Taken = true;
                        Error = $"The key '{keyId}' of an external account binding was taken away meanwhile.";
                        return false;
                    }

                    if (key.BoundTo is not null)
                    {
                        Taken = true;
                        Error = $"The key '{keyId}' of an external account binding opened an account already, and opens no other.";
                        return false;
                    }

                    key.BoundTo = Account.Id;

                }

                accounts[Account.Id] = Account;

                if (TrySave(out Error))
                    return true;

                accounts.Remove(Account.Id);

                if (key is not null)
                    key.BoundTo = null;

                return false;

            }

        }

        /// <summary>
        /// Change an account - under the gate, and written at once; undone
        /// where the file could not be written.
        /// </summary>
        public Boolean TryChange(ACMEAccount                       Account,
                                 Action<ACMEAccount>               Change,
                                 [NotNullWhen(false)] out String?  Error)
        {

            lock (Gate)
            {

                var before = (Account.JWK, Account.Thumbprint, Contacts: new List<String>(Account.Contacts), Account.Status);

                Change(Account);

                if (TrySave(out Error))
                    return true;

                (Account.JWK, Account.Thumbprint, Account.Contacts, Account.Status) = before;
                return false;

            }

        }

        #endregion

        #region External account keys

        public ACMEExternalAccountKey? ExternalAccountKey(String KeyId)
        {
            lock (Gate)
                return externalKeys.TryGetValue(KeyId, out var key) ? key : null;
        }

        public IReadOnlyList<ACMEExternalAccountKey> ExternalAccountKeys()
        {
            lock (Gate)
                return [.. externalKeys.Values.OrderBy(key => key.CreatedAt)];
        }

        /// <summary>
        /// A new key of an external account binding: 32 random bytes as its
        /// MAC key, and a key identifier nobody guesses either.
        /// </summary>
        public Boolean TryNewExternalAccountKey(String?                                          Description,
                                                String                                           CreatedBy,
                                                [NotNullWhen(true)]  out ACMEExternalAccountKey? Key,
                                                [NotNullWhen(false)] out String?                 Error)
        {

            Key = new ACMEExternalAccountKey(
                      "kid-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(),
                      RandomNumberGenerator.GetBytes(32),
                      String.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
                      Now,
                      CreatedBy,
                      null
                  );

            lock (Gate)
            {

                externalKeys[Key.KeyId] = Key;

                if (TrySave(out Error))
                    return true;

                externalKeys.Remove(Key.KeyId);
                Key = null;
                return false;

            }

        }

        /// <summary>
        /// A key of an external account binding taken away: one not used yet
        /// opens no account any more. An account it opened stays as it is.
        /// </summary>
        public Boolean TryRemoveExternalAccountKey(String                            KeyId,
                                                   out Boolean                       NotFound,
                                                   [NotNullWhen(false)] out String?  Error)
        {

            lock (Gate)
            {

                NotFound = !externalKeys.Remove(KeyId, out var key);

                if (NotFound)
                {
                    Error = $"There is no key '{KeyId}' of an external account binding.";
                    return false;
                }

                if (TrySave(out Error))
                    return true;

                externalKeys[KeyId] = key!;
                return false;

            }

        }

        #endregion

        #region Issued certificates

        public ACMEIssued? Issued(String CertificateId)
        {
            lock (Gate)
                return issued.TryGetValue(CertificateId, out var one) ? one : null;
        }

        public IReadOnlyList<ACMEIssued> IssuedFor(String AccountId)
        {
            lock (Gate)
                return [.. issued.Values.Where(one => one.AccountId == AccountId).OrderBy(one => one.IssuedAt)];
        }

        /// <summary>
        /// Whether a certificate was replaced already, by one ACME signed.
        /// </summary>
        public Boolean IsReplaced(String CertificateId)
        {
            lock (Gate)
                return issued.Values.Any(one => one.Replaces == CertificateId);
        }

        public Boolean TryRecord(ACMEIssued                        Issued,
                                 [NotNullWhen(false)] out String?  Error)
        {

            lock (Gate)
            {

                issued[Issued.CertificateId] = Issued;

                if (TrySave(out Error))
                    return true;

                issued.Remove(Issued.CertificateId);
                return false;

            }

        }

        #endregion

        #region Orders, authorizations and challenges

        /// <summary>
        /// A new id of an order, an authorization or a challenge: random, so
        /// that nobody finds the resources of another account by counting.
        /// </summary>
        public static String NewId()
            => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(12));

        public ACMEOrder? Order(String Id)
        {
            lock (Gate)
                return orders.TryGetValue(Id, out var order) ? order : null;
        }

        public ACMEAuthorization? Authorization(String Id)
        {
            lock (Gate)
                return authorizations.TryGetValue(Id, out var authorization) ? authorization : null;
        }

        public ACMEChallenge? Challenge(String Id)
        {
            lock (Gate)
                return challenges.TryGetValue(Id, out var challenge) ? challenge : null;
        }

        public IReadOnlyList<ACMEOrder> OrdersOf(ACMEAccount Account)
        {
            lock (Gate)
                return [.. orders.Values.Where(order => order.Account == Account)];
        }

        /// <summary>
        /// The authorization of an account for a name that is valid still -
        /// which a new order of the account takes instead of a new one.
        /// </summary>
        public ACMEAuthorization? ValidAuthorization(ACMEAccount     Account,
                                                     ACMEIdentifier  Identifier)
        {

            var now = Now;

            lock (Gate)
                return authorizations.Values.FirstOrDefault(authorization => authorization.Account    == Account    &&
                                                                             authorization.Identifier == Identifier &&
                                                                             authorization.StatusAt(now) == "valid" &&
                                                                             authorization.Expires > now + TimeSpan.FromDays(1));

        }

        /// <summary>
        /// A new order kept, with its authorizations and their challenges -
        /// and what has run out of time for a day forgotten.
        /// </summary>
        public void Add(ACMEOrder Order)
        {

            var now = Now;

            lock (Gate)
            {

                foreach (var old in orders.Values.Where(order => now - order.Expires > TimeSpan.FromDays(1)).ToList())
                    orders.Remove(old.Id);

                var kept = orders.Values.SelectMany(order => order.Authorizations).ToHashSet();

                foreach (var old in authorizations.Values.Where(authorization => !kept.Contains(authorization) && now - authorization.Expires > TimeSpan.FromDays(1)).ToList())
                {
                    authorizations.Remove(old.Id);
                    foreach (var challenge in old.Challenges)
                        challenges.Remove(challenge.Id);
                }

                orders[Order.Id] = Order;

                foreach (var authorization in Order.Authorizations)
                {
                    authorizations[authorization.Id] = authorization;
                    foreach (var challenge in authorization.Challenges)
                        challenges[challenge.Id] = challenge;
                }

            }

        }

        /// <summary>
        /// How many orders of the account are not done yet.
        /// </summary>
        public Int32 PendingOrdersOf(ACMEAccount Account)
        {

            var now = Now;

            lock (Gate)
                return orders.Values.Count(order => order.Account == Account && order.StatusAt(now) is "pending" or "ready");

        }

        #endregion


        #region (private) TrySave(out Error)

        /// <summary>
        /// Everything kept, written to the file. Called under the gate.
        /// </summary>
        private Boolean TrySave([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            if (LoadError is not null)
            {
                Error = $"Nothing of ACME is written while {LoadError}";
                return false;
            }

            var temporary = File + ".tmp";

            try
            {

                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(File))!);

                var json = new JObject(
                               new JProperty("accounts",             new JArray(accounts.    Values.OrderBy(account => account.CreatedAt).Select(account => account.ToJSON()))),
                               new JProperty("externalAccountKeys",  new JArray(externalKeys.Values.OrderBy(key     => key.CreatedAt).    Select(key     => key.ToStoredJSON()))),
                               new JProperty("certificates",         new JArray(issued.      Values.OrderBy(one     => one.IssuedAt).     Select(one     => one.ToJSON())))
                           );

                System.IO.File.WriteAllText(temporary, json.ToString(Formatting.Indented));
                System.IO.File.Move(temporary, File, overwrite: true);

                return true;

            }
            catch (Exception e)
            {

                try
                {
                    if (System.IO.File.Exists(temporary))
                        System.IO.File.Delete(temporary);
                }
                catch (Exception)
                { }

                Error = $"'{File}' could not be written: {e.Message}";
                return false;

            }

        }

        #endregion

    }

}
