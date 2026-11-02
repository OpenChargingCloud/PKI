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

using System.Security.Cryptography;

#endregion

namespace cloud.charging.open.PKI.Transparency
{

    /// <summary>
    /// The Merkle tree of RFC 6962, section 2.1: the hash of a leaf, the
    /// hash of a tree, the audit path of a leaf in a tree and the proof that
    /// a tree is what a smaller one grew into - and how either proof is
    /// checked, as RFC 9162, sections 2.1.3.2 and 2.1.4.2, check them.
    /// </summary>
    /// <remarks>
    /// Over the hashes of the leaves rather than the leaves: a log keeps
    /// those, and every hash above them is made from them again where it is
    /// asked for. That is a walk over every leaf for every proof, which a
    /// PKI of some ten thousand certificates does in a moment, and a log of
    /// the web would not.
    /// </remarks>
    public static class MerkleTree
    {

        #region Hashes

        /// <summary>
        /// The hash of a leaf: SHA-256 of 0x00 and the leaf.
        /// </summary>
        public static Byte[] LeafHash(ReadOnlySpan<Byte> Leaf)
        {

            var input = new Byte[Leaf.Length + 1];

            input[0] = 0x00;
            Leaf.CopyTo(input.AsSpan(1));

            return SHA256.HashData(input);

        }

        /// <summary>
        /// The hash of a node: SHA-256 of 0x01, its left and its right.
        /// </summary>
        public static Byte[] NodeHash(ReadOnlySpan<Byte> Left,
                                      ReadOnlySpan<Byte> Right)
        {

            var input = new Byte[1 + Left.Length + Right.Length];

            input[0] = 0x01;
            Left. CopyTo(input.AsSpan(1));
            Right.CopyTo(input.AsSpan(1 + Left.Length));

            return SHA256.HashData(input);

        }

        /// <summary>
        /// The hash of the tree of the first <paramref name="Size"/> leaves:
        /// MTH of RFC 6962 - SHA-256 of nothing for a tree of none.
        /// </summary>
        public static Byte[] RootHash(IReadOnlyList<Byte[]>  LeafHashes,
                                      Int32                  Size)
        {

            CheckSize(LeafHashes, Size);

            return Size == 0
                       ? SHA256.HashData(ReadOnlySpan<Byte>.Empty)
                       : Hash(LeafHashes, 0, Size);

        }

        #endregion

        #region Proofs

        /// <summary>
        /// The audit path of the leaf at <paramref name="Index"/> in the tree
        /// of the first <paramref name="Size"/> leaves: PATH of RFC 6962.
        /// </summary>
        public static IReadOnlyList<Byte[]> InclusionProof(IReadOnlyList<Byte[]>  LeafHashes,
                                                           Int32                  Index,
                                                           Int32                  Size)
        {

            CheckSize(LeafHashes, Size);

            if (Index < 0 || Index >= Size)
                throw new ArgumentOutOfRangeException(nameof(Index), $"A tree of {Size} leaves has no leaf {Index}.");

            var path = new List<Byte[]>();

            Path(LeafHashes, Index, 0, Size, path);

            return path;

        }

        /// <summary>
        /// The proof that the tree of the first <paramref name="Second"/>
        /// leaves is what the tree of the first <paramref name="First"/> grew
        /// into, and nothing else: PROOF of RFC 6962.
        /// </summary>
        public static IReadOnlyList<Byte[]> ConsistencyProof(IReadOnlyList<Byte[]>  LeafHashes,
                                                             Int32                  First,
                                                             Int32                  Second)
        {

            CheckSize(LeafHashes, Second);

            if (First < 1 || First > Second)
                throw new ArgumentOutOfRangeException(nameof(First), $"A tree of {First} leaves is no tree a tree of {Second} grew from.");

            var proof = new List<Byte[]>();

            SubProof(LeafHashes, First, 0, Second, true, proof);

            return proof;

        }

        #endregion

        #region Checking a proof

        /// <summary>
        /// Whether the leaf of the given hash is at <paramref name="Index"/> in
        /// the tree of <paramref name="Size"/> leaves whose hash is
        /// <paramref name="RootHash"/>, as the audit path says: RFC 9162,
        /// section 2.1.3.2.
        /// </summary>
        public static Boolean VerifyInclusion(ReadOnlySpan<Byte>     LeafHash,
                                              Int64                  Index,
                                              Int64                  Size,
                                              IReadOnlyList<Byte[]>  Path,
                                              ReadOnlySpan<Byte>     RootHash)
        {

            if (Index < 0 || Index >= Size)
                return false;

            var fn  = Index;
            var sn  = Size - 1;
            var r   = LeafHash.ToArray();

            foreach (var p in Path)
            {

                if (sn == 0)
                    return false;

                if ((fn & 1) == 1 || fn == sn)
                {

                    r = NodeHash(p, r);

                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }

                }
                else
                    r = NodeHash(r, p);

                fn >>= 1;
                sn >>= 1;

            }

            return sn == 0 && r.AsSpan().SequenceEqual(RootHash);

        }

        /// <summary>
        /// Whether the tree of <paramref name="Second"/> leaves whose hash is
        /// <paramref name="SecondHash"/> grew from the tree of
        /// <paramref name="First"/> leaves whose hash is
        /// <paramref name="FirstHash"/>, as the proof says: RFC 9162, section
        /// 2.1.4.2.
        /// </summary>
        public static Boolean VerifyConsistency(Int64                  First,
                                                Int64                  Second,
                                                ReadOnlySpan<Byte>     FirstHash,
                                                ReadOnlySpan<Byte>     SecondHash,
                                                IReadOnlyList<Byte[]>  Proof)
        {

            if (First < 1 || First > Second)
                return false;

            if (First == Second)
                return Proof.Count == 0 && FirstHash.SequenceEqual(SecondHash);

            var path = (First & (First - 1)) == 0
                           ? Proof.Prepend(FirstHash.ToArray()).ToList()
                           : Proof.ToList();

            if (path.Count == 0)
                return false;

            var fn = First  - 1;
            var sn = Second - 1;

            while ((fn & 1) == 1)
            {
                fn >>= 1;
                sn >>= 1;
            }

            var fr = path[0];
            var sr = path[0];

            foreach (var c in path.Skip(1))
            {

                if (sn == 0)
                    return false;

                if ((fn & 1) == 1 || fn == sn)
                {

                    fr = NodeHash(c, fr);
                    sr = NodeHash(c, sr);

                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }

                }
                else
                    sr = NodeHash(sr, c);

                fn >>= 1;
                sn >>= 1;

            }

            return sn == 0 &&
                   fr.AsSpan().SequenceEqual(FirstHash) &&
                   sr.AsSpan().SequenceEqual(SecondHash);

        }

        #endregion


        #region (private static) The recursions of RFC 6962

        /// <summary>
        /// MTH over the leaves from <paramref name="Start"/>, up to but not
        /// including <paramref name="End"/>, of which there is one at least.
        /// </summary>
        private static Byte[] Hash(IReadOnlyList<Byte[]> LeafHashes, Int32 Start, Int32 End)
        {

            if (End - Start == 1)
                return LeafHashes[Start];

            var k = Split(End - Start);

            return NodeHash(Hash(LeafHashes, Start, Start + k),
                            Hash(LeafHashes, Start + k, End));

        }

        private static void Path(IReadOnlyList<Byte[]> LeafHashes, Int32 Index, Int32 Start, Int32 End, List<Byte[]> Into)
        {

            if (End - Start == 1)
                return;

            var k = Split(End - Start);

            if (Index < k)
            {
                Path(LeafHashes, Index, Start, Start + k, Into);
                Into.Add(Hash(LeafHashes, Start + k, End));
            }
            else
            {
                Path(LeafHashes, Index - k, Start + k, End, Into);
                Into.Add(Hash(LeafHashes, Start, Start + k));
            }

        }

        private static void SubProof(IReadOnlyList<Byte[]> LeafHashes, Int32 M, Int32 Start, Int32 End, Boolean Whole, List<Byte[]> Into)
        {

            var n = End - Start;

            if (M == n)
            {
                if (!Whole)
                    Into.Add(Hash(LeafHashes, Start, End));
                return;
            }

            var k = Split(n);

            if (M <= k)
            {
                SubProof(LeafHashes, M, Start, Start + k, Whole, Into);
                Into.Add(Hash(LeafHashes, Start + k, End));
            }
            else
            {
                SubProof(LeafHashes, M - k, Start + k, End, false, Into);
                Into.Add(Hash(LeafHashes, Start, Start + k));
            }

        }

        /// <summary>
        /// The largest power of two smaller than <paramref name="N"/>, which is
        /// two at least.
        /// </summary>
        private static Int32 Split(Int32 N)
        {

            var k = 1;

            while (k << 1 < N)
                k <<= 1;

            return k;

        }

        private static void CheckSize(IReadOnlyList<Byte[]> LeafHashes, Int32 Size)
        {
            if (Size < 0 || Size > LeafHashes.Count)
                throw new ArgumentOutOfRangeException(nameof(Size), $"There are {LeafHashes.Count} leaves, and no tree of {Size} of them.");
        }

        #endregion

    }

}
