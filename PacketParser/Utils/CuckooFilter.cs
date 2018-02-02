using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    //this is intended to be an alternative to PacketParser.CleartextTools.BloomFilter
    //https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf
    public class CuckooFilter<T> {

        //2 hash functions
        //b = 4
        //f = 8 (actually slighly less since value 0x00 cannot be used in this implementation)

        /// <summary>
        /// A hash function that returns a single byte from the object.
        /// The implementation must be independent from .NET's item.GetHashCode function!
        /// </summary>
        /// <param name="item">The item to create a "unique" fingerprint from</param>
        /// <returns>returns a byte value that can never be 0x00</returns>
        public delegate byte Fingerprint(T item);

        private const int MAX_KICKS = 100;
        private readonly uint TABLE_SIZE;


        //private Dictionary<int,int> dict;
        //private Fingerprint fingerprintFunction;
        private int[] table;

        //public CuckooFilter(Fingerprint fingerprintFunction) {
        public CuckooFilter(int size) {
            //this.dict = new Dictionary<int, int>();
            //this.fingerprintFunction = fingerprintFunction;
            uint roofSize = 1;
            while (roofSize < size)
                roofSize <<= 1;
            this.TABLE_SIZE = roofSize;
            this.table = new int[this.TABLE_SIZE];
            
        }

        public bool Contains(T item) {
            HashedItem hashedItem = new HashedItem(item, this.TABLE_SIZE);
            for (int i = 0; i < 2; i++)
                if (this.bucketContains(this.table[hashedItem.Hash[i]], hashedItem.Fingerprint))
                    return true;
            return false;
        }

        public void Insert(T item) {
            //byte f = this.fingerprintFunction(item);
            //uint fullHashCode = (uint)item.GetHashCode();
            HashedItem hashedItem = new HashedItem(item, this.TABLE_SIZE);

            int[] buckets = new int[2];
            for (int i = 0; i < 2; i++) {
                buckets[i] = this.table[hashedItem.Hash[i]];
            }

            /*
            for (int i = 0; i < 2; i++) {
                if(b[i] == null) {
                    this.dict.Add(h[i], f);
                    return;
                }
            }*/
            for (int i = 0; i < 2; i++) {
                if (buckets[i] >> 24 != 0) {//there is room in the bucket for the fingerprint
                    this.table[hashedItem.Hash[i]] = this.append(buckets[i], hashedItem.Fingerprint);
                    return;
                }
            }
            //we will need to do some kicking
            //1. "randomly" pick bucket 1 or 2
            this.kickMove(hashedItem.Fingerprint, hashedItem.Hash[hashedItem.Fingerprint % 1], MAX_KICKS);
            
        }

        /*
        private byte getFingerprint(T item) {
            uint fullHashCode = (uint)item.GetHashCode();
            byte fingerprint = 0;
            for (int i = 24; i >= 0; i--) {
                fingerprint = (byte)(fullHashCode >> i);
                if (fingerprint != 0)
                    break;
            }
            if (fingerprint == 0)
                fingerprint = 0xff;
            return fingerprint;
        }*/

        private uint[] getHashes(T item, byte fingerprint) {
            uint[] hash = new uint[2];
            hash[0] = (uint)item.GetHashCode() % (uint)this.table.Length;
            hash[1] = hash[0] ^ ((uint)fingerprint.GetHashCode() % this.TABLE_SIZE);//hash_2 = hash_1 XOR hash(fingerprint)
            return hash;
        }

        private void kickMove(byte fingerprint, uint hash, int maxRecursions) {
            //2. randomly select an entry from the bucket
            //   - I'll just treat the buckets as a queue and kick out the oldest value
            //3. swap f and the fingerprint stored in the entry
            if (!bucketContains(this.table[hash], fingerprint)) {
                if (maxRecursions == 0)
                    throw new Exception("Too many kicks in CuckooFilter!");

                byte kickedFingerprint = (byte)(this.table[hash] >> 24);
                this.table[hash] = this.append(this.table[hash], fingerprint);//the most significant value will now be shifted out
                if (kickedFingerprint != 0)
                    this.kickMove(kickedFingerprint, hash ^ ((uint)kickedFingerprint.GetHashCode() % this.TABLE_SIZE), maxRecursions - 1);
            }
        }

        private int append(int bucket, byte fingerprint) {
            return (bucket << 8) + fingerprint;
            /*
            for (int i=0; i<4; i++) {
                if(bucket >> (i*8) != 0) {
                    return bucket | (value << (i * 8));
                }
            }
            throw new Exception("Bucket is full");
            */
        }

        private bool bucketContains(int bucket, byte fingerprint) {
            while(bucket != 0) {
                if (((byte)bucket) == fingerprint)
                    return true;
                bucket >>= 8;//shift down one byte
            }
            return false;
        }

        public class HashedItem {
            private uint fullHashCode;
            private uint[] hash;
            private byte fingerprint;
            private readonly uint TABLE_SIZE;

            internal uint[] Hash { get { return this.hash; } }
            internal byte Fingerprint { get { return this.fingerprint; } }

            public HashedItem(T item, uint tableSize) {
                this.fullHashCode = (uint)item.GetHashCode();
                this.hash = new uint[2];
                this.TABLE_SIZE = tableSize;

                this.fingerprint = 0;
                for (int i = 24; i >= 0; i--) {
                    fingerprint = (byte)(fullHashCode >> i);
                    if (fingerprint != 0)
                        break;
                }
                if (fingerprint == 0)
                    fingerprint = 0xff;

                hash[0] = fullHashCode % this.TABLE_SIZE;
                hash[1] = hash[0] ^ ((uint)fingerprint.GetHashCode() % TABLE_SIZE);//hash_2 = hash_1 XOR hash(fingerprint)
            }
        }

    }
}
