using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    public class BoyerMoore {
        /**
         * Returns the index within this string of the first occurrence of the
         * specified substring. If it is not a substring, return -1.
         * 
         * @param haystack The string to be scanned
         * @param needle The target string to search
         * @return The start index of the substring
         */
        public static int IndexOf(byte[] haystack, byte[] needle) {
            if (needle.Length == 0) {
                return 0;
            }
            int[] byteTable = MakeByteTable(needle);
            int[] offsetTable = MakeOffsetTable(needle);
            return IndexOf(haystack, needle, byteTable, offsetTable);
        }

        public static int IndexOf(byte[] haystack, byte[] needle, int[] byteTable, int[] offsetTable, bool ignoreCase) {
            if (!ignoreCase)
                return IndexOf(haystack, needle, byteTable, offsetTable);
            else {
                if (needle.Length == 0) {
                    return 0;
                }
                for (int i = needle.Length - 1, j; i < haystack.Length; ) {
                    for (j = needle.Length - 1; ToUpper(needle[j]) == ToUpper(haystack[i]); --i, --j) {
                        if (j == 0) {
                            return i;
                        }
                    }
                    // i += needle.length - j; // For naive method
                    i += Math.Max(offsetTable[needle.Length - 1 - j], byteTable[ToUpper(haystack[i])]);
                }
                return -1;
            }
        }

        public static int IndexOf(byte[] haystack, byte[] needle, int[] byteTable, int[] offsetTable) {
            if (needle.Length == 0) {
                return 0;
            }
            for (int i = needle.Length - 1, j; i < haystack.Length; ) {
                for (j = needle.Length - 1; needle[j] == haystack[i]; --i, --j) {
                    if (j == 0) {
                        return i;
                    }
                }
                // i += needle.length - j; // For naive method
                i += Math.Max(offsetTable[needle.Length - 1 - j], byteTable[haystack[i]]);
            }
            return -1;
        }

        public static byte[] ToUpper(byte[] b) {
            byte[] result = new byte[b.Length];
            for (int i = 0; i < b.Length; i++)
                result[i] = ToUpper(b[i]);
            return result;
        }
        public static byte ToUpper(byte b) {
            if (b < 0x61)
                return b;
            else
                return (byte) (b - 0x20);
        }


        public static int[] MakeByteTable(byte[] needle, bool ignoreCase) {
            if (!ignoreCase)
                return MakeByteTable(needle);
            else {
                const int ALPHABET_SIZE = 256;
                int[] table = new int[ALPHABET_SIZE];
                for (int i = 0; i < table.Length; ++i) {
                    table[i] = needle.Length;
                }
                for (int i = 0; i < needle.Length - 1; ++i) {
                    table[ToUpper(needle[i])] = needle.Length - 1 - i;
                }
                return table;
            }
        }

        /**
         * Makes the jump table based on the mismatched character information.
         */
        public static int[] MakeByteTable(byte[] needle) {
            const int ALPHABET_SIZE = 256;
            int[] table = new int[ALPHABET_SIZE];
            for (int i = 0; i < table.Length; ++i) {
                table[i] = needle.Length;
            }
            for (int i = 0; i < needle.Length - 1; ++i) {
                table[needle[i]] = needle.Length - 1 - i;
            }
            return table;
        }

        /**
         * Makes the jump table based on the scan offset which mismatch occurs.
         */
        public static int[] MakeOffsetTable(byte[] needle) {
            int[] table = new int[needle.Length];
            int lastPrefixPosition = needle.Length;
            for (int i = needle.Length - 1; i >= 0; --i) {
                if (isPrefix(needle, i + 1)) {
                    lastPrefixPosition = i + 1;
                }
                table[needle.Length - 1 - i] = lastPrefixPosition - i + needle.Length - 1;
            }
            for (int i = 0; i < needle.Length - 1; ++i) {
                int slen = suffixLength(needle, i);
                table[slen] = needle.Length - 1 - i + slen;
            }
            return table;
        }

        /**
         * Is needle[p:end] a prefix of needle?
         */
        private static bool isPrefix(byte[] needle, int p) {
            for (int i = p, j = 0; i < needle.Length; ++i, ++j) {
                if (needle[i] != needle[j]) {
                    return false;
                }
            }
            return true;
        }

        /**
         * Returns the maximum length of the substring ends at p and is a suffix.
         */
        private static int suffixLength(byte[] needle, int p) {
            int len = 0;
            for (int i = p, j = needle.Length - 1;
                 i >= 0 && needle[i] == needle[j]; --i, --j) {
                len += 1;
            }
            return len;
        }
    }
}
