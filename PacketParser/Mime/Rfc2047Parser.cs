using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Mime {
    class Rfc2047Parser {
        private static readonly char[] EQ = { '=' };
        private static readonly char[] QU = { '?' };

        public static string DecodeRfc2047Parts(string encoded) {
            try {
                StringBuilder decoded = new StringBuilder();
                int offset = 0;
                while (offset < encoded.Length - 4) {
                    int start = encoded.IndexOf("=?", offset);
                    if (start < 0) {//no more RFC 2047 string
                        decoded.Append(encoded.Substring(offset));
                        return decoded.ToString();
                    }
                    else
                        decoded.Append(encoded, offset, start - offset);//unencoded part before RFC 2047 part
                    
                    int end = encoded.IndexOf("?=", start + 2);
                    while (end > start && end <= encoded.Length - 2) {
                        if (IsRfc2047String(encoded.Substring(start, end - start + 2)))
                            break;
                        else
                            end = encoded.IndexOf("?=", end + 1);
                    }
                    if (end < 0) {
                        decoded.Append(encoded.Substring(start));
                        return decoded.ToString();
                    }
                    else if (IsRfc2047String(encoded.Substring(start, end - start + 2))) {
                        end = end + 2;
                        decoded.Append(ParseRfc2047String(encoded.Substring(start, end - start)));
                        offset = end;
                    }
                    else {
                        decoded.Append(encoded.Substring(start));
                        return decoded.ToString();
                    }
                }
                if (offset < encoded.Length)
                    decoded.Append(encoded.Substring(offset));
                return decoded.ToString();
            }
            catch (Exception) {
                return encoded;
            }

        }

        public static bool IsRfc2047String(string s) {
            try {
                return s.StartsWith("=?") && s.EndsWith("?=") && s.Trim(EQ).Split(QU, StringSplitOptions.RemoveEmptyEntries).Length == 3;
            }
            catch (Exception) { }
            return false;
        }

        public static string ParseRfc2047String(string rfc2047String) {
            if (rfc2047String.StartsWith("=?") && rfc2047String.EndsWith("?=")) {
                string[] parts = rfc2047String.Trim(EQ).Split(QU, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 3) {
                    Encoding enc = System.Text.Encoding.GetEncoding(parts[0]);
                    //undo the byte[] to string conversion from PacketParser.Mime.UnbufferedReader
                    List<byte> bytes = new List<byte>();
                    for (int i = 0; i < parts[2].Length; i++)
                        bytes.Add((byte)parts[2][i]);
                    if (parts[1].Equals("B", StringComparison.InvariantCultureIgnoreCase))//base64 decode
                        bytes = new List<byte>(System.Convert.FromBase64String(parts[2]));
                    else if (parts[1].Equals("Q", StringComparison.InvariantCultureIgnoreCase))//Quoted Printable
                        bytes = Utils.ByteConverter.ReadQuotedPrintable(bytes.ToArray());
                    return enc.GetString(bytes.ToArray());
                }
                else throw new Exception("Invalid RFC 2047 string");
            }
            else throw new Exception("Invalid RFC 2047 string");
        }
    }
}
