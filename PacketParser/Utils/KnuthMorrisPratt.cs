using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    public static class KnuthMorrisPratt {


        public static long ReadTo(byte[] pattern, byte[] data, int offset, out System.Collections.Generic.List<byte> readBytes) {
            return ReadTo(pattern, data, offset, out readBytes, KmpFailureFunction(pattern));
        }

        public static long ReadTo(byte[] pattern, byte[] data, int offset, out System.Collections.Generic.List<byte> readBytes, int[] kmpFailureFunction) {
            System.IO.MemoryStream mStream = new System.IO.MemoryStream(data);
            mStream.Position = offset;
            return ReadTo(pattern, mStream, out readBytes, kmpFailureFunction);
        }


        /// <summary>
        /// Reads the data in the stream until the pattern is found
        /// </summary>
        /// <param name="bytePattern">Byte pattern to read to</param>
        /// <returns>Position of the first occurance of the bytePattern parameters</returns>
        public static long ReadTo(byte[] pattern, System.IO.Stream stream, out System.Collections.Generic.List<byte> readBytes) {
            return ReadTo(pattern, stream, out readBytes, KmpFailureFunction(pattern));
        }

        public static long ReadTo(byte[] pattern, System.IO.Stream stream, out System.Collections.Generic.List<byte> readBytes, int[] kmpFailureFunction) {
            readBytes=new List<byte>();
            //I will have to implement some sort of linear string matching algorithm.
            long startPosition=stream.Position;
            //Knuth-Morris-Pratt algorithm:
            //int[] f=kmpFailureFunction(pattern);
            //int i=0;
            int j=0;
            int tmp=stream.ReadByte();
            if(tmp<0)
                return tmp;//end of stream
            byte t=(byte)tmp;
            readBytes.Add(t);
            while(stream.Position<stream.Length+1) {
                if(pattern[j]==t) {
                    if(j==pattern.Length-1)//see if we have a match
                        return stream.Position-pattern.Length;//i-m+1
                    //i++;//do I need this?
                    tmp=stream.ReadByte();
                    if(tmp<0)
                        return tmp;//end of stream
                    t=(byte)tmp;
                    readBytes.Add(t);
                    j++;
                }
                else if(j>0) {//move forward in the pattern
                    j = kmpFailureFunction[j - 1];
                }
                else {
                    //i++;
                    tmp=stream.ReadByte();
                    if(tmp<0)
                        return tmp;//end of stream
                    t=(byte)tmp;
                    readBytes.Add(t);
                }
            }
            return -1;//There is no matching substring
        }

        public static int[] KmpFailureFunction(byte[] pattern) {
            int i=1;
            int j=0;
            int[] f=new int[pattern.Length];
            if(f.Length>0)
                f[0]=0;
            while(i<pattern.Length) {
                if(pattern[j]==pattern[i]) {
                    //we have matched j+1 characters
                    f[i]=j+1;
                    i++;
                    j++;
                }
                else if(j>0) {
                    //j indexes just after a prefic of P that must match
                    j=f[j-1];
                }
                else {
                    //no match
                    f[i]=0;
                    i++;
                }
            }
            return f;
        }
    }
}
