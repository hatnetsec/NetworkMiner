//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    /// <summary>
    /// Sadly this class is needed since Big and little endian can't be configured in System.ByteConverter
    /// I'll use the same types of functions as in ByteConverter.
    /// </summary>
    /// 
    public static class ByteConverter{

        public enum Encoding { Normal, TDS_password }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="hexString">For example "0x6a7167"</param>
        /// <returns></returns>
        public static byte[] ToByteArrayFromHexString(string hexString) {
            if(hexString.StartsWith("0x")) {
                if(hexString.Length%2==0){
                    byte[] byteArray=new byte[(hexString.Length-2)/2];
                    for(int i=0; i<byteArray.Length; i++)
                        byteArray[i]=Convert.ToByte(hexString.Substring(2+i*2, 2), 16);
                    return byteArray;
                }
                else
                    throw new Exception("HexString must contain an even number of bytes");
            }
            else
                throw new Exception("HexString must start with \"0x\"");
        }

        public static void ToByteArray(ushort value, byte[] array, int arrayOffset) {
            array[arrayOffset]=(byte)(value>>8);
            array[arrayOffset+1]=(byte)(value&0x00ff);
        }
        public static void ToByteArray(uint value, byte[] array, int arrayOffset) {
            array[arrayOffset]=(byte)(value>>24);
            array[arrayOffset+1]=(byte)((value>>16)&0x000000ff);
            array[arrayOffset+2]=(byte)((value>>8)&0x000000ff);
            array[arrayOffset+3]=(byte)(value&0x000000ff);
        }
        public static void ToByteArray(ulong value, byte[] array, int arrayOffset) {
            ToByteArray((uint)(value >> 32), array, arrayOffset);
            ToByteArray((uint)value, array, arrayOffset + 4);
        }
        public static byte[] ToByteArray(byte[] source, ref int index, byte endValue, bool copyEndValue) {
            byte[] endValues = {endValue};
            return ToByteArray(source, ref index, endValues, copyEndValue);
        }
        public static byte[] ToByteArray(byte[] source, ref int index, byte[] endValues, bool copyEndValue) {
            int count=source.Length-index;//maximum size
            foreach(byte endValue in endValues){
                int position = Array.IndexOf<byte>(source, endValue, index);
                if(position>index && position-index+1 < count)
                    count = position-index+1;
            }
            /*
            for(int i=index; i<source.Length; i++) {
                if(Array.IndexOf<byte>(endValues, source[i]  source[i] == endValue) {
                    count = i-index+1;
                    break;
                }
            }*/
            int returnArraySize = count;
            if(!copyEndValue && Array.IndexOf<byte>(endValues, source[index+count-1]) != -1)
                returnArraySize--;
            byte[] returnArray = new byte[returnArraySize];
            Array.Copy(source, index, returnArray, 0, returnArray.Length);
            index+=count;
            return returnArray;
        }



        public static ushort ToUInt16(byte[] value) {
            return (ushort)ToUInt32(value, 0, 2, false);
        }
        public static ushort ToUInt16(byte[] value, int startIndex) {
            return (ushort)ToUInt32(value, startIndex, 2, false);
        }
        public static ushort ToUInt16(byte[] value, int startIndex, bool reverseByteOrder) {
            return (ushort)ToUInt32(value, startIndex, 2, reverseByteOrder);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <param name="startIndex"></param>
        /// <param name="nBytes"></param>
        /// <param name="reverseByteOrder">true = little endian</param>
        /// <returns></returns>
        public static uint ToUInt32(byte[] value, int startIndex, int nBytes, bool reverseByteOrder) {
            uint returnValue=0;

            for(int i=0; i<nBytes && i+startIndex<value.Length; i++) {
                returnValue<<=8;
                if(reverseByteOrder)//first byte is smallest value (LSB)
                    returnValue+=(uint)value[startIndex+nBytes-1-i];
                else//first byte is largest value (MSB)
                    returnValue+=(uint)value[startIndex+i];
            }
            return returnValue;
        }

        public static ulong ToUInt64(byte[] value, int startIndex, bool reverseOrder) {
            ulong returnValue=0;

            uint i1=ToUInt32(value, startIndex, 4, reverseOrder);
            uint i2=ToUInt32(value, startIndex+4, 4, reverseOrder);
            if(reverseOrder) {
                returnValue+=i2;
                returnValue<<=32;
                returnValue+=i1;
            }
            else {
                returnValue+=i1;
                returnValue<<=32;
                returnValue+=i2;
            }
            return returnValue;
        }
        public static uint ToUInt32(byte[] value, int startIndex, int nBytes) {
            return ToUInt32(value, startIndex, nBytes, false);
        }
        public static uint ToUInt32(byte[] value) {
            return ToUInt32(value, 0, value.Length, false);
        }
        public static uint ToUInt32(byte[] value, int startIndex) {
            return ToUInt32(value, startIndex, 4, false);
        }

        public static uint ToUInt32(System.Net.IPAddress ip) {
            byte[] bytes=ip.GetAddressBytes();
            long l=0;
            for(int i=0; i<bytes.Length; i++)
                l=(l<<8)+bytes[i];
            return (uint)l;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ushort1">Most significant 2 bytes</param>
        /// <param name="ushort2">Least significant 2 bytes</param>
        /// <returns></returns>
        public static uint ToUInt32(ushort ushort1, ushort ushort2) {
            uint returnValue=(uint)ushort1;
            returnValue<<=16;
            returnValue^=ushort2;
            return returnValue;
        }

        /// <summary>
        /// Reads one line from the byte[] in data and returns the line as a string.
        /// A line is defined by a number of char's followed by \r\n
        /// </summary>
        /// <param name="data"></param>
        /// <param name="dataIndex"></param>
        /// <returns>The string (wihtout CRLF) if all is OK, otherwise null (for example if there is no CRLF)</returns>
        public static string ReadLine(byte[] data, ref int dataIndex, bool acceptUnixLinefeeds = false) {
            int maxStringLength=16384;
            //  \r = 0x0d = carriage return (not required for Unix line feeds)
            //  \n = 0x0a = line feed
            StringBuilder line=new StringBuilder();
            bool carrigeReturnReceived=false;
            bool lineFeedReceived=false;
            int indexOffset=0;
            while(!(acceptUnixLinefeeds || carrigeReturnReceived) || !lineFeedReceived) {
                if(dataIndex+indexOffset>=data.Length || indexOffset>=maxStringLength)
                    return null;
                else {
                    byte b=data[dataIndex+indexOffset];
                    if(b==0x0d)
                        carrigeReturnReceived=true;
                    else if((acceptUnixLinefeeds || carrigeReturnReceived) && b==0x0a)
                        lineFeedReceived=true;
                    else {
                        line.Append((char)b);
                        carrigeReturnReceived=false;
                        lineFeedReceived=false;
                    }
                    indexOffset++;
                }
            }
            dataIndex+=indexOffset;
            return line.ToString();

        }


        public static string ReadHexString(byte[] data, int nBytesToRead){
            return ReadHexString(data, nBytesToRead, 0);
        }
        public static string ReadHexString(byte[] data, int nBytesToRead, int offset){
            StringBuilder sb=new StringBuilder();
            for(int i=0; i<nBytesToRead; i++) {
                sb.Append(data[offset+i].ToString("X2"));
            }
            return sb.ToString();
        }

        public static string ReadString(byte[] data) {
            int i=0;
            return ReadString(data, ref i, data.Length, false, false);
        }
        public static string ReadString(byte[] data, string nonAsciiNonPrintableReplacement) {
            return System.Text.RegularExpressions.Regex.Replace(ReadString(data), @"\p{Cc}", nonAsciiNonPrintableReplacement);
        }
        //note: @"[^ -~]" replaces all non 7-bit ASCII printable while @"\p{Cc}" preserves non-7bit-ASCII printable (like 0xff = "ÿ")
        public static string ReadString(byte[] data, int startIndex, int lenght, string nonAsciiNonPrintableReplacement) {
            return System.Text.RegularExpressions.Regex.Replace(ReadString(data, startIndex, lenght), @"[^ -~]", nonAsciiNonPrintableReplacement);
        }
        public static string ReadString(byte[] data, int startIndex, int lenght) {
            return ReadString(data, ref startIndex, lenght, false, false);
        }
        public static string ReadString(byte[] data, int startIndex, int lenght, bool unicodeData, bool reverseOrder) {
            return ReadString(data, ref startIndex, lenght, unicodeData, reverseOrder);
        }
        public static string ReadString(byte[] data, ref int dataIndex, int bytesToRead, bool unicodeData, bool reverseOrder, bool nullTerminatedString = false) {
            return ReadString(data, ref dataIndex, bytesToRead, unicodeData, reverseOrder, Encoding.Normal, nullTerminatedString);
        }
        public static string ReadString(byte[] data, ref int dataIndex, int bytesToRead, bool unicodeData, bool reverseOrder, Encoding encoding, bool nullTerminatedString = false) {
            int i = 0;
            StringBuilder sb = new StringBuilder();
            while (i < bytesToRead && dataIndex + i < data.Length) {
                if (unicodeData) {
                    ushort unicodeValue = ByteConverter.ToUInt16(data, dataIndex + i, reverseOrder);
                    if (nullTerminatedString && unicodeValue == 0)
                        break;
                    if (encoding == Encoding.TDS_password) {
                        //http://www.securiteam.com/tools/6Q00I0UEUM.html
                        //XOR with A5
                        unicodeValue ^= 0xa5a5;
                        //swap nibbles
                        unicodeValue = SwapNibbles(unicodeValue);
                    }
                    sb.Append((char)unicodeValue);
                    i += 2;
                }
                else {
                    if (data[dataIndex + i] == 0)
                        break;

                    sb.Append((char)data[dataIndex + i]);
                    i++;
                }
            }
            dataIndex += i;

            return sb.ToString();
        }

        

        public static string ReadLengthValueString(byte[] data, ref int index, int stringLengthFieldBytes) {
            int stringLength=0;
            if(stringLengthFieldBytes == 1)
                stringLength = data[index];
            else if(stringLengthFieldBytes == 2)
                stringLength = ByteConverter.ToUInt16(data, index);
            else if(stringLengthFieldBytes == 4)
                stringLength = (int)ByteConverter.ToUInt32(data, index);
            else
                throw new Exception("Selected stringLengthFieldBytes is not supported");
            index+=stringLengthFieldBytes;
            string returnString = ByteConverter.ReadString(data, index, stringLength);
            index+=stringLength;
            return returnString;
        }

        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex) {
            return ReadNullTerminatedString(data, ref dataIndex, false, false);
        }
        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex, bool unicodeData, bool reverseOrder) {
            int maxStringLength=1024;
            return ReadNullTerminatedString(data, ref dataIndex, unicodeData, reverseOrder, maxStringLength);
        }
        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex, bool unicodeData, bool reverseOrder, int maxStringLength) {
            StringBuilder returnString =new StringBuilder();

            if(!unicodeData) {
                for(int offset=0; dataIndex+offset<data.Length && offset<maxStringLength; offset++) {
                    byte b=data[dataIndex+offset];
                    if(b==0x00) {
                        dataIndex+=(offset+1);
                        return returnString.ToString();
                    }
                    else {
                        returnString.Append((char)b);
                    }
                }
            }
            else {//unicode
                for(int offset=0; dataIndex+offset<data.Length && offset<maxStringLength*2; offset+=2) {
                    ushort b;
                    if(dataIndex+offset+1<data.Length)
                        b=ByteConverter.ToUInt16(data, dataIndex+offset, reverseOrder);
                    else//only one byte to read
                        b=(ushort)data[dataIndex+offset];
                    if(b==0x0000) {
                        dataIndex+=(offset+2);
                        return returnString.ToString();
                    }
                    else {
                        returnString.Append((char)b);
                    }
                }
            }
            //we should hopefully not end up here!!!
            //But sometimes implementations just don't use a terminator and instead they just end the whole packet!!!
            //so let's degrade gracefully...
            if (unicodeData)
                dataIndex += returnString.Length * 2;
            else
                dataIndex += returnString.Length;
            return returnString.ToString();
        }

        //converts a string that looks like for example "2 421 100 B" into 2421100
        public static double StringToClosestDouble(string numberLikeLookingString) {
            double returnValue=0.0;
            int decimalNumber=0;
            for(int i=0; i<numberLikeLookingString.Length; i++) {
                char c=numberLikeLookingString[i];
                if(Char.IsNumber(c)) {
                    if(decimalNumber==0)
                        returnValue=returnValue*10+(int)c;
                    else {
                        returnValue+=returnValue/(Math.Pow(10.0, (double)decimalNumber));
                        decimalNumber++;
                    }
                }
                else if(decimalNumber==0 && (c=='.' || c==','))
                    decimalNumber=1;
            }
            return returnValue;
        }

        public static string ToMd5HashString(string originalText) {
            System.Security.Cryptography.MD5 md5=System.Security.Cryptography.MD5CryptoServiceProvider.Create();
            byte[] textArray=new byte[originalText.Length];
            for(int i=0; i<originalText.Length; i++)
                textArray[i]=(byte)originalText[i];
            byte[] hashArray=md5.ComputeHash(textArray);
            StringBuilder hashStringBuilder=new StringBuilder();
            for(int i=0; i<hashArray.Length; i++) {
                hashStringBuilder.Append(hashArray[i].ToString("X2").ToLower());
            }
            return hashStringBuilder.ToString();
        }

        //Format: 6162633132330a\tabc123.
        public static string ToXxdHexString(byte[] data) {
            string hexPart = ReadHexString(data, data.Length);
            string asciiPart = ReadString(data, ".");
            return hexPart + "\t" + asciiPart;
        }


        public static ushort SwapNibbles(ushort data) {
            return (ushort)(((data>>4)&0x0f0f)|((data<<4)&0xf0f0));
        }

        public static DateTime ToUnixTimestamp(byte[] data, int offset) {
            //reads 4 bytes
            long seconds=(long)ByteConverter.ToUInt32(data, offset);/*seconds since January 1, 1970 00:00:00 GMT*/
            DateTime timestamp=new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return timestamp.AddTicks(seconds*10000000);
        }

        public static List<byte> ToQuotedPrintable(string text) {
            List<byte> quotedPrintableBytes = new List<byte>();
            //byte[] asciiBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(text);
            byte[] cp850bytes = System.Text.Encoding.GetEncoding(850).GetBytes(text);
            foreach(byte b in cp850bytes) {
                if(b>=33 && b<=60)//Rule #2
                    quotedPrintableBytes.Add(b);
                else if(b>=62 && b<=126)//Rule #2
                    quotedPrintableBytes.Add(b);
                else if(b==9 || b==32)//Rule #3
                    quotedPrintableBytes.Add(b);
                else {//Rule #1
                    string escapeSequence = "=" + b.ToString("X2");
                    foreach(byte eb in System.Text.ASCIIEncoding.ASCII.GetBytes(escapeSequence))
                        quotedPrintableBytes.Add(eb);
                }

            }
            return quotedPrintableBytes;
        }

        public static List<byte> ReadQuotedPrintable(byte[] quotedPrintableData) {
            //http://tools.ietf.org/html/rfc2045#page-19

            /**
             * (General 8bit representation) Any octet, except a CR or
             * LF that is part of a CRLF line break of the canonical
             * (standard) form of the data being encoded, may berepresented by an "=" followed by a two digit
             * hexadecimal representation of the octet's value.  The
             * digits of the hexadecimal alphabet, for this purpose,
             * are "0123456789ABCDEF".  Uppercase letters must be
             * used; lowercase letters are not allowed.  Thus, for
             * example, the decimal value 12 (US-ASCII form feed) can
             * be represented by "=0C", and the decimal value 61 (US-
             * ASCII EQUAL SIGN) can be represented by "=3D".  This
             * rule must be followed except when the following rules
             * allow an alternative encoding.
             */

            List<byte> outputBytes = new List<byte>();
            byte equals=0x3d; //'='
            for(int i=0; i<quotedPrintableData.Length; i++) {
                if(quotedPrintableData[i]==equals && i+2<quotedPrintableData.Length) {
                    string hexValue = ByteConverter.ReadString(quotedPrintableData, i+1, 2);
                    try {
                        outputBytes.Add(Convert.ToByte(hexValue, 16)); //read from hex value to byte
                    }
                    catch(Exception e) {
                        //do nothing
                    }
                    i+=2; //skip past the quoted value
                }
                else
                    outputBytes.Add(quotedPrintableData[i]);
            }
            return outputBytes;
        }

        /// <summary>
        /// Gets the sequence element length (in number of bytes) and advances the index value to the first byte after the length data
        /// </summary>
        /// <param name="data">The raw data</param>
        /// <param name="index">The index should point to the length start position in data. The index will be moved to the first position after the lenght parameter after the function is executed.</param>
        /// <returns>ASN.1 BER/DER length</returns>
        public static int GetAsn1Length(byte[] data, ref int index) {
            //https://en.wikipedia.org/wiki/X.690#Length_octets
            //https://msdn.microsoft.com/en-us/library/ms995330.aspx

            int sequenceElementLength = 0;
            //see if first bit (indicating long data) is set
            if (data[index] >= 0x80) {
                int bytesInLengthValue = data[index] & 0x0f;
                index++;

                if (bytesInLengthValue == 0)
                    return Int32.MaxValue;//Should actually be Indefinite
                else if (sequenceElementLength >= 127)
                    throw new Exception("Reserved");
                else {
                    //lengths are in Network Byte Order (Big-Endian).
                    sequenceElementLength = (int)Utils.ByteConverter.ToUInt32(data, index, bytesInLengthValue, false);
                    index += bytesInLengthValue;
                }
            }
            else {//just a short single byte lenght value
                sequenceElementLength = (int)data[index];
                index++;
                
            }
            return sequenceElementLength;
        }

    }
}
