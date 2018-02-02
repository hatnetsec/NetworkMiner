//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //NetBIOS Abstract Base packet. Has to be extended by a "Name Service" or "Datagram Service" packet
    //http://ubiqx.org/cifs/rfc-draft/rfc1001.html#s14.1
    //http://ubiqx.org/cifs/NetBIOS.html

    //The purpose of this intermediate class is to have all NetBIOS common functions in one place.
    //That is for example the "RFC 1001 FIRST LEVEL ENCODING"
    abstract class NetBiosPacket : AbstractPacket {

        internal NetBiosPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, string packetTypeDescription)
            : base(parentFrame, packetStartIndex, packetEndIndex, packetTypeDescription) {
            //nothing important to store here...
        }

        /// <summary>
        /// This functions decodes NetBIOS names encoded with First Level Encoding
        /// The function also moves forward in the frameIndex so that it is set to the first byte AFTER the
        /// NetBIOS name when the function is finished.
        /// </summary>
        /// <param name="frameIndex"></param>
        /// <returns></returns>
        internal static string DecodeNetBiosName(Frame parentFrame, ref int frameIndex){
            int initialFrameIndex=frameIndex;
            //get a NetBIOS name label
            StringBuilder decodedName=new StringBuilder("");
            byte labelByteCount=parentFrame.Data[frameIndex];//max 63
            if (!parentFrame.QuickParse)
                if(labelByteCount>63)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, frameIndex, frameIndex, "NetBios Name label is larger than 63 : "+labelByteCount));
            frameIndex++;
            for(byte b=0; b<labelByteCount; b+=2) {
                byte b1;
                byte b2;
                b1=parentFrame.Data[frameIndex];
                b2=parentFrame.Data[frameIndex+1];
                char c=(char)(((b1-0x41)<<4)+(b2-0x41));
                if(b==labelByteCount-2 && frameIndex==initialFrameIndex+1+2*15) {//Microsoft(!) uses 16:th and last character in the NetBIOS name as a "NetBIOS suffix"
                    //See http://support.microsoft.com/kb/q163409/
                    if(((byte)c)!=0x00 && ((byte)c)!=0x20)//I skip theese since they are the normal ones for hosts
                        decodedName.Append("<"+((byte)c).ToString("X2")+">");
                }
                else if(c!=(char)0x20 && c!=(char)0x00)//0x20 is padding (spaces). In some cases 0x00 is used as padding, that's not according to the standard (bad Microsoft!).
                    decodedName.Append(c);
                frameIndex+=2;
            }
            //check for the 0x00 terminator
            //now get the SCOPE_ID label
            while(parentFrame.Data[frameIndex]!=0x00 && frameIndex<initialFrameIndex+255 && frameIndex<parentFrame.Data.Length) {//&& frameIndex<packetStartIndex+12+255
                decodedName.Append(".");
                labelByteCount=parentFrame.Data[frameIndex];//max 63
                if (!parentFrame.QuickParse)
                    if(labelByteCount>63)
                        parentFrame.Errors.Add(new Frame.Error(parentFrame, frameIndex, frameIndex, "NetBios Name label is larger than 63 : "+labelByteCount));
                frameIndex++;
                for(byte b=0; b<labelByteCount; b++) {
                    decodedName.Append((char)parentFrame.Data[frameIndex]);
                    frameIndex++;
                }
            }
            frameIndex++;
            //we have now decoded the name!
            return decodedName.ToString();//I'll just assume that there is only one question...
        }

    }
}
