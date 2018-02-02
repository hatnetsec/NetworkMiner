//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    internal class NtlmSspPacket : AbstractPacket{
        //http://davenport.sourceforge.net/ntlm.html

        internal enum NtlmMessageTypes : uint { Negotiate=0x01000000, Challenge=0x02000000, Authentication=0x03000000 }

        internal struct SecurityBuffer {

            internal ushort length;
            internal ushort lengthAllocated;
            internal uint offset;

            internal SecurityBuffer(byte[] data, ref int dataOffset) {
                this.length = Utils.ByteConverter.ToUInt16(data, dataOffset, true);
                dataOffset+=2;
                this.lengthAllocated = Utils.ByteConverter.ToUInt16(data, dataOffset, true);
                dataOffset+=2;
                this.offset = Utils.ByteConverter.ToUInt32(data, dataOffset, 4, true);
                dataOffset+=4;
            }

            internal byte[] GetBufferData(byte[] frameData, int packetStartIndex) {
                byte[] buffer=new byte[this.length];
                Array.Copy(frameData, packetStartIndex+offset, buffer, 0, length);
                return buffer;
            }
        }

        private string domainName;
        private string userName;
        private string hostName;

        private string lanManagerResponse;
        private string ntlmResponse;

        private string ntlmChallenge;


        internal string DomainName { get { return this.domainName; } }
        internal string UserName { get { return this.userName; } }
        internal string HostName { get { return this.hostName; } }

        internal string LanManagerResponse { get { return this.lanManagerResponse; } }
        internal string NtlmResponse { get { return this.ntlmResponse; } }

        internal string NtlmChallenge { get { return this.ntlmChallenge; } }

        internal NtlmSspPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NTLMSSP") {

            this.domainName=null;
            this.userName=null;
            this.hostName=null;

            this.lanManagerResponse=null;
            this.ntlmResponse=null;

            int packetIndex=packetStartIndex;
            //0x4e544c4d53535000 = "NTLMSSP"
            if (Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref packetIndex) != "NTLMSSP")
                throw new Exception("Expected NTLMSSP signature string missing!");
            uint messageType = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetIndex);
            //message type is normally 0x00000001 = Negotiate
            packetIndex+=4;

            if(messageType==(uint)NtlmMessageTypes.Negotiate) {
                /*
                 *  Description Content 
                 * 0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                 * 8 NTLM Message Type long (0x01000000) 
                 * 12 Flags long 
                 * (16) Supplied Domain (Optional) security buffer 
                 * (24) Supplied Workstation (Optional) security buffer 
                 * (32) OS Version Structure (Optional) 8 bytes 
                 * (32) (40) start of data block (if required) 
                 */
            }
            else if(messageType==(uint)NtlmMessageTypes.Challenge) {
                //  Description Content 
                //0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                //8 NTLM Message Type long (0x02000000) 
                //12 Target Name security buffer 
                //20 Flags long 
                //24 Challenge 8 bytes 
                //(32) Context (optional) 8 bytes (two consecutive longs) 
                //(40) Target Information (optional) security buffer 
                //(48) OS Version Structure (Optional) 8 bytes 
                //32 (48) (56) start of data block 
                bool dataIsUnicode=false;
                SecurityBuffer domainNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);

                //see if we have unicode data
                if(domainNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+domainNameSecurityBuffer.offset+domainNameSecurityBuffer.length-1]==(byte)0x00);

                packetIndex+=4;//skip flags
                this.ntlmChallenge = Utils.ByteConverter.ReadHexString(parentFrame.Data, 8, packetIndex);
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("NTLM Challenge", this.ntlmChallenge);

                if(domainNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)domainNameSecurityBuffer.offset;
                    this.domainName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, domainNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Domain Name", this.domainName);
                }

            }
            else if(messageType==(uint)NtlmMessageTypes.Authentication) {
                //  Description Content 
                //0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                //8 NTLM Message Type long (0x03000000) 
                //12 LM/LMv2 Response security buffer 
                //20 NTLM/NTLMv2 Response security buffer 
                //28 Target Name security buffer 
                //36 User Name security buffer 
                //44 Workstation Name security buffer 
                //(52) Session Key (optional) security buffer 
                //(60) Flags (optional) long 
                //(64) OS Version Structure (Optional) 8 bytes 
                //52 (64) (72) start of data block 

                bool dataIsUnicode=false;
                SecurityBuffer lanManagerSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer ntLanManagerSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer domainNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer userNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer workstationNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer sessionKeySecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                
                //see if we have unicode data
                if(domainNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+domainNameSecurityBuffer.offset+domainNameSecurityBuffer.length-1]==(byte)0x00);
                else if(userNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+userNameSecurityBuffer.offset+userNameSecurityBuffer.length-1]==(byte)0x00);
                else if(workstationNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+workstationNameSecurityBuffer.offset+workstationNameSecurityBuffer.length-1]==(byte)0x00);   

                //extract the data
                if(lanManagerSecurityBuffer.length>0) {
                    byte[] bufferData=lanManagerSecurityBuffer.GetBufferData(parentFrame.Data, packetStartIndex);
                    this.lanManagerResponse = Utils.ByteConverter.ReadHexString(bufferData, bufferData.Length);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("LAN Manager Response", this.lanManagerResponse);
                }
                if(ntLanManagerSecurityBuffer.length>0) {
                    byte[] bufferData=ntLanManagerSecurityBuffer.GetBufferData(parentFrame.Data, PacketStartIndex);
                    this.ntlmResponse = Utils.ByteConverter.ReadHexString(bufferData, bufferData.Length);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("NTLM Response", this.ntlmResponse);
                }
                if(domainNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)domainNameSecurityBuffer.offset;
                    this.domainName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, domainNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Domain Name", this.domainName);
                }
                if(userNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)userNameSecurityBuffer.offset;
                    this.userName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, userNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("User Name", this.userName);
                }
                if(workstationNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)workstationNameSecurityBuffer.offset;
                    this.hostName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, workstationNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Host Name", this.hostName);
                }

            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
