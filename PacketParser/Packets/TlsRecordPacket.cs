//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    /// <summary>
    /// A Transport Layer Security (TLS) Record
    /// </summary>
    class TlsRecordPacket : AbstractPacket {
        //http://en.wikipedia.org/wiki/Transport_Layer_Security
        //http://tools.ietf.org/html/rfc2246

        internal enum ContentTypes : byte {
            ChangeCipherSpec=0x14,
            Alert=0x15,
            Handshake=0x16,
            Application=0x17,
        };

        private ContentTypes contentType;
        private byte versionMajor;//MSB
        private byte versionMinor;//LSB
        private ushort length;//MSB & LSB
        //private HandshakeProtocol handshakeProtocol;

        internal bool TlsRecordIsComplete { get { return PacketEndIndex-PacketStartIndex+1==5+this.length; } }
        internal ushort Length { get { return this.length; } }

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            if(!Enum.IsDefined(typeof(ContentTypes), parentFrame.Data[packetStartIndex]))
                return false;

            //verify that the complete TLS record has been received
            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            if(length+5 > packetEndIndex-packetStartIndex+1)
                return false;

            try {
                result = new TlsRecordPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result = null;
            }

            if(result == null)
                return false;
            else
                return true;
        }

        internal TlsRecordPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "TLS Record") {
            this.contentType=(ContentTypes)parentFrame.Data[packetStartIndex];
            this.versionMajor=parentFrame.Data[packetStartIndex+1];
            this.versionMinor=parentFrame.Data[packetStartIndex+2];
            this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            this.PacketEndIndex=Math.Min(packetStartIndex+5+length-1, this.PacketEndIndex);

            if (!this.ParentFrame.QuickParse) {
                this.Attributes.Add("Content Type", "" + this.contentType);
                this.Attributes.Add("TLS Version major", "" + versionMajor);
                this.Attributes.Add("TLS Version minor", "" + versionMinor);
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //I only care about the hadshake protocol
            if(this.contentType==ContentTypes.Handshake) {
                int subPacketStartIndex=PacketStartIndex+5;
                while(subPacketStartIndex<PacketEndIndex) {

                    AbstractPacket packet;
                    if(this.contentType==ContentTypes.Handshake) {
                        try {
                            packet=new HandshakePacket(ParentFrame, subPacketStartIndex, PacketEndIndex);
                        }
                        catch {
                            packet=new RawPacket(ParentFrame, subPacketStartIndex, PacketEndIndex);
                        }
                    }
                    else
                        packet=new RawPacket(ParentFrame, subPacketStartIndex, PacketEndIndex);

                    subPacketStartIndex=packet.PacketEndIndex+1;
                    yield return packet;
                }
            }//end handshake
        }

        internal class HandshakePacket : AbstractPacket{

            internal enum MessageTypes : byte {
                HelloRequest=0x00,
                ClientHello=0x01,
                ServerHello=0x02,
                Certificate=0x0b,

                ServerKeyExchange=0x0c,
                CertificateRequest=0x0d,
                ServerHelloDone=0x0e,
                CertificateVerify=0x0f,

                ClientKeyExchange=0x10,
                Finished=0x14,
            };

            private MessageTypes messageType;
            private uint messageLength;//actually a 3-byte (uint24) long field

            private System.Collections.Generic.List<byte[]> certificateList;//only for messageType=0x0b
            private string serverHostName = null;

            internal MessageTypes MessageType { get { return this.messageType; } }
            internal uint MessageLenght { get { return this.messageLength; } }
            internal System.Collections.Generic.List<byte[]> CertificateList { get { return this.certificateList; } }
            internal string ServerHostName { get { return this.serverHostName; } }



            internal HandshakePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, "TLS Handshake Protocol") {
                this.certificateList=new List<byte[]>();

                this.messageType=(MessageTypes)parentFrame.Data[packetStartIndex];
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Message Type", ""+messageType);
                this.messageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 3);
                this.PacketEndIndex=(int)(packetStartIndex+4+messageLength-1);

                if (this.messageType == MessageTypes.ClientHello) {
                    ushort cipherSuiteLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 39);
                    byte compressionMethodsLength = parentFrame.Data[PacketStartIndex + 41 + cipherSuiteLength];
                    ushort extensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 42 + cipherSuiteLength + compressionMethodsLength);
                    int extensionIndex = PacketStartIndex + 44 + cipherSuiteLength + compressionMethodsLength;
                    while(extensionIndex < this.PacketEndIndex && extensionIndex < PacketStartIndex + 44 + cipherSuiteLength + compressionMethodsLength + extensionsLength) {
                        ushort extensionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                        ushort extensionLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex +2);
                        if(extensionType == 0) {//Server Name Indication rfc6066
                            ushort serverNameListLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            while (offset < serverNameListLength) {
                                byte serverNameType = parentFrame.Data[extensionIndex + offset];
                                ushort serverNameLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + 1);
                                if(serverNameType == 0) {//host_name(0)
                                    this.serverHostName = Utils.ByteConverter.ReadString(parentFrame.Data, extensionIndex + offset + 3, serverNameLength);
                                }
                                offset += serverNameLength;
                            }

                        }
                        extensionIndex += 4 + extensionLength;
                    }
                }
                else if(this.messageType==MessageTypes.Certificate) {
                    uint certificatesLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 3);
                    int certificateIndexBase=packetStartIndex+7;
                    int certificateIndexOffset=0;
                    while(certificateIndexOffset<certificatesLenght) {
                        //read 3 byte length
                        uint certificateLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, certificateIndexBase + certificateIndexOffset, 3);
                        certificateIndexOffset+=3;
                        //rest is a certificate
                        byte[] certificate=new byte[certificateLenght];
                        Array.Copy(parentFrame.Data, certificateIndexBase+certificateIndexOffset, certificate, 0, certificate.Length);
                        this.certificateList.Add(certificate);
                        certificateIndexOffset+=certificate.Length;
                    }
                }
            }
            //Server Certificate: http://tools.ietf.org/html/rfc2246 7.4.2


            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if(includeSelfReference)
                    yield return this;
                yield break;//no sub packets
            }
        }



    }
}
