//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    //http://ubiqx.org/cifs/SMB.html see: 2.1.2 NBT or Not NBT

    class NetBiosSessionService : NetBiosPacket, ISessionPacket {

        internal enum MessageTypes : byte { SessionMessage=0x00, SessionRequest=0x81, PositiveSessionResponse=0x82 }

        private byte messageType;
        private int length;

        private bool raw;//True if SMB should run directly over TCP, False if NetBIOS over TCP/IP is disabled

        internal byte MessageType { get { return this.messageType; } }
        internal int Length { get { return this.length; } }


        public bool PacketHeaderIsComplete {
            get { return true; }
        }

        public int ParsedBytesCount {
            get {
                return 4 + this.length; // header + content length
            }
        }

        [System.Obsolete("use TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result)", true)]
        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            throw new System.NotImplementedException("use TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result)");
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result) {
            result = null;
            bool raw = sourcePort == 445 || destinationPort == 445;
            uint sessionServiceHeader = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
            if (sessionServiceHeader == 0x85000000) {
                //CIFS TCP session keep-alive message
                result = new NetBiosSessionService(parentFrame, packetStartIndex, packetStartIndex + 3, raw);
                return true;
            }
            else {
                uint length;
                byte[] allowedCommands = { 0x00, 0x81, 0x82, 0x83, 0x84, 0x85 };//see NetBIOS RFC 1002 http://tools.ietf.org/html/rfc1002
                //if ((sessionServiceHeader & 0xff000000) != 0) //first byte must be zero according to http://ubiqx.org/cifs/SMB.html
                if (Array.IndexOf<byte>(allowedCommands, (byte)(sessionServiceHeader & 0xff000000)) < 0) //first byte must be 0x00, 0x81, 0x82, 0x83, 0x84, 0x85 according to RFC 1002
                    return false;
                if (raw)
                    length = sessionServiceHeader & 0x00ffffff;//get the last 3 bytes (24 bits)
                else
                    length = sessionServiceHeader & 0x0001ffff;//get the last 17 bits

                if (length == packetEndIndex - packetStartIndex + 1 - 4) {
                    result = new NetBiosSessionService(parentFrame, packetStartIndex, packetEndIndex, raw);
                    return true;
                }
                else if (length < packetEndIndex - packetStartIndex + 1 - 4) {
                    //there is more data to parse after the returned result
                    byte nextPacketHeaderByte = parentFrame.Data[packetStartIndex + length + 4];
                    if (nextPacketHeaderByte == 0x00 || nextPacketHeaderByte == 0x85) {
                        result = new NetBiosSessionService(parentFrame, packetStartIndex, packetStartIndex + (int)length + 3, raw);
                        return true;
                    }
                    else
                        return false;
                }
                else
                    return false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="parentFrame"></param>
        /// <param name="packetStartIndex"></param>
        /// <param name="packetEndIndex"></param>
        private NetBiosSessionService(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool raw)
        //internal NetBiosSessionService(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NetBIOS Session Service") {
            this.messageType=parentFrame.Data[packetStartIndex];

            if (this.messageType == 0x85 && packetEndIndex-packetStartIndex == 3) {
                /**
                 * From: http://msdn.microsoft.com/en-us/library/dd327704.aspx
                 * 
                 * A CIFS TCP session keep-alive message consists of a byte with value 0x85, followed by three bytes with value zero.
                 * 
                 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 * |      0x85     |                    0                          |
                 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 * 
                 * The keep-alive message may be sent if no messages have been sent for a client-configurable interval. A server receiving such a message must discard it.
                 * */
                this.length = 0;//will force bytesParsed to return 4
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Message", "NetBios Session Service session keep-alive");
            }
            else {
                //this.raw=raw;
                uint l = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
                if (raw)
                    this.length = (int)(l & 0x00ffffff);//get the last 3 bytes (24 bits)
                else
                    this.length = (int)(l & 0x0001ffff);//get the last 17 bits
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Length", length.ToString());
                if (this.length > 0 && this.PacketEndIndex  >  PacketStartIndex + this.length - 1)
                    this.PacketEndIndex = PacketStartIndex + this.length - 1;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;

            if(this.messageType==0x00 && PacketStartIndex+4<PacketEndIndex) {
                AbstractPacket packet;

                try {
                    if(ParentFrame.Data[PacketStartIndex + 4] == 0xff)
                        packet=new SmbPacket(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                    else if(ParentFrame.Data[PacketStartIndex + 4] == 0xfe)
                        packet = new Smb2Packet(ParentFrame, PacketStartIndex + 4, PacketEndIndex);
                    else
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 4, PacketEndIndex);
                }
                catch {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }

                yield return packet;

                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

        }


    }
}
