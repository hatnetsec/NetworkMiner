//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //Trivial File Transfer Protocol
    //http://tools.ietf.org/html/rfc1350
    //http://www.networksorcery.com/enp/rfc/rfc2347.txt (TFTP Option Extension)
    class TftpPacket : AbstractPacket {

        internal const ushort DefaultUdpPortNumber=(ushort)69;

        internal enum OpCodes : ushort {
            ReadRequest=0x01,//RRQ
            WriteRequest=0x02,//WRQ
            Data=0x03,//DATA
            Acknowledgment=0x04,//ACK
            Error=0x05,//ERROR
            OptionAcknowledgment = 0x06//rfc2347
        }
        internal enum Modes { netascii, octet, mail }

        private ushort opCode;
        private string filename;
        private Modes mode;
        private ushort dataBlockNumber;
        private byte[] dataBlock;
        private ushort blksize;
        private Dictionary<string,string> rfc2347OptionList;

        internal OpCodes OpCode {
            get {
                return (OpCodes)this.opCode;
            }
        }
        internal Modes Mode {
            get { return (Modes)this.mode; }
        }
        internal string Filename { get { return this.filename; } }
        internal byte[] DataBlock { get { return this.dataBlock; } }
        internal ushort DataBlockNumber { get { return this.dataBlockNumber; } }
        internal bool DataBlockIsLast { get { return this.dataBlock.Length<this.blksize; } }
        internal ushort Blksize { get { return this.blksize; } }


        //default block size is 512 bytes as stated in rfc1350 (rfc2347 makes it possible to use larger block sizes)
        internal TftpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : this(parentFrame, packetStartIndex, packetEndIndex, 512) { }

        internal TftpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort blksize)
            : base(parentFrame, packetStartIndex, packetEndIndex, "TFTP") {
            this.blksize = blksize;
            rfc2347OptionList = new Dictionary<string,string>();
            this.opCode = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            if (opCode < (ushort)OpCodes.ReadRequest || opCode > (ushort)OpCodes.OptionAcknowledgment)
                throw new Exception("Incorrect OPCODE ("+opCode+"), not correct TFTP pakcet");
            else {
                if(opCode==(ushort)OpCodes.ReadRequest || opCode==(ushort)OpCodes.WriteRequest) {
                    int index=packetStartIndex+2;
                    this.filename = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index);

                    //mode is: "netascii", "octet", or "mail" (in any upper or lower case version)
                    string strMode = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index);
                    if(strMode.ToLower()=="netascii")
                        this.mode=Modes.netascii;
                    else if(strMode.ToLower()=="octet")
                        this.mode=Modes.octet;
                    else if(strMode.ToLower()=="mail")
                        this.mode=Modes.mail;

                    /**
                     * From RFC 2347:
                     * TFTP options are appended to the Read Request and Write Request packets.
                     **/
                    while(index < packetEndIndex) {
                        string optName = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, packetEndIndex - index);
                        string optValue = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, packetEndIndex - index);
                        this.rfc2347OptionList[optName] = optValue;
                        if(optName.Equals("blksize", StringComparison.InvariantCultureIgnoreCase)) {
                            this.blksize = UInt16.Parse(optValue);
                        }
                    }

                }
                else if(opCode==(ushort)OpCodes.Data) {
                    this.dataBlockNumber = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                    this.dataBlock=new byte[Math.Min(blksize,packetEndIndex-packetStartIndex-3)];
                    Array.Copy(parentFrame.Data, packetStartIndex+4, this.dataBlock, 0, this.dataBlock.Length);
                }
                else if(opCode==(ushort)OpCodes.Acknowledgment) {
                    this.dataBlockNumber = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                }
                else if (opCode == (ushort)OpCodes.OptionAcknowledgment) {
                    int index = packetStartIndex + 2;
                    while (index < packetEndIndex) {
                        string optName = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, packetEndIndex - index);
                        string optValue = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, packetEndIndex - index);
                        this.rfc2347OptionList[optName] = optValue;
                        if (optName.Equals("blksize", StringComparison.InvariantCultureIgnoreCase)) {
                            this.blksize = UInt16.Parse(optValue);
                        }
                    }
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
