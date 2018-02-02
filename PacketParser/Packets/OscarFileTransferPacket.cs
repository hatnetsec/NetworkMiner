//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class OscarFileTransferPacket : AbstractPacket, ISessionPacket {

        //http://www.shaim.net/trac/oscarlib/

        /**
         * This packet parser was written mainly as a result from the
         * philosecurity.org / SANS Network Forensics Puzzle Contest
         * http://philosecurity.org/2009/08/14/network-forensics-puzzle-contest
         * https://blogs.sans.org/computer-forensics/2009/08/19/network-forensics-puzzle-contest/
         */

        public enum CommandType : ushort { SendRequest=0x0101, ReceiveAccept=0x0202, TransferComplete=0x0204 }

        private ushort commandType;
        private string fileName;
        private uint totalFileSize;

        public CommandType Type { get { return (CommandType)this.commandType; } }
        public string FileName { get { return this.fileName; } }
        public uint TotalFileSize { get { return this.totalFileSize; } }

        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            try {
                if(packetEndIndex - packetStartIndex < 255)
                    return false;
                if (!Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex, 4).Equals("OFT2"))
                    return false;
                if (!Enum.IsDefined(typeof(CommandType), Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6)))
                    return false;

                result = new OscarFileTransferPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                return false;
            }
            return true;
        }


        internal OscarFileTransferPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "OSCAR File Transfer") {
            System.Diagnostics.Debug.Assert(base.PacketLength >= 256);
            string oft2String = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex, 4);
            System.Diagnostics.Debug.Assert(oft2String.Equals("OFT2"));
            //skip 0x0100
            //get the type
            this.commandType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);//0x0101
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Command Type", "0x"+this.commandType.ToString("X2"));
            //skip 8 bytes File Handler cookie
            ushort encryption = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 16);
            ushort compression = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 18);
            ushort totalFiles = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 20);
            ushort filesRemaining = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 22);
            ushort totalParts = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 24);
            ushort partsLeft = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 26);

            this.totalFileSize = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 28);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Total File Size", this.totalFileSize.ToString());
            //skip a lot of stuff
            int index = packetStartIndex+68;
            string idString = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index);
            //skip a lot
            index = packetStartIndex+192;
            this.fileName = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Filename", this.fileName);


        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            get { return true; }
        }

        public int ParsedBytesCount {
            get { return 256; }
        }

        #endregion
    }
}
