//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //Stream Control Transmission Protocol (SCTP)
    public class SctpPacket : AbstractPacket, ITransportLayerPacket {

        private ushort sourcePort;
        private ushort destinationPort;
        private uint verificationTag;
        private uint checksum;

        public ushort SourcePort { get { return this.sourcePort; } }
        public ushort DestinationPort { get { return this.destinationPort; } }
        public uint VerificationTag { get { return this.verificationTag; } }
        public uint Checksum { get { return this.checksum; } }
        public byte DataOffsetByteCount { get { return 28; } }
        public byte FlagsRaw { get { return 0; } }

        internal SctpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SCTP") {

            this.sourcePort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source Port", sourcePort.ToString());
            this.destinationPort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination Port", destinationPort.ToString());

            this.verificationTag = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            this.checksum = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            yield break;
        }




    }
}
