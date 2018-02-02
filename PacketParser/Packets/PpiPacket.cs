//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
    class PpiPacket : AbstractPacket {

        private ushort ppiLength;
        private PcapFileHandler.PcapFrame.DataLinkTypeEnum dataLinkType;

        internal PpiPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "PPI") {
                this.ppiLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, true);
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("Length", "" + ppiLength);
                uint dataLinkTypeUInt = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 4, true);
                this.dataLinkType = (PcapFileHandler.PcapFrame.DataLinkTypeEnum)dataLinkTypeUInt;
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("Data Link Type", dataLinkType.ToString());
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if (this.PacketStartIndex + this.ppiLength <= this.PacketEndIndex) {
                AbstractPacket packet = null;
                if (PacketFactory.TryGetPacket(out packet, this.dataLinkType, this.ParentFrame, this.PacketStartIndex + this.ppiLength, this.PacketEndIndex)) {
                    yield return packet;
                    foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
                else
                    yield return new RawPacket(this.ParentFrame, this.PacketStartIndex + this.ppiLength, this.PacketEndIndex);
            }
        
        }
    }
}
