using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //Extensible Record Format (ERF) as used by Endance
    class ErfFrame : AbstractPacket {

        public enum RecordTypes : byte {
            ERF_TYPE_LEGACY = 0,
            ERF_TYPE_HDLC_POS = 1,
            ERF_TYPE_ETH = 2,
            ERF_TYPE_ATM = 3,
            ERF_TYPE_AAL5 = 4,
            ERF_TYPE_MC_HDLC = 5,
            ERF_TYPE_MC_RAW = 6,
            ERF_TYPE_MC_ATM = 7,
            ERF_TYPE_MC_RAW_CHANNEL = 8,
            ERF_TYPE_MC_AAL5 = 9,
            ERF_TYPE_COLOR_HDLC_POS = 10,
            ERF_TYPE_COLOR_ETH = 11,
            ERF_TYPE_MC_AAL2 = 12,
            ERF_TYPE_IP_COUNTER = 13,
            ERF_TYPE_TCP_FLOW_COUNTER = 14,
            ERF_TYPE_DSM_COLOR_HDLC_POS = 15,
            ERF_TYPE_DSM_COLOR_ETH = 16,
            ERF_TYPE_COLOR_MC_HDLC_POS = 17,
            ERF_TYPE_AAL2 = 18,
            ERF_TYPE_INFINIBAND = 21,
            ERF_TYPE_IPV4 = 22,
            ERF_TYPE_IPV6 = 23,
            ERF_TYPE_RAW_LINK = 24,
            ERF_TYPE_INFINIBAND_LINK = 25
        }

        private byte type;
        private bool extensionHeadersPresent = false;
        //private ushort rlen;

        internal ErfFrame(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "ERF") {
            this.type = (byte)(parentFrame.Data[packetStartIndex + 8] & 0x7f);
            this.extensionHeadersPresent = (parentFrame.Data[packetStartIndex + 8] & 0x80) == 0x80;
            //this.rlen = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 10, 
            if (!this.ParentFrame.QuickParse) {
                if(Enum.IsDefined(typeof(RecordTypes), this.type))
                    this.Attributes.Add("Type", ((RecordTypes)this.type).ToString().Substring(9));
                else
                    this.Attributes.Add("Type", ""+this.type);

            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            AbstractPacket packet = null;
            int erfHeaderLength = 16;
            if (this.extensionHeadersPresent)
                erfHeaderLength+=4;//correct?

            if(PacketStartIndex+16<PacketEndIndex) {
                if (type == (byte)RecordTypes.ERF_TYPE_ETH || type == (byte)RecordTypes.ERF_TYPE_COLOR_ETH || type == (byte)RecordTypes.ERF_TYPE_DSM_COLOR_ETH)
                    packet = new Ethernet2Packet(this.ParentFrame, this.PacketStartIndex + erfHeaderLength + 2, this.PacketEndIndex);
                else if (type == (byte)RecordTypes.ERF_TYPE_IPV4)
                    packet = new IPv4Packet(this.ParentFrame, this.PacketStartIndex + erfHeaderLength, this.PacketEndIndex);
                else if(type == (byte)RecordTypes.ERF_TYPE_IPV6)
                    packet = new IPv6Packet(this.ParentFrame, this.PacketStartIndex + erfHeaderLength, this.PacketEndIndex);
                else if (
                   type == (byte)RecordTypes.ERF_TYPE_HDLC_POS ||
                   type == (byte)RecordTypes.ERF_TYPE_COLOR_HDLC_POS ||
                   type == (byte)RecordTypes.ERF_TYPE_DSM_COLOR_HDLC_POS ||
                   type == (byte)RecordTypes.ERF_TYPE_COLOR_MC_HDLC_POS) {
                    int firstByte = this.ParentFrame.Data[this.PacketStartIndex];
                    if (firstByte == 0x0f || firstByte == 0x8f)
                        packet = new CiscoHdlcPacket(this.ParentFrame, this.PacketStartIndex + erfHeaderLength, this.PacketEndIndex);
                    else
                        packet = new PointToPointPacket(this.ParentFrame, this.PacketStartIndex + erfHeaderLength, this.PacketEndIndex);
                }

                if (packet != null) {
                    yield return packet;
                    foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
            }
            
        }
    }
}
