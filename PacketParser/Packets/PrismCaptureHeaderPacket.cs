using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class PrismCaptureHeaderPacket : AbstractPacket{
        private uint messageLength;
        private string device;
        private uint channel;

        public uint MessageLength { get { return this.messageLength; } }
        public string Device { get { return this.device; } }
        public uint Channel { get { return this.channel; } }


        internal PrismCaptureHeaderPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Prism capture header") {
                this.messageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, PacketStartIndex + 4, 4, true);
            this.device = Utils.ByteConverter.ReadString(parentFrame.Data, PacketStartIndex + 8, 16, false, false);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Device", device);
            //skip host timestamp. 12 bytes
            //skip MAC timestamp. 12 bytes
            this.channel = Utils.ByteConverter.ToUInt32(parentFrame.Data, PacketStartIndex + 56, 4, true);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Channel", channel.ToString());

        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+144<PacketEndIndex) {
                AbstractPacket packet;
                try {
                    packet=new IEEE_802_11Packet(ParentFrame, PacketStartIndex+144, PacketEndIndex);
                }
                catch(Exception e) {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+144, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;

            }

            yield break;
        }
    }
}
