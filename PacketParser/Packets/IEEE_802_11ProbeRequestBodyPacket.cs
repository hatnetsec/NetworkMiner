using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.Packets {
    class IEEE_802_11ProbeRequestBodyPacket : AbstractPacket{
        private string requestedSsid;

        //802.11 - 1999.pdf - 7.2.3.8 Probe Request frame format
        internal IEEE_802_11ProbeRequestBodyPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IEEE 802.11 Probe Request Body") {
            //1 SSID
            
            //skip tag number
            byte length=parentFrame.Data[PacketStartIndex+1];
            this.requestedSsid=new String(parentFrame.Data, PacketStartIndex+2, length);

            //2 Supported rates
            //skip rates...
        }


        internal override IEnumerable<AbstractPacket> GetSubPackets() {
            throw new Exception("The method or operation is not implemented.");
        }
    }
}
