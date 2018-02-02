using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SyslogPacketHandler : AbstractPacketHandler, IPacketHandler {


        public SyslogPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            Packets.SyslogPacket syslogPacket = null;
            Packets.UdpPacket udpPacket = null;

            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.SyslogPacket))
                    syslogPacket = (Packets.SyslogPacket)p;
                else if (p.GetType() == typeof(Packets.UdpPacket))
                    udpPacket = (Packets.UdpPacket)p;

                if (syslogPacket != null && udpPacket != null && syslogPacket.SyslogMessage != null && syslogPacket.SyslogMessage.Length > 0) {

                    System.Collections.Specialized.NameValueCollection tmpCol = new System.Collections.Specialized.NameValueCollection();

                    tmpCol.Add("Syslog Message", syslogPacket.SyslogMessage);

                    base.MainPacketHandler.OnParametersDetected(new PacketParser.Events.ParametersEventArgs(syslogPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, "UDP " + udpPacket.SourcePort, "UDP " + udpPacket.DestinationPort, tmpCol, syslogPacket.ParentFrame.Timestamp, "Syslog Message"));
                }
            }
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
