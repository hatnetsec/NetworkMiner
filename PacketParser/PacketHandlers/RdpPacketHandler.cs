using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class RdpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {


        public RdpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                throw new NotImplementedException();
            }
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            /*
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }*/
            System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
            Packets.RdpPacket.Cookie rdpCookiePacket = null;
            foreach (Packets.AbstractPacket p in packetList) {
                //if (p is Packets.IIPPacket)
                //    ipPacket = (Packets.IIPPacket)p;
                if (p.GetType() == typeof(Packets.RdpPacket.Cookie)) {
                    rdpCookiePacket = (Packets.RdpPacket.Cookie)p;
                    if (rdpCookiePacket.RoutingCookie != null && rdpCookiePacket.RoutingCookie.Length > 0) {
                        base.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "RDP Cookie", rdpCookiePacket.RoutingCookie, "", rdpCookiePacket.ParentFrame.Timestamp));
                        if(rdpCookiePacket.RoutingCookie.Contains("=")) {
                            string[] parts = rdpCookiePacket.RoutingCookie.Split('=');
                            if(parts.Length > 1) {
                                string pn = parts[0].Trim();
                                string pv = parts[1].Trim();
                                if(pn.Length > 0 && pv.Length > 0)
                                    parms.Add(pn, pv);
                            }
                        }
                            
                    }

                
                }
            }
            if (parms.Count > 0 && rdpCookiePacket != null)
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(rdpCookiePacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, rdpCookiePacket.ParentFrame.Timestamp, "RDP Cookie"));


            return 0;//these bytes should already have been accounted for by the generic handler for TPKT
        }



        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
