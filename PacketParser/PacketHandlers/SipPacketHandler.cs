using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SipPacketHandler : AbstractPacketHandler, IPacketHandler {

        public SipPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.SipPacket)) {
                    Packets.SipPacket sipPacket=(Packets.SipPacket)p;
                    if(sipPacket.To!=null && sipPacket.To.Length>0){
                        string to=sipPacket.To;
                        if(to.Contains(";"))
                            to=to.Substring(0,to.IndexOf(';'));
                        destinationHost.AddNumberedExtraDetail("SIP User", to);
                        //destinationHost.ExtraDetailsList["SIP User"]=to;
                    }
                    if(sipPacket.From!=null && sipPacket.From.Length>0) {
                        string from=sipPacket.From;
                        if(from.Contains(";"))
                            from=from.Substring(0, from.IndexOf(';'));
                        destinationHost.AddNumberedExtraDetail("SIP User", from);
                        //sourceHost.ExtraDetailsList["SIP User"]=from;
                    }
                }
            }
        }

        public void Reset() {
            //I could hold state of each session here, but that isn't needed right now
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
