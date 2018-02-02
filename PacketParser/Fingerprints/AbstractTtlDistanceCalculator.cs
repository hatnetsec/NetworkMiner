using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Fingerprints {
    abstract class AbstractTtlDistanceCalculator : ITtlDistanceCalculator {


        #region ITtlDistanceCalculator Members

        //some default behaviour that can be overridden by other classes
        public virtual bool TryGetTtlDistance(out byte ttlDistance, IEnumerable<Packets.AbstractPacket> packetList) {
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.IPv4Packet)){
                    ttlDistance=GetTtlDistance(((Packets.IPv4Packet)p).TimeToLive);
                    return true;
                }
            }
            ttlDistance=0;
            return false;
        }

        public virtual byte GetTtlDistance(byte ipTimeToLive) {
            return (byte)(GetOriginalTimeToLive(ipTimeToLive)-ipTimeToLive);
        }

        #endregion

        public virtual byte GetOriginalTimeToLive(byte ipTimeToLive) {
            if(ipTimeToLive>128)
                return (byte)255;
            else if(ipTimeToLive>64)
                return (byte)128;
            else if(ipTimeToLive>32)
                return (byte)64;
            else
                return (byte)32;
        }
    }
}
