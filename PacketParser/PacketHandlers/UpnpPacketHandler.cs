//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class UpnpPacketHandler : AbstractPacketHandler, IPacketHandler {

        public UpnpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.UpnpPacket))
                    ExtractData((Packets.UpnpPacket)p, sourceHost);
            }
        }

        private void ExtractData(Packets.UpnpPacket upnpPacket, NetworkHost sourceHost) {
            if(upnpPacket.FieldList.Count>0) {
                if(sourceHost.UniversalPlugAndPlayFieldList==null)
                    sourceHost.UniversalPlugAndPlayFieldList=new SortedList<string, string>();
                lock(sourceHost.UniversalPlugAndPlayFieldList)
                    foreach(string field in upnpPacket.FieldList)
                        if(!sourceHost.UniversalPlugAndPlayFieldList.ContainsKey(field))
                            sourceHost.UniversalPlugAndPlayFieldList.Add(field, field);
            }
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
