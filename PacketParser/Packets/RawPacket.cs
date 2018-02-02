//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    /// <summary>
    /// RawPacket is used when the packet type is unknown
    /// </summary>
    public class RawPacket : AbstractPacket {

        public RawPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex):base(parentFrame, packetStartIndex, packetEndIndex, "Unknown") {

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
            //throw new Exception("The method or operation is not implemented.");
        }
        

    }
}
