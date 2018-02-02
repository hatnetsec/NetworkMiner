//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    public abstract class AbstractPacketHandler{

        private PacketHandler mainPacketHandler;
        internal PacketHandler MainPacketHandler { get { return this.mainPacketHandler; } }

        internal AbstractPacketHandler(PacketHandler mainPacketHandler) {
            this.mainPacketHandler=mainPacketHandler;
        }

    }
}
