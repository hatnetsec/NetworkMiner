//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SpotifyKeyExchangePacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.SpotifyServerProtocol; }
        }


        public SpotifyKeyExchangePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            

            foreach (Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.SpotifyKeyExchangePacket)) {
                    Packets.SpotifyKeyExchangePacket spotifyPacket=(Packets.SpotifyKeyExchangePacket)p;
                    if(spotifyPacket.IsClientToServer) {
                        if(!tcpSession.ClientHost.ExtraDetailsList.ContainsKey("Spotify application OS"))
                            tcpSession.ClientHost.ExtraDetailsList.Add("Spotify application OS", spotifyPacket.ClientOperatingSystem);
                        NetworkCredential nc=new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, spotifyPacket.PacketTypeDescription, spotifyPacket.ClientUsername, spotifyPacket.ParentFrame.Timestamp);
                        nc.Password="Client DH public key: "+spotifyPacket.PublicKeyHexString;
                        base.MainPacketHandler.AddCredential(nc);
                    }
                    else {
                        NetworkCredential nc=new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, spotifyPacket.PacketTypeDescription, spotifyPacket.ClientUsername, spotifyPacket.ParentFrame.Timestamp);
                        nc.Password="Server DH public key: "+spotifyPacket.PublicKeyHexString;
                        base.MainPacketHandler.AddCredential(nc);
                    }
                    //this function will always return true for spotify packets since I don't want to cache a lot of packets!
                    return spotifyPacket.PacketLength;
                }
            }
            return 0;
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
            ////do nothing... no state
        }

        #endregion
    }
}
