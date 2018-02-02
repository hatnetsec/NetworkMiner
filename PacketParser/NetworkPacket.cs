//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class NetworkPacket {
        private NetworkHost sourceHost, destinationHost;
        private ushort? sourceTcpPort, destinationTcpPort, sourceUdpPort, destinationUdpPort;
        private bool tcpSynFlag, tcpSynAckFlag;
        private int tcpPacketByteCount;

        private int packetBytes;//from IP-level (i.e. without ethernet header)
        private DateTime timestamp;
        private int payloadBytes, cleartextBytes;//are theese really needed on packet level???

        internal int PacketBytes { get { return packetBytes; } }
        internal int PayloadBytes { get { return payloadBytes; } }
        internal int CleartextBytes { get { return cleartextBytes; } }
        internal NetworkHost SourceHost { get { return sourceHost; } }
        internal NetworkHost DestinationHost { get { return destinationHost; } }
        internal ushort? SourceTcpPort { get { return sourceTcpPort; } }
        internal ushort? DestinationTcpPort { get { return destinationTcpPort; } }
        internal ushort? SourceUdpPort { get { return sourceUdpPort; } }
        internal ushort? DestinationUdpPort { get { return destinationUdpPort; } }
        internal DateTime Timestamp { get { return this.timestamp; } }
        internal bool TcpSynFlag { get { return this.tcpSynFlag; } }
        internal bool TcpSynAckFlag { get { return this.tcpSynAckFlag; } }
        internal int TcpPacketByteCount { get { return this.tcpPacketByteCount; } }

        internal NetworkPacket(NetworkHost sourceHost, NetworkHost destinationHost, Packets.AbstractPacket ipPacket) {
            this.tcpSynFlag=false;
            this.tcpSynAckFlag=false;
            this.tcpPacketByteCount=0;
            this.sourceHost=sourceHost;
            this.destinationHost=destinationHost;
            this.packetBytes=ipPacket.PacketEndIndex-ipPacket.PacketStartIndex+1;
            this.timestamp=ipPacket.ParentFrame.Timestamp;
            this.payloadBytes=0;
            this.cleartextBytes=0;

        }

        internal void SetTcpData(Packets.TcpPacket tcpPacket) {
            this.sourceTcpPort=tcpPacket.SourcePort;
            this.destinationTcpPort=tcpPacket.DestinationPort;
            this.tcpPacketByteCount=tcpPacket.PacketByteCount;
            //this.sourceHost.AddSentPacketFromTcpPort(tcpPacket.SourcePort);//this info is in the NetworkPacketList instead
            if(tcpPacket.FlagBits.Synchronize) {
                this.tcpSynFlag=true;
                if(tcpPacket.FlagBits.Acknowledgement) {
                    this.tcpSynAckFlag=true;
                    if(!sourceHost.TcpPortIsOpen(tcpPacket.SourcePort))
                        this.sourceHost.AddOpenTcpPort(tcpPacket.SourcePort);
                }
            }
        }
        internal void SetUdpData(Packets.UdpPacket udpPacket) {
            this.sourceUdpPort=udpPacket.SourcePort;
            this.destinationUdpPort=udpPacket.DestinationPort;
            //this.sourceHost.AddSentPacketFromUdpPort(udpPacket.SourcePort);//this info is in the NetworkPacketList instead
        }
        
        internal void SetPayload(int payloadBytes, int cleartextBytes) {
            this.payloadBytes=payloadBytes;
            this.cleartextBytes=cleartextBytes;
        }

    }


}
