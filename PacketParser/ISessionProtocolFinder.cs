using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {

    //this enum should probably be moved somewhere else...
    public enum ApplicationLayerProtocol {
        Unknown,
        Dhcp, //UDP
        Dns, //TCP or UDP
        FtpControl, //TCP
        Http, //TCP
        Irc, //TCP
        IEC_104, //TCP
        Imap, //TCP
        ModbusTCP, //TCP
        NetBiosNameService, //TCP or UDP
        NetBiosDatagramService, //UDP
        NetBiosSessionService, //TCP
        OpenFlow, //TCP
        Oscar, //TCP
        OscarFileTransfer, //TCP
        Pop3, //TCP
        Smtp, //TCP
        Socks, //TCP
        Ssh, //TCP
        Ssl, //TCP
        Syslog, //UDP
        TabularDataStream, //TCP
        Tftp, //UDP
        Tpkt, //TCP
        Upnp, //UDP
        Sip, //UDP
        SpotifyServerProtocol, //TCP
        VXLAN//UDP
    }

    //public enum TransportLayerProtocol { UDP, TCP }

    public interface ISessionProtocolFinder {
        PacketParser.NetworkHost Server { get;}
        PacketParser.NetworkHost Client { get;}
        ushort ServerPort { get;}
        ushort ClientPort { get;}
        //TransportLayerProtocol TransportLayerProtocol { get; }
        NetworkFlow Flow { get; }

        //PacketParser.ApplicationLayerProtocol ConfirmedApplicationLayerProtocol{ get; set;}
        PacketParser.ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol();
        void SetConfirmedApplicationLayerProtocol(PacketParser.ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint);


        void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, PacketParser.NetworkHost source, PacketParser.NetworkHost destination);
        IEnumerable<PacketParser.ApplicationLayerProtocol> GetProbableApplicationLayerProtocols();
        

    }
}
