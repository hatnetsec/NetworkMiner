using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class UdpPortProtocolFinder : IPortProtocolFinder {

        private static IPortProtocolFinder instance = null;

        public static IPortProtocolFinder Instance {
            get {
                if (instance == null)
                    instance = new UdpPortProtocolFinder();
                return instance;
            }
            set {
                instance = value;
            }
        }


        public PacketParser.ApplicationLayerProtocol GetApplicationLayerProtocol(PacketParser.FiveTuple.TransportProtocol transport, ushort sourcePort, ushort destinationPort) {
            

            
            if (destinationPort == 53 || sourcePort == 53 || destinationPort == 5353 || sourcePort == 5353 || destinationPort == 5355 || sourcePort == 5355) {
                //DNS
                //Multicast DNS (UDP 5353) http://www.multicastdns.org/
                //LLMNR DNS (UDP 5355)
                return ApplicationLayerProtocol.Dns;
            }
            else if (destinationPort == 67 || destinationPort == 68 || sourcePort == 67 || sourcePort == 68) {
                return ApplicationLayerProtocol.Dhcp;
            }
            else if (destinationPort == 69 || sourcePort == 69) {
                return ApplicationLayerProtocol.Tftp;
            }
            else if (destinationPort == 137 || sourcePort == 137) {
                return ApplicationLayerProtocol.NetBiosNameService;
            }
            else if (destinationPort == 138 || sourcePort == 138) {
                return ApplicationLayerProtocol.NetBiosDatagramService;
            }
            else if (destinationPort == 514 || sourcePort == 514) {
                return ApplicationLayerProtocol.Syslog;
            }
            else if (destinationPort == 1900 || sourcePort == 1900) {
                return ApplicationLayerProtocol.Upnp;
            }
            else if (destinationPort == 4789 || sourcePort == 4789 || destinationPort == 8472 || sourcePort == 8472) {
                return ApplicationLayerProtocol.VXLAN;
            }
            else if (destinationPort == 5060 || sourcePort == 5060) {
                return ApplicationLayerProtocol.Sip;
            }
            else {
                return ApplicationLayerProtocol.Unknown;
            }
        }
    }
}
