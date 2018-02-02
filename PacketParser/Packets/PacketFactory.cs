using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class PacketFactory {

        public static bool TryGetPacket(out Packets.AbstractPacket packet, PcapFileHandler.PcapFrame.DataLinkTypeEnum dataLinkType, Frame parentFrame, int startIndex, int endIndex) {
            return TryGetPacket(out packet, GetPacketType(dataLinkType), parentFrame, startIndex, endIndex);
        }

        public static System.Type GetPacketType(PcapFileHandler.PcapFrame.DataLinkTypeEnum dataLinkType) {

            Type packetType = typeof(Packets.Ethernet2Packet);//use Ethernet as default



            if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET)
                packetType = typeof(Packets.Ethernet2Packet);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11 || dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_AVS) {
                packetType = typeof(Packets.IEEE_802_11Packet);
            }
            //802.11 after a RadioTap header
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP) {
                packetType = typeof(Packets.IEEE_802_11RadiotapPacket);
            }
            //Or raw IP?
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP ||
                            dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_2 ||
                            dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_3 ||
                            dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP4) {
                packetType = typeof(Packets.IPv4Packet);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP6) {
                packetType = typeof(Packets.IPv6Packet);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_CHDLC) {
                packetType = typeof(Packets.CiscoHdlcPacket);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_SLL) {
                packetType = typeof(Packets.LinuxCookedCapture);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_PRISM_HEADER) {
                packetType = typeof(Packets.PrismCaptureHeaderPacket);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_PPI) {
                packetType = typeof(Packets.PpiPacket);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_PPP) {
                packetType = typeof(Packets.PointToPointPacket);
            }
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_NULL)
                packetType = typeof(Packets.NullLoopbackPacket);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ERF)
                packetType = typeof(Packets.ErfFrame);
            return packetType;
        }

        public static bool TryGetPacket(out Packets.AbstractPacket packet, System.Type packetType, Frame parentFrame, int startIndex, int endIndex) {
            packet = null;
            try {
                if (packetType.Equals(typeof(Packets.Ethernet2Packet)))
                    packet = new Packets.Ethernet2Packet(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.IPv4Packet)))
                    packet = new Packets.IPv4Packet(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.IPv6Packet)))
                    packet = new Packets.IPv6Packet(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.TcpPacket)))
                    packet = new Packets.TcpPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.IEEE_802_11Packet)))
                    packet = new Packets.IEEE_802_11Packet(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.IEEE_802_11RadiotapPacket)))
                    packet = new Packets.IEEE_802_11RadiotapPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.CiscoHdlcPacket)))
                    packet = new Packets.CiscoHdlcPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.LinuxCookedCapture)))
                    packet = new Packets.LinuxCookedCapture(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.PrismCaptureHeaderPacket)))
                    packet = new Packets.PrismCaptureHeaderPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.PpiPacket)))
                    packet = new Packets.PpiPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.PointToPointPacket)))
                    packet = new Packets.PointToPointPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.NullLoopbackPacket)))
                    packet = new Packets.NullLoopbackPacket(parentFrame, startIndex, endIndex);
                else if (packetType.Equals(typeof(Packets.ErfFrame)))
                    packet = new Packets.ErfFrame(parentFrame, startIndex, endIndex);

                if (packet == null)
                    return false;
                else
                    return true;
            }
            catch (Exception) {
                packet = new Packets.RawPacket(parentFrame, startIndex, endIndex);
                return false;
            }
        }

        public static AbstractPacket GetPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) {
            if(parentFrame.Data.Length<=packetEndIndex)
                return null;
            if(packetEndIndex<packetStartIndex)
                return null;

            return GetPacket(parentFrame, packetStartIndex, packetEndIndex, typeof(RawPacket));
        }
        /*public AbstractPacket GetPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, PacketConstructorDelegate constructor) {
            return constructor(parentFrame, packetStartIndex, packetEndIndex);
        }*/
        public static AbstractPacket GetPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, Type packetType) {
            if(packetType==typeof(RawPacket))
                return new RawPacket(parentFrame, packetStartIndex, packetEndIndex);
            else {
                //this is a slow solution which uses boxing and reflection...
                //so I prefer to create the objects as above instead!
                Type[] constructorParameterTypes={ typeof(Frame), typeof(int), typeof(int) };
                Object[] parameters={ (Object)parentFrame, (Object)packetStartIndex, (Object)packetEndIndex };
                return (AbstractPacket)packetType.GetConstructor(constructorParameterTypes).Invoke(parameters);
            }
        }
    
    
    }
}
