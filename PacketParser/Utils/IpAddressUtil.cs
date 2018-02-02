using System;
using System.Collections.Generic;
using System.Text;

using System.Net;

namespace PacketParser.Utils {
    public static class IpAddressUtil {

        //http://www.iana.org/assignments/ipv4-address-space
        private static byte[] ipv4ReservedClassA = { 0, /*10,*/ 127, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255 };
        private static List<byte> ipv4ReservedClassAList = new List<byte>(ipv4ReservedClassA);

        public static bool IsIanaReserved(IPAddress ipAddress) {
            byte[] ip=ipAddress.GetAddressBytes();
            if(ip.Length==4)//let's start with IPv4
                return ipv4ReservedClassAList.Contains(ip[0]);
            else
                return false;//unknown (no IPv6 db yet...
        }
    }
}
