using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class RdpPacket {

        //http://www.jasonfilley.com/rdpcookies.html
        public class Cookie : AbstractPacket {

            private const string COOKIE_FIELD_HEADER = "Cookie: ";
            private string routingCookie;

            internal string RoutingCookie { get { return this.routingCookie; } }

            internal Cookie(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "RDP Cookie") {
                //The format of the user cookie is: Cookie:[space]mstshash =[ANSI string][0x0d0a]
                int index = packetStartIndex;
                string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                if (line.StartsWith(COOKIE_FIELD_HEADER))
                    this.routingCookie = line.Substring(COOKIE_FIELD_HEADER.Length);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }
    }
}
