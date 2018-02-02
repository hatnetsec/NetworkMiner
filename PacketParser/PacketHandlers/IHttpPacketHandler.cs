using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    public interface IHttpPacketHandler {

        /// <summary>
        /// 
        /// </summary>
        /// <param name="httpPacket"></param>
        /// <param name="tcpPacket"></param>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="mainPacketHandler"></param>
        /// <returns>True if the data was successfully parsed. False if the data need to be parsed again with more data</returns>
        bool ExtractHttpData(Packets.HttpPacket httpPacket, Packets.TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, PacketHandler mainPacketHandler);
        void Reset();//resets all captured data
    }
}
