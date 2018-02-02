using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class TabularDataStreamPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.TabularDataStream; }
        }

        public TabularDataStreamPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }

        #region ITcpSessionPacketHandler Members


        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            int returnValue=0;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.TabularDataStreamPacket))
                    returnValue=ExtractData(tcpSession, transferIsClientToServer, (Packets.TabularDataStreamPacket)p);
            }

            return returnValue;
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, Packets.TabularDataStreamPacket tdsPacket) {
            if(!tdsPacket.PacketHeaderIsComplete)
                return 0;

            if(tdsPacket.PacketType==(byte)Packets.TabularDataStreamPacket.PacketTypes.SqlQuery) {
                System.Collections.Specialized.NameValueCollection sqlParams=new System.Collections.Specialized.NameValueCollection();
                char[] splitters={';'};
                foreach(string s in tdsPacket.Query.Split(splitters)){
                    sqlParams.Add("SQL Query "+sqlParams.Count+1, s);
                }
                if (sqlParams.Count > 0) {
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tdsPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, sqlParams, tdsPacket.ParentFrame.Timestamp, ""));
                }
            }
            if(tdsPacket.PacketType==(byte)Packets.TabularDataStreamPacket.PacketTypes.Tds7Login) {
                NetworkCredential nc=null;

                if(tdsPacket.ClientHostname!=null && tdsPacket.ClientHostname.Length>0)
                    tcpSession.ClientHost.AddHostName(tdsPacket.ClientHostname);
                if(tdsPacket.Username!=null && tdsPacket.Username.Length>0)
                    nc=new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "TDS (SQL)", tdsPacket.Username, tdsPacket.ParentFrame.Timestamp);
                if(tdsPacket.Password!=null && tdsPacket.Password.Length>0 && nc!=null)
                    nc.Password=tdsPacket.Password;
                //skip appName
                if(tdsPacket.AppName!=null && tdsPacket.AppName.Length>0 && !tcpSession.ServerHost.ExtraDetailsList.ContainsKey("SQL AppName"))
                    tcpSession.ServerHost.ExtraDetailsList.Add("SQL AppName", tdsPacket.AppName);
                if(tdsPacket.ServerHostname!=null && tdsPacket.ServerHostname.Length>0)
                    tcpSession.ServerHost.AddHostName(tdsPacket.ServerHostname);
                if(tdsPacket.LibraryName!=null && tdsPacket.LibraryName.Length>0 && !tcpSession.ServerHost.ExtraDetailsList.ContainsKey("SQL Library"))
                    tcpSession.ServerHost.ExtraDetailsList.Add("SQL Library", tdsPacket.LibraryName);
                if(tdsPacket.DatabaseName!=null && tdsPacket.DatabaseName.Length>0 && !tcpSession.ServerHost.ExtraDetailsList.ContainsKey("SQL Database Name"))
                    tcpSession.ServerHost.ExtraDetailsList.Add("SQL Database Name", tdsPacket.DatabaseName);

                if(nc!=null)
                    base.MainPacketHandler.AddCredential(nc);
            }

            return tdsPacket.PacketLength;
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
            //do nothing... no state
        }

        #endregion
    }
}
