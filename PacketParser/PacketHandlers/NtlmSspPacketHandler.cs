using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class NtlmSspPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        #region ITcpSessionPacketHandler Members

        private PopularityList<int, string> ntlmChallengeList;

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
            //or should I set it to Unknown?
        }

        public NtlmSspPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            this.ntlmChallengeList=new PopularityList<int, string>(20);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }
            //bool successfulExtraction=false;
            int successfullyExtractedBytes =0;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.NtlmSspPacket)) {
                    Packets.NtlmSspPacket ntlmPacket=(Packets.NtlmSspPacket)p;
                    if(ntlmPacket.NtlmChallenge!=null) {
                        if(ntlmChallengeList.ContainsKey(tcpSession.GetHashCode()))
                            ntlmChallengeList[tcpSession.GetHashCode()]=ntlmPacket.NtlmChallenge;
                        else
                            ntlmChallengeList.Add(tcpSession.GetHashCode(), ntlmPacket.NtlmChallenge);
                    }
                    if(ntlmPacket.DomainName!=null)
                        sourceHost.AddDomainName(ntlmPacket.DomainName);
                    if(ntlmPacket.HostName!=null)
                        sourceHost.AddHostName(ntlmPacket.HostName);
                    if(ntlmPacket.UserName!=null) {
                        sourceHost.AddNumberedExtraDetail("NTLM Username ", ntlmPacket.UserName);
                        /*
                        if(!sourceHost.ExtraDetailsList.ContainsKey("NTLM Username "+ntlmPacket.UserName))
                            sourceHost.ExtraDetailsList.Add("NTLM Username "+ntlmPacket.UserName, ntlmPacket.UserName);
                            */
                        string lanManagerHashInfo=null;
                        if(ntlmPacket.LanManagerResponse!=null)
                            lanManagerHashInfo="LAN Manager Response: "+ntlmPacket.LanManagerResponse;
                        if(ntlmPacket.NtlmResponse!=null) {
                            if(lanManagerHashInfo==null)
                                lanManagerHashInfo="";
                            else
                                lanManagerHashInfo=lanManagerHashInfo+" - ";
                            lanManagerHashInfo=lanManagerHashInfo+"NTLM Response: "+ntlmPacket.NtlmResponse;
                        }
                        if(lanManagerHashInfo==null)
                            base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.UserName, ntlmPacket.ParentFrame.Timestamp));
                        else {
                            if(ntlmChallengeList.ContainsKey(tcpSession.GetHashCode()))
                                lanManagerHashInfo="NTLM Challenge: "+ntlmChallengeList[tcpSession.GetHashCode()]+" - "+lanManagerHashInfo;
                            if (ntlmPacket.DomainName == null)
                                base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.UserName, lanManagerHashInfo, ntlmPacket.ParentFrame.Timestamp));
                            else
                                base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.DomainName +"\\"+ ntlmPacket.UserName, lanManagerHashInfo, ntlmPacket.ParentFrame.Timestamp));
                        }
                    }
                    successfullyExtractedBytes+=ntlmPacket.ParentFrame.Data.Length;//it's OK to return a larger value that what was parsed
                }
            }

            return successfullyExtractedBytes;
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
