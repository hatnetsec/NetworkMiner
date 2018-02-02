using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class IrcPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //TODO: LÄGG TILL SESSIONSTRACKER OCH HÅLL KOLL PÅ INLOGGNINGAR MED USER OCH PASS

        private class IrcSession {
            private string nick = null;
            private string user = null;
            private string pass = null;

            internal string Nick { set { this.nick = value; } }
            internal string User { set { this.user = value; } }
            internal string Pass { set { this.pass = value; } }

            internal NetworkCredential GetCredential(NetworkHost sourceHost, NetworkHost destinationHost, DateTime timestamp) {
                string credentialUser="";
                if (this.nick != null)
                    credentialUser = this.nick;
                if (this.user != null)
                    credentialUser += "(IRC User: " + this.user + ")";
                string credentialPassword = "N/A";
                if (this.pass != null)
                    credentialPassword = this.pass;
                return new NetworkCredential(sourceHost, destinationHost, "IRC", credentialUser, credentialPassword, timestamp);
            }
        }

        private PopularityList<NetworkTcpSession, IrcSession> ircSessionList;

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Irc; }
        }

        public IrcPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
                this.ircSessionList = new PopularityList<NetworkTcpSession, IrcSession>(1000);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
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


            Packets.IrcPacket ircPacket = null;
            Packets.TcpPacket tcpPacket = null;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
                else if(p.GetType()==typeof(Packets.IrcPacket))
                    ircPacket=(Packets.IrcPacket)p;
            }
            if(ircPacket != null && tcpPacket != null) {
                System.Collections.Specialized.NameValueCollection tmpCol=new System.Collections.Specialized.NameValueCollection();
                foreach(Packets.IrcPacket.Message m in ircPacket.Messages) {
                    tmpCol.Add(m.Command, m.ToString());
                    if(m.Command.Equals("USER", StringComparison.InvariantCultureIgnoreCase)){
                        //the first parameter is the username
                        List<string> parameters=new List<string>();
                        foreach(string s in m.Parameters)
                            parameters.Add(s);
                        if (parameters.Count > 0) {
                            string ircUser = parameters[0];
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.User = ircUser;
                            //tcpSession.Flow.FiveTuple.ClientHost.AddNumberedExtraDetail("IRC Username", ircUser);
                            sourceHost.AddNumberedExtraDetail("IRC Username", ircUser);
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                        if(parameters.Count>1)
                            sourceHost.AddHostName(parameters[1]);
                        if(parameters.Count>2)
                            destinationHost.AddHostName(parameters[2]);
                    }
                    else if(m.Command.Equals("NICK", StringComparison.InvariantCultureIgnoreCase)) {
                        IEnumerator<string> enumerator=m.Parameters.GetEnumerator();
                        if (enumerator.MoveNext()) {//move to the first position
                            string ircNick = enumerator.Current;
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.Nick = ircNick;
                            sourceHost.AddNumberedExtraDetail("IRC Nick", ircNick);
                            //NetworkCredential ircNicCredential = new NetworkCredential(sourceHost, destinationHost, "IRC", enumerator.Current, "N/A (only IRC Nick)", ircPacket.ParentFrame.Timestamp);
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                    }
                    else if (m.Command.Equals("PASS", StringComparison.InvariantCultureIgnoreCase)) {
                        IEnumerator<string> enumerator = m.Parameters.GetEnumerator();
                        if (enumerator.MoveNext()) {//move to the first position
                            string ircPass = enumerator.Current;
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.Pass = ircPass;
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                    }
                    else if(m.Command.Equals("PRIVMSG", StringComparison.InvariantCultureIgnoreCase)) {
                        //first parameter is recipient, second is message
                        List<string> parameters=new List<string>();
                        foreach(string s in m.Parameters)
                            parameters.Add(s);
                        if(parameters.Count>=2) {
                            System.Collections.Specialized.NameValueCollection attributes=new System.Collections.Specialized.NameValueCollection();
                            attributes.Add("Command", m.Command);
                            string from="";
                            if(m.Prefix!=null && m.Prefix.Length>0) {
                                attributes.Add("Prefix", m.Prefix);
                                from=m.Prefix;
                            }
                            for(int i=0; i<parameters.Count; i++)
                                attributes.Add("Parameter "+(i+1), parameters[i]);
                            base.MainPacketHandler.OnMessageDetected(new PacketParser.Events.MessageEventArgs( ApplicationLayerProtocol.Irc, sourceHost, destinationHost, ircPacket.ParentFrame.FrameNumber, ircPacket.ParentFrame.Timestamp, from, parameters[0], parameters[1], parameters[1], attributes));
                        }
                    }
                }
                if(tmpCol.Count > 0) {
                    base.MainPacketHandler.OnParametersDetected(new PacketParser.Events.ParametersEventArgs(ircPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, tmpCol, tcpPacket.ParentFrame.Timestamp, "IRC packet"));
                    return ircPacket.ParsedBytesCount;
                }
            }
            return 0;
        }

        public void Reset() {
            this.ircSessionList.Clear();
        }

    }
}
