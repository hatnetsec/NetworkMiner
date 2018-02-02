using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class ImapPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private PopularityList<NetworkTcpSession, ImapPacket.ClientCommand> lastCommand;
        private PopularityList<NetworkTcpSession, System.IO.MemoryStream> serverToClientEmailReassemblers, clientToServerEmailReassemblers;

        public ApplicationLayerProtocol HandledProtocol
        {
            get
            {
                return ApplicationLayerProtocol.Imap;
            }
        }

        public ImapPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.lastCommand = new PopularityList<NetworkTcpSession, ImapPacket.ClientCommand>(100);
            this.serverToClientEmailReassemblers = new PopularityList<NetworkTcpSession, System.IO.MemoryStream>(100);
            this.clientToServerEmailReassemblers = new PopularityList<NetworkTcpSession, System.IO.MemoryStream>(100);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            /*
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }*/
            Packets.ImapPacket imapPacket = null;
            Packets.TcpPacket tcpPacket = null;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.TcpPacket))
                    tcpPacket = (Packets.TcpPacket)p;
                else if (p.GetType() == typeof(Packets.ImapPacket))
                    imapPacket = (Packets.ImapPacket)p;
            }
            if (tcpPacket != null && (tcpPacket.SourcePort == 220 || tcpPacket.SourcePort == 143) && this.lastCommand.ContainsKey(tcpSession) && this.lastCommand[tcpSession] == ImapPacket.ClientCommand.UID && this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {
                return this.ExtractEmail(tcpSession, tcpPacket, tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount, tcpPacket.PayloadDataLength);
            }
            else if (tcpPacket != null && (tcpPacket.DestinationPort == 220 || tcpPacket.DestinationPort == 143) && this.lastCommand.ContainsKey(tcpSession) && this.lastCommand[tcpSession] == ImapPacket.ClientCommand.APPEND && this.clientToServerEmailReassemblers.ContainsKey(tcpSession)) {
                return this.ExtractEmail(tcpSession, tcpPacket, tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount, tcpPacket.PayloadDataLength);
            }
            else if (tcpPacket != null && imapPacket != null) {
                if (imapPacket.ClientToServer) {
                    if (imapPacket.Command != null) {
                        if (lastCommand.ContainsKey(tcpSession))
                            lastCommand[tcpSession] = imapPacket.Command.Value;
                        else
                            lastCommand.Add(tcpSession, imapPacket.Command.Value);

                        if (imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            parameters.Add(imapPacket.Command.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Client Command"));
                        }

                        //remove any old email reassemblers since we have now received a new command
                        if (this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {
                            this.serverToClientEmailReassemblers[tcpSession].Close();
                            this.serverToClientEmailReassemblers.Remove(tcpSession);//we will need to create a new reassembler
                        }

                        if (imapPacket.Command == ImapPacket.ClientCommand.APPEND) {
                            //an email is being uploaded to the server
                            if (imapPacket.BodyLength > 0) {
                                int emailBytes = this.ExtractEmail(tcpSession, tcpPacket, imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount, imapPacket.PacketLength - imapPacket.ParsedBytesCount, imapPacket.BodyLength, true);
                                imapPacket.ParsedBytesCount += emailBytes;
                            }
                        }
                        else if (imapPacket.Command == ImapPacket.ClientCommand.LOGIN) {
                            string[] args = imapPacket.FullRequestOrResponseLine.Split(new char[] { ' ' });
                            char[] quoteChars = new char[] { '\'', '"' };
                            //a001 LOGIN SMITH SESAME
                            if (args.Length > 3) {
                                string username = args[2].Trim(quoteChars);
                                string password = args[3].Trim(quoteChars);
                                NetworkCredential cred = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "IMAP", username, password, imapPacket.ParentFrame.Timestamp);
                                //base.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                base.MainPacketHandler.AddCredential(cred);
                            }
                        }
                    }
                    else if (lastCommand.ContainsKey(tcpSession) && lastCommand[tcpSession] == ImapPacket.ClientCommand.AUTHENTICATE) {
                        if (imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            string base64 = imapPacket.FullRequestOrResponseLine;
                            NetworkCredential cred = SmtpPacketHandler.ExtractBase64EncodedAuthPlainCredential(base64, imapPacket.ParentFrame, tcpSession, ApplicationLayerProtocol.Imap);
                            if (cred != null) {
                                //base.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                base.MainPacketHandler.AddCredential(cred);

                                if (imapPacket.ParsedBytesCount == 0)
                                    imapPacket.ParsedBytesCount = base64.Length + 2;//add CRLF
                            }
                        }
                    }

                }
                else {//server to client
                    if (imapPacket.Result != null && imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                        System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                        parameters.Add(imapPacket.Result.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Server Response"));
                    }

                    if (lastCommand.ContainsKey(tcpSession) && (lastCommand[tcpSession] == ImapPacket.ClientCommand.FETCH || lastCommand[tcpSession] == ImapPacket.ClientCommand.UID)) {
                        if (imapPacket.Command != null && imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            parameters.Add(imapPacket.Command.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Untagged Response"));
                        }
                        //the server might push an email here
                        if (imapPacket.BodyLength > 0) {
                            int emailBytes = this.ExtractEmail(tcpSession, tcpPacket, imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount, imapPacket.PacketLength - imapPacket.ParsedBytesCount, imapPacket.BodyLength, false);
                            if (imapPacket.ParenthesesDiff > 0 && imapPacket.ParsedBytesCount + emailBytes < imapPacket.PacketLength) {
                                //we might have a trailing line that closes the parenthesis, let's read that one too
                                int index = imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount + emailBytes;
                                string trailingLine = Utils.ByteConverter.ReadLine(imapPacket.ParentFrame.Data, ref index);
                                int trailingParenthesesDiff = trailingLine.Split('(').Length - trailingLine.Split(')').Length;
                                if (imapPacket.ParenthesesDiff + trailingParenthesesDiff == 0)
                                    return index - imapPacket.PacketStartIndex;
                                else
                                    return imapPacket.ParsedBytesCount + emailBytes;
                            }
                            else
                                return imapPacket.ParsedBytesCount + emailBytes;
                        }
                    }
                    else if (lastCommand.ContainsKey(tcpSession) && (lastCommand[tcpSession] == ImapPacket.ClientCommand.STARTTLS)) {
                        if (imapPacket.Result == ImapPacket.ServerResult.OK) {
                            //1 OK Begin TLS negotiation now
                            //do the same protocol switch trick as in SocksPacketHandler
                            //tcpSession.ProtocolFinder = new TcpPortProtocolFinder(tcpSession.ClientHost, tcpSession.ServerHost, tcpSession.ClientTcpPort, tcpSession.ServerTcpPort, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, base.MainPacketHandler);
                            tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Ssl, false);
                        }
                    }
                }
                return imapPacket.ParsedBytesCount;
            }
            else
                return 0;
        }

        public void Reset() {
            this.lastCommand.Clear();
            this.serverToClientEmailReassemblers.Clear();
        }

        private int ExtractEmail(NetworkTcpSession tcpSession, TcpPacket tcpPacket, int emailStartIndex, int length, int totalLength = 0, bool clientToServer = false) {
            System.IO.MemoryStream reassembler;
            if (this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {
                reassembler = this.serverToClientEmailReassemblers[tcpSession];
                clientToServer = false;
            }
            else if (this.clientToServerEmailReassemblers.ContainsKey(tcpSession)) {
                reassembler = this.clientToServerEmailReassemblers[tcpSession];
                clientToServer = true;
            }
            else if (totalLength > 0) {
                //reassembler = new Utils.StreamReassembler(Pop3Packet.MULTILINE_RESPONSE_TERMINATOR, 2);//include the first 2 bytes of the terminator to get a CR-LF at the end of the extracted data
                reassembler = new System.IO.MemoryStream(totalLength);
                if (clientToServer)
                    this.clientToServerEmailReassemblers.Add(tcpSession, reassembler);
                else
                    this.serverToClientEmailReassemblers.Add(tcpSession, reassembler);
            }
            else
                return 0;

            if (reassembler.Capacity < reassembler.Position + length)
                length = (int)(reassembler.Capacity - reassembler.Position);

            reassembler.Write(tcpPacket.ParentFrame.Data, emailStartIndex, length);
            if(reassembler.Position == reassembler.Capacity) {
                FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation assemblyLocation;
                if (clientToServer)
                    assemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination;
                else {
                    assemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source;
                    //remove the last command since we don't wanna reassemble any more for this command
                    if (this.lastCommand.ContainsKey(tcpSession))
                        this.lastCommand.Remove(tcpSession);
                }

                Mime.Email email = new Mime.Email(reassembler, base.MainPacketHandler, tcpPacket, clientToServer, tcpSession, ApplicationLayerProtocol.Imap, assemblyLocation);
                /*
                if (clientToServer) {
                    email = new Mime.Email(reassembler, base.MainPacketHandler, tcpPacket, tcpSession.ClientHost, tcpSession.ServerHost, tcpSession, ApplicationLayerProtocol.Imap, !clientToServer);
                    this.clientToServerEmailReassemblers.Remove(tcpSession);
                }
                else {
                    email = new Mime.Email(reassembler, base.MainPacketHandler, tcpPacket, tcpSession.ServerHost, tcpSession.ClientHost, tcpSession, ApplicationLayerProtocol.Imap, !clientToServer);
                    this.serverToClientEmailReassemblers.Remove(tcpSession);
                    //remove the last command since we don't wanna reassemble any more for this command
                    if (this.lastCommand.ContainsKey(tcpSession))
                        this.lastCommand.Remove(tcpSession);
                }
                */
                

            }
            return length;
        }
    }
}
