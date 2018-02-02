using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {

    class Pop3PacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //enum Pop3States { HEJ, HOPP };

        private PopularityList<NetworkTcpSession, Pop3Packet.ClientCommand> pop3LastCommand;
        private PopularityList<NetworkTcpSession, NetworkCredential> pop3Credentials;
        private PopularityList<NetworkTcpSession, Utils.StreamReassembler> emailReassemblers;

        public Pop3PacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.pop3LastCommand = new PopularityList<NetworkTcpSession, Pop3Packet.ClientCommand>(100);
            this.pop3Credentials = new PopularityList<NetworkTcpSession, NetworkCredential>(100);
            this.emailReassemblers = new PopularityList<NetworkTcpSession, Utils.StreamReassembler>(100);
        }

        public ApplicationLayerProtocol HandledProtocol
        {
            get
            {
                return ApplicationLayerProtocol.Pop3;
            }
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

            //Frame originalFrame = null;
            //SortedList<int, Packets.AbstractPacket> sortedPacketList = new SortedList<int, AbstractPacket>();

            Packets.Pop3Packet pop3Packet = null;
            Packets.TcpPacket tcpPacket = null;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.TcpPacket))
                    tcpPacket = (Packets.TcpPacket)p;
                else if (p.GetType() == typeof(Packets.Pop3Packet))
                    pop3Packet = (Packets.Pop3Packet)p;
            }
            if(tcpPacket != null && tcpPacket.SourcePort == 110 && this.pop3LastCommand.ContainsKey(tcpSession) && this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.RETR && this.emailReassemblers.ContainsKey(tcpSession)) {
                return this.ExtractEmail(tcpSession, tcpPacket, tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount, tcpPacket.PayloadDataLength);
            }
            else if (pop3Packet != null && tcpPacket != null) {
                if (pop3Packet.PacketHeaderIsComplete) {

                    int bytesParsedAfterHeader = 0;

                    if (pop3Packet.FullRequestOrResponseLine != null && pop3Packet.FullRequestOrResponseLine.Length > 0) {
                        System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                        string command = pop3Packet.GetCommandOrResponse();
                        parms.Add(command, pop3Packet.GetCommandOrResponseArguments());

                        if (pop3Packet.ClientToServer) {
                            NetworkHost sourceHost, destinationHost;
                            if (transferIsClientToServer) {
                                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                            }
                            else {
                                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                            }

                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(pop3Packet.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, pop3Packet.ParentFrame.Timestamp, "POP3 Command"));
                            //See if there are additional lines after the command




                            if (Enum.IsDefined(typeof(Pop3Packet.ClientCommand), command.ToUpper())) {
                                Pop3Packet.ClientCommand clientCommand = (Pop3Packet.ClientCommand)Enum.Parse(typeof(Pop3Packet.ClientCommand), command.ToUpper());

                                //remove any old email reassemblers since we have now received a new command
                                if (this.emailReassemblers.ContainsKey(tcpSession)) {
                                    this.emailReassemblers[tcpSession].Close();
                                    this.emailReassemblers.Remove(tcpSession);//we will need to create a new reassembler
                                }

                                /**
                                 * https://tools.ietf.org/html/rfc1939
                                 * If an argument was given and the POP3 server issues a
                                 * positive response with a line containing information for
                                 * that message.
                                 * If no argument was given and the POP3 server issues a
                                 * positive response, then the response given is multi-line.
                                 **/

                                if (clientCommand == Pop3Packet.ClientCommand.LIST && pop3Packet.FullRequestOrResponseLine.Length > 5)
                                    clientCommand = Pop3Packet.ClientCommand.LIST_WITH_ARGS;
                                else if (clientCommand == Pop3Packet.ClientCommand.UIDL && pop3Packet.FullRequestOrResponseLine.Length > 5)
                                    clientCommand = Pop3Packet.ClientCommand.UIDL_WITH_ARGS;

                                if (clientCommand == Pop3Packet.ClientCommand.USER) {
                                    if (pop3Packet.GetCommandOrResponseArguments().Length > 0) {
                                        
                                        NetworkCredential credential = new NetworkCredential(sourceHost, destinationHost, "POP3", pop3Packet.GetCommandOrResponseArguments(), pop3Packet.ParentFrame.Timestamp);
                                        //this.pop3Credentials.Add(tcpSession, credential);
                                        this.updateCredential(credential, tcpSession);
                                    }
                                }
                                else if (clientCommand == Pop3Packet.ClientCommand.PASS) {
                                    if (this.pop3Credentials.ContainsKey(tcpSession)) {
                                        NetworkCredential credential = this.pop3Credentials[tcpSession];
                                        credential.Password = pop3Packet.GetCommandOrResponseArguments();
                                        //this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(credential));
                                        this.MainPacketHandler.AddCredential(credential);
                                    }
                                }
                                else if (clientCommand == Pop3Packet.ClientCommand.AUTH) {
                                    string authArgs = pop3Packet.GetCommandOrResponseArguments();
                                    if (authArgs.StartsWith("PLAIN", StringComparison.InvariantCultureIgnoreCase)) {
                                        clientCommand = Pop3Packet.ClientCommand.AUTH_PLAIN;

                                        if (authArgs.Trim().Length > 5) {
                                            //we have an in-line credential
                                            //AUTH PLAIN dGVzdAB0ZXN0AHRlc3RwYXNz
                                            //dGVzdAB0ZXN0AHRlc3RwYXNz  == "test\0test\0pass"
                                            string emailAndPassword = authArgs.Substring(5).TrimStart();
                                            this.extractBase64EncodedEmailAndPassword(emailAndPassword, pop3Packet.ParentFrame, tcpSession);
                                        }
                                    }
                                }
                                else if (clientCommand == Pop3Packet.ClientCommand.APOP) {
                                    //username is cleartext
                                    //password is MD5(nonce+password)

                                    /**
                                     * S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
                                     * C: APOP mrose c4c9334bac560ecc979e58001b3e22fb
                                     * S: +OK maildrop has 1 message (369 octets)
                                     **/
                                    string userAndHash = pop3Packet.GetCommandOrResponseArguments();
                                    userAndHash = userAndHash.Trim();
                                    int spaceIndex = userAndHash.IndexOf(' ');
                                    if (spaceIndex > 0 && spaceIndex < userAndHash.Length - 1) {
                                        string user = userAndHash.Substring(0, spaceIndex).Trim();
                                        string hash = userAndHash.Substring(spaceIndex).Trim();
                                        NetworkCredential cred = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "POP3", user, "APOP hash: " + hash, pop3Packet.ParentFrame.Timestamp);
                                        //MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                        MainPacketHandler.AddCredential(cred);
                                    }
                                }
                                else if (clientCommand == Pop3Packet.ClientCommand.RETR) {
                                    //clear all previous server-to-client data in case there is still some trailing data from the previous command that hasn't been parsed yet
                                    int bytesInStream = tcpSession.ServerToClientTcpDataStream.CountBytesToRead();
                                    if (bytesInStream > 0) {
                                        tcpSession.ServerToClientTcpDataStream.RemoveData(bytesInStream);
                                    }
                                }

                                if (this.pop3LastCommand.ContainsKey(tcpSession))
                                    this.pop3LastCommand[tcpSession] = clientCommand;
                                else
                                    this.pop3LastCommand.Add(tcpSession, clientCommand);
                            }
                            else {
                                //unknown command. We might be seing a multi-line command
                                //Check for last command
                                if (this.pop3LastCommand.ContainsKey(tcpSession)) {
                                    if (this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.AUTH_PLAIN) {
                                        /**
                                         * C: AUTH PLAIN
                                         * S: +
                                         * C: dGVzdAB0ZXN0AHRlc3Q=
                                         **/
                                        /**
                                         * Client: AUTH PLAIN
                                         * Server: + 
                                         * Client: bmFtZUBleGFtcGxlLmNvbU15UGFzc3dvcmQK
                                         * Server: +OK mailbox "name@example.com" has 30 messages (1115683 octets) H migmx127
                                         **/
                                        this.extractBase64EncodedEmailAndPassword(pop3Packet.FullRequestOrResponseLine, tcpPacket.ParentFrame, tcpSession);
                                        //TODO parsa ovanstående i en ny funktion
                                    }
                                }
                            }
                        }
                        else {

                            if (pop3Packet.GetCommandOrResponse() == Pop3Packet.RESPONSE_OK) {
                                if (this.pop3LastCommand.ContainsKey(tcpSession)) {
                                    //consume all multi-line responses here
                                    if (this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.LIST_WITH_ARGS) {
                                        foreach (string s in pop3Packet.ReadResponseLines()) {
                                            //do nothing... just make sure all lines are read
                                        }
                                    }
                                    else if (this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.RETR) {

                                        /*
                                        Utils.StreamReassembler reassembler;
                                        if (this.emailReassemblers.ContainsKey(tcpSession))
                                            reassembler = this.emailReassemblers[tcpSession];
                                        else
                                            reassembler = new Utils.StreamReassembler(Pop3Packet.MULTILINE_RESPONSE_TERMINATOR, 0);

                                        foreach (string line in pop3Packet.ReadResponseLines()) {
                                            reassembler.AddData(line);
                                            if (reassembler.TerminatorFound)
                                                break;
                                        }
                                        if(reassembler.TerminatorFound) {
                                            Mime.Email email = new Mime.Email(reassembler.DataStream, base.MainPacketHandler, tcpPacket, sourceHost, destinationHost, tcpSession, ApplicationLayerProtocol.Pop3);
                                        }
                                        */
                                        bytesParsedAfterHeader += this.ExtractEmail(tcpSession, tcpPacket, pop3Packet);

                                    }
                                    else if (this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.TOP) {
                                        foreach (string s in pop3Packet.ReadResponseLines()) {
                                            //do nothing... just make sure all lines are read
                                        }
                                    }
                                    if (this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.UIDL_WITH_ARGS) {
                                        foreach (string s in pop3Packet.ReadResponseLines()) {
                                            //do nothing... just make sure all lines are read
                                        }
                                    }
                                    else if (pop3Packet.ParsedBytesCount < pop3Packet.PacketEndIndex - pop3Packet.PacketStartIndex + 1) {
                                        foreach (string s in pop3Packet.ReadResponseLines()) {
                                            //do nothing... just make sure all lines are read
                                        }
                                    }


                                    //parse single line details from responses here

                                }
                                else if (pop3Packet.PacketHeaderIsComplete) {
                                    if (pop3Packet.GetCommandOrResponseArguments().Length > 0) {
                                        

                                        if (!tcpSession.Flow.FiveTuple.ServerHost.ExtraDetailsList.ContainsKey("POP3 Banner")) {
                                            tcpSession.Flow.FiveTuple.ServerHost.ExtraDetailsList.Add("POP3 Banner", pop3Packet.GetCommandOrResponseArguments());
                                        }
                                    }
                                }
                                if (pop3Packet.PacketHeaderIsComplete) {
                                    NetworkHost sourceHost, destinationHost;
                                    if (transferIsClientToServer) {
                                        sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                                        destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                                    }
                                    else {
                                        sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                                        destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                                    }
                                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(pop3Packet.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, pop3Packet.ParentFrame.Timestamp, "POP3 Response"));
                                }
                                    
                            }
                        }
                    }
                    return pop3Packet.ParsedBytesCount + bytesParsedAfterHeader;
                }
                
                else if(!pop3Packet.ClientToServer) {//invalid response received from Server
                    if (this.pop3LastCommand.ContainsKey(tcpSession) && this.pop3LastCommand[tcpSession] == Pop3Packet.ClientCommand.RETR) {
                        //reassemble a segment of an email here
                        return pop3Packet.ParsedBytesCount + this.ExtractEmail(tcpSession, tcpPacket, pop3Packet);
                    }
                    else if (pop3Packet.ParentFrame.Data[pop3Packet.PacketStartIndex] == '+') {
                        //special handling of responses like "+ " for AUTH PLAIN to indicate that more data is expected from the client
                        int index = pop3Packet.PacketStartIndex;
                        string line = Utils.ByteConverter.ReadLine(pop3Packet.ParentFrame.Data, ref index);
                        return index - pop3Packet.PacketStartIndex;
                    }
                    else return 0;
                }
                else
                    return 0;
            }
            else
                return 0;
        }

        private int ExtractEmail(NetworkTcpSession tcpSession, TcpPacket tcpPacket, Pop3Packet pop3Packet) {
            return this.ExtractEmail(tcpSession, tcpPacket, pop3Packet.PacketStartIndex + pop3Packet.ParsedBytesCount, pop3Packet.PacketEndIndex - pop3Packet.PacketStartIndex + 1 - pop3Packet.ParsedBytesCount);
        }

        private int ExtractEmail(NetworkTcpSession tcpSession, TcpPacket tcpPacket, int emailStartIndex, int length) {
            Utils.StreamReassembler reassembler;
            if (this.emailReassemblers.ContainsKey(tcpSession))
                reassembler = this.emailReassemblers[tcpSession];
            else {
                reassembler = new Utils.StreamReassembler(Pop3Packet.MULTILINE_RESPONSE_TERMINATOR, 2);//include the first 2 bytes of the terminator to get a CR-LF at the end of the extracted data
                this.emailReassemblers.Add(tcpSession, reassembler);
            }

            //add all data after the POP3 response header (after +OK or +ERR)
            int addedBytes = reassembler.AddData(tcpPacket.ParentFrame.Data, emailStartIndex, length);
            if (reassembler.TerminatorFound) {
                //I'm assuming the email is going from server to client
                Mime.Email email = new Mime.Email(reassembler.DataStream, base.MainPacketHandler, tcpPacket, false, tcpSession, ApplicationLayerProtocol.Pop3, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source);
                //remove the last command since we don't wanna reassemble any more for this RETR command
                if(this.pop3LastCommand.ContainsKey(tcpSession))
                    this.pop3LastCommand.Remove(tcpSession);
                this.emailReassemblers.Remove(tcpSession);
            }
            return addedBytes;
        }

        private IEnumerable<string> getDomainsAndParentDomains(IEnumerable<string> domains) {
            foreach (string domain in domains) {
                yield return domain;
                string parentDomain = domain;
                while(parentDomain.Split('.').Length > 2) {
                    parentDomain = parentDomain.Substring(parentDomain.IndexOf('.'));
                    yield return parentDomain;
                }
            }
        }

        
        private void extractBase64EncodedEmailAndPassword(string base64, Frame frame, NetworkTcpSession session) {
            NetworkCredential cred = SmtpPacketHandler.ExtractBase64EncodedAuthPlainCredential(base64, frame, session, ApplicationLayerProtocol.Pop3);
            if(cred != null) {
                //this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                this.MainPacketHandler.AddCredential(cred);
                this.updateCredential(cred, session);
                return;
            }

            /*
            //dGVzdAB0ZXN0AHRlc3RwYXNz  => user = test, password = password
            byte[] bytes = System.Convert.FromBase64String(base64);
            if (bytes.Length > 3 && Array.IndexOf<byte>(bytes, 0, 2) > 0) {
                int firstNullIndex = Array.IndexOf<byte>(bytes, 0);
                int secondNullIndex = Array.IndexOf<byte>(bytes, 0, firstNullIndex+1);
                if (firstNullIndex >= 0 && secondNullIndex > 0) {
                    string username = ASCIIEncoding.ASCII.GetString(bytes, firstNullIndex + 1, secondNullIndex - firstNullIndex - 1);
                    string password = ASCIIEncoding.ASCII.GetString(bytes, secondNullIndex + 1, bytes.Length - secondNullIndex - 1);
                    NetworkCredential cred = new NetworkCredential(session.ClientHost, session.ServerHost, "POP3", username, password, frame.Timestamp);
                    this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                    this.updateCredential(cred, session);
                    return;
                }
            }
            */


            /*
            //the following code is probably not needed since we should already have found the credential by now
            string emailAndPassword = System.Text.ASCIIEncoding.ASCII.GetString(bytes);
            //TODO figure out how to split the email and password!
            bool credentialFound = false;
            if (!credentialFound) {
                foreach (string hostname in this.getDomainsAndParentDomains(session.ServerHost.HostNameList)) {
                    if (hostname.Length > 0 && hostname.Contains(".") && emailAndPassword.ToLower().Contains(hostname.ToLower())) {
                        int passwordIndex = emailAndPassword.IndexOf(hostname, StringComparison.InvariantCultureIgnoreCase) + hostname.Length;
                        NetworkCredential cred = new NetworkCredential(session.ClientHost, session.ServerHost, "POP3", emailAndPassword.Substring(0, passwordIndex), emailAndPassword.Substring(passwordIndex), frame.Timestamp);
                        this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                        credentialFound = true;
                        this.updateCredential(cred, session);
                    }
                }
            }
            if(!credentialFound && emailAndPassword.Contains(".") && emailAndPassword.Contains("@")) {
                int atIndex = emailAndPassword.IndexOf('@');
                string[] top20TopDomains = { ".com", ".org", ".edu", ".gov", ".uk", ".net", ".ca", ".de", ".jp", ".fr", ".au", ".us", ".ru", ".ch", ".it", ".nl", ".se", ".no", ".es", ".mil" };
                foreach(string topDomain in top20TopDomains) {
                    if(emailAndPassword.IndexOf(topDomain, atIndex, StringComparison.InvariantCultureIgnoreCase) > 0) {
                        int passwordIndex = emailAndPassword.IndexOf(topDomain, atIndex, StringComparison.InvariantCultureIgnoreCase) + topDomain.Length;
                        NetworkCredential cred = new NetworkCredential(session.ClientHost, session.ServerHost, "POP3", emailAndPassword.Substring(0, passwordIndex), emailAndPassword.Substring(passwordIndex), frame.Timestamp);
                        this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                        credentialFound = true;
                        this.updateCredential(cred, session);
                    }

                }
                if(!credentialFound) {
                    //it might be some less popular domain name
                    int dotIndex = emailAndPassword.IndexOf('.', atIndex);
                    if(dotIndex > 0) {
                        int passwordIndex = dotIndex + 2;//just a guess, could be something else
                        if(passwordIndex < emailAndPassword.Length) {
                            NetworkCredential cred = new NetworkCredential(session.ClientHost, session.ServerHost, "POP3", emailAndPassword.Substring(0, passwordIndex), emailAndPassword.Substring(passwordIndex), frame.Timestamp);
                            this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                            credentialFound = true;
                            this.updateCredential(cred, session);
                        }
                    }
                }
            }
            if(!credentialFound && emailAndPassword.Length > 0) {
                NetworkCredential cred = new NetworkCredential(session.ClientHost, session.ServerHost, "POP3", emailAndPassword, emailAndPassword, frame.Timestamp);
                this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
            }
            */

        }

        private void updateCredential(NetworkCredential cred, NetworkTcpSession session) {
            if (this.pop3Credentials.ContainsKey(session)) {
                NetworkCredential oldCred = this.pop3Credentials[session];
                //check to see which credential is best
                if (oldCred.Username.Equals(cred.Username, StringComparison.InvariantCultureIgnoreCase)) {
                    if (oldCred.Password == null || oldCred.Password.Length <= 0)
                        oldCred.Password = cred.Password;
                }
                else if (cred.Username.Contains("@") && cred.Username.Contains(".") && !oldCred.Username.Contains("@") && !oldCred.Username.Contains(".")) {
                    this.pop3Credentials[session] = cred;
                }
            }
            else
                this.pop3Credentials.Add(session, cred);
        }

        public void Reset() {
            this.pop3Credentials.Clear();
            this.pop3LastCommand.Clear();
        }
    }
}
