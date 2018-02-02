using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    public class SmtpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //used in both SMTP and POP3 for "AUTH PLAIN" and in IMAP for "authenticate plain"
        public static NetworkCredential ExtractBase64EncodedAuthPlainCredential(string base64, Frame frame, NetworkTcpSession session, ApplicationLayerProtocol protocol) {
            /**
             * https://tools.ietf.org/html/rfc2595
             * 
             * The client sends the authorization identity (identity to
             * login as), followed by a US-ASCII NUL character, followed by the
             * authentication identity (identity whose password will be used),
             * followed by a US-ASCII NUL character, followed by the clear-text
             * password.  The client may leave the authorization identity empty to
             * indicate that it is the same as the authentication identity.
             * 
             * Also, more details here: http://www.fehcom.de/qmail/smtpauth.html
             **/

            //dGVzdAB0ZXN0AHRlc3RwYXNz  => user = test, password = password
            byte[] bytes = System.Convert.FromBase64String(base64);
            if (bytes.Length > 3 && Array.IndexOf<byte>(bytes, 0, 2) > 0) {
                int firstNullIndex = Array.IndexOf<byte>(bytes, 0);
                int secondNullIndex = Array.IndexOf<byte>(bytes, 0, firstNullIndex + 1);
                if (firstNullIndex >= 0 && secondNullIndex > 0) {
                    string username = ASCIIEncoding.ASCII.GetString(bytes, firstNullIndex + 1, secondNullIndex - firstNullIndex - 1);
                    string password = ASCIIEncoding.ASCII.GetString(bytes, secondNullIndex + 1, bytes.Length - secondNullIndex - 1);
                    return new NetworkCredential(session.ClientHost, session.ServerHost, protocol.ToString(), username, password, frame.Timestamp);
                }
            }
            return null;
        }

        internal class SmtpSession : Utils.StreamReassembler {
            internal enum SmtpState { None, AuthLogin, Username, Password, Authenticated, Data, Footer, StartTlsRequested }

            private static readonly byte[] DATA_TERMINATOR = {0x0d, 0x0a, 0x2e, 0x0d, 0x0a}; //CRLF.CRLF

            

            private SmtpState state;
            private string username;
            private string password;
            private string mailFrom;
            private List<string> rcptTo;

            //private System.IO.MemoryStream dataStream; //to hold the DATA part of an email
            //private System.Text.ASCIIEncoding asciiEncoding;

            internal SmtpState State { get { return this.state; } set { this.state = value; } }
            internal string Username { get { return this.username; } set { this.username = value; } }
            internal string Password { get { return this.password; } set { this.password = value; } }
            internal string MailFrom { get { return this.mailFrom; } set { this.mailFrom=value; } }
            internal IEnumerable<string> RcptTo { get { return this.rcptTo; } }
            //internal System.IO.MemoryStream DataStream { get { return this.dataStream; } set { this.dataStream = value; }  }

            internal SmtpSession() : base(DATA_TERMINATOR, 2) {
                this.state = SmtpState.None;
                this.rcptTo = new List<string>();
                //this.dataStream = new System.IO.MemoryStream();
                //this.asciiEncoding = new System.Text.ASCIIEncoding();
            }

            internal void AddRecipient(string rcptTo) {
                this.rcptTo.Add(rcptTo);
            }

            /*
            internal void AddData(string dataString) {
                byte[] data = asciiEncoding.GetBytes(dataString);
                this.AddData(data, 0, data.Length);
            }
            */
            /*
            internal void AddData(byte[] buffer, int offset, int count) {
                List<byte> readBytes;
                
                long terminatorIndex = Utils.KnuthMorrisPratt.ReadTo(DATA_TERMINATOR, buffer, offset, out readBytes);
                //terminator might be split in between two packets
                if (terminatorIndex == -1 && this.dataStream.Length > 0) {
                    int oldBytesToRead = Math.Min(DATA_TERMINATOR.Length-1, (int)dataStream.Length);
                    byte[] oldBufferTail = new byte[oldBytesToRead];
                    this.dataStream.Seek(this.dataStream.Length - oldBytesToRead, System.IO.SeekOrigin.Begin);
                    int oldBytesRead = this.dataStream.Read(oldBufferTail, 0, oldBytesToRead);
                    byte[] tempBuffer = new byte[oldBytesRead + buffer.Length - offset];
                    Array.Copy(oldBufferTail, 0, tempBuffer, 0, oldBytesRead);
                    Array.Copy(buffer, offset, tempBuffer, oldBytesRead, buffer.Length - offset);
                    long tempTerminatorIndex = Utils.KnuthMorrisPratt.ReadTo(DATA_TERMINATOR, tempBuffer, 0, out readBytes);
                    if (tempTerminatorIndex >= 0) {
                        count = (int)tempTerminatorIndex - oldBytesRead + 2;
                        this.state = SmtpState.Footer;
                    }
                }
                else if(terminatorIndex >= 0) {
                    //terminator was found

                    //the final <cr><lf>.<cr><lf> will not included, but let's at least add one <cr><lf> at the end
                    count = (int)terminatorIndex-offset+2; //"+2" adds the <cr><lf>
                    //offset = 0;
                    this.state = SmtpState.Footer;
                }
                if (count > 0) {
                    this.dataStream.Seek(0, System.IO.SeekOrigin.End);
                    this.dataStream.Write(buffer, offset, count);
                }
            }*/

            internal new void AddData(byte[] buffer, int offset, int count) {
                base.AddData(buffer, offset, count);
                if (base.TerminatorFound)
                    this.state = SmtpState.Footer;
            }

        }

        private PopularityList<NetworkTcpSession, SmtpSession> smtpSessionList;

        public SmtpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.smtpSessionList=new PopularityList<NetworkTcpSession, SmtpSession>(100);//max 100 simultaneous SMTP sessions
        }

        

        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Smtp; }
        }


        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
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
            SmtpSession smtpSession;
            if(this.smtpSessionList.ContainsKey(tcpSession))
                smtpSession=this.smtpSessionList[tcpSession];
            else {
                smtpSession = new SmtpSession();
                this.smtpSessionList.Add(tcpSession, smtpSession);
            }

            Packets.TcpPacket tcpPacket=null;
            Packets.SmtpPacket smtpPacket=null;

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
                else if(p.GetType()==typeof(Packets.SmtpPacket))
                    smtpPacket=(Packets.SmtpPacket)p;
            }



            if(smtpPacket!=null) {
                if(smtpPacket.ClientToServer) {

                    if(smtpSession.State == SmtpSession.SmtpState.Username) {
                        string base64Username = smtpPacket.ReadLine().Trim();
                        
                        try {
                            byte[] usernameBytes = System.Convert.FromBase64String(base64Username);
                            smtpSession.Username = System.Text.ASCIIEncoding.ASCII.GetString(usernameBytes);
                        }
                        catch(FormatException e) { }
                    }
                    else if(smtpSession.State == SmtpSession.SmtpState.Password) {
                        string base64Password = smtpPacket.ReadLine().Trim();
                        try {
                            byte[] passwordBytes = System.Convert.FromBase64String(base64Password);
                            smtpSession.Password = System.Text.ASCIIEncoding.ASCII.GetString(passwordBytes);
                        }
                        catch(FormatException e) { }
                    }
                    else if(smtpSession.State == SmtpSession.SmtpState.Data) {
                        //write data to file until we receive "\n.\n" could also be \r\n.\r\n
                        smtpSession.AddData(smtpPacket.ParentFrame.Data, smtpPacket.PacketStartIndex, smtpPacket.PacketLength);
                        //check if state has transitioned over to footer
                        if (smtpSession.State == SmtpSession.SmtpState.Footer) {
                            Mime.Email email = new Mime.Email(smtpSession.DataStream, base.MainPacketHandler, tcpPacket, transferIsClientToServer, tcpSession, ApplicationLayerProtocol.Smtp, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination);
                           
                        }
                    }
                    else {
                        foreach(KeyValuePair<string, string> requestCommandAndArgument in smtpPacket.RequestCommandsAndArguments) {
                            if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.HELO.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                string clientDomain = requestCommandAndArgument.Value;
                            }
                            else if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.EHLO.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                string clientDomain = requestCommandAndArgument.Value;
                            }
                            else if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.AUTH.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                if (requestCommandAndArgument.Value.Trim().StartsWith("LOGIN", StringComparison.InvariantCultureIgnoreCase)) {
                                //if (requestCommandAndArgument.Value.ToUpper().Contains("LOGIN")) {
                                    smtpSession.State = SmtpSession.SmtpState.AuthLogin;
                                    //SMTP clients sometimes send the email address right away like this: "AUTH LOGIN aGVqaG9wcEBpbnRlcm5ldC5zZQ=="
                                    if(requestCommandAndArgument.Value.Length > "LOGIN ".Length) {
                                        try {
                                            string base64Username = requestCommandAndArgument.Value.Substring("LOGIN ".Length).Trim();
                                            byte[] usernameBytes = System.Convert.FromBase64String(base64Username);
                                            smtpSession.Username = System.Text.ASCIIEncoding.ASCII.GetString(usernameBytes);
                                        }
                                        catch (ArgumentException) { }
                                    }
                                }
                                else if (requestCommandAndArgument.Value.Trim().StartsWith("PLAIN", StringComparison.InvariantCultureIgnoreCase)) {
                                    //AUTH PLAIN <base64-encoded username and password>
                                    smtpSession.State = SmtpSession.SmtpState.AuthLogin;
                                    //SMTP clients sometimes send the email address right away like this: "AUTH LOGIN aGVqaG9wcEBpbnRlcm5ldC5zZQ=="
                                    if (requestCommandAndArgument.Value.Length > "PLAIN ".Length) {
                                        try {
                                            string base64 = requestCommandAndArgument.Value.Substring("PLAIN ".Length).Trim();
                                            NetworkCredential cred = SmtpPacketHandler.ExtractBase64EncodedAuthPlainCredential(base64, smtpPacket.ParentFrame, tcpSession, ApplicationLayerProtocol.Smtp);
                                            if (cred != null) {
                                                //this.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                                this.MainPacketHandler.AddCredential(cred);
                                            }
                                        }
                                        catch (ArgumentException) { }
                                    }
                                }
                            }
                            else if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.MAIL.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                if(requestCommandAndArgument.Value.StartsWith("FROM", StringComparison.InvariantCultureIgnoreCase)) {
                                    int colonIndex = requestCommandAndArgument.Value.IndexOf(':');
                                    if(colonIndex>0 && requestCommandAndArgument.Value.Length > colonIndex+1)
                                        smtpSession.MailFrom = requestCommandAndArgument.Value.Substring(colonIndex+1).Trim();
                                }
                            }
                            else if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.RCPT.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                if(requestCommandAndArgument.Value.StartsWith("TO", StringComparison.InvariantCultureIgnoreCase)) {
                                    int colonIndex = requestCommandAndArgument.Value.IndexOf(':');
                                    if(colonIndex>0 && requestCommandAndArgument.Value.Length > colonIndex+1)
                                        smtpSession.AddRecipient(requestCommandAndArgument.Value.Substring(colonIndex+1).Trim());
                                }
                            }
                            else if(requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.DATA.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                smtpSession.State = SmtpSession.SmtpState.Data;
                            }
                            else if (requestCommandAndArgument.Key.Equals(SmtpPacket.ClientCommands.STARTTLS.ToString(), StringComparison.InvariantCultureIgnoreCase)) {
                                smtpSession.State = SmtpSession.SmtpState.StartTlsRequested;
                            }

                        }
                    }
                   

                }
                else {//server to client
                    foreach(KeyValuePair<int, string> replyCodeAndArgument in smtpPacket.Replies) {
                        if(replyCodeAndArgument.Key == 334) { //AUTH LOGIN
                            if(replyCodeAndArgument.Value.Equals("VXNlcm5hbWU6"))
                                smtpSession.State = SmtpSession.SmtpState.Username;
                            else if(replyCodeAndArgument.Value.Equals("UGFzc3dvcmQ6"))
                                smtpSession.State = SmtpSession.SmtpState.Password;
                        }
                        else if(replyCodeAndArgument.Key == 235) { //AUTHENTICATION SUCCESSFUL 
                            base.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, smtpPacket.PacketTypeDescription, smtpSession.Username, smtpSession.Password, smtpPacket.ParentFrame.Timestamp));
                            smtpSession.State = SmtpSession.SmtpState.Authenticated;
                        }
                        else if(replyCodeAndArgument.Key >= 500) //error
                            smtpSession.State = SmtpSession.SmtpState.None;
                        else if(replyCodeAndArgument.Key == 354) //DATA "Start mail input; end with <CRLF>.<CRLF>"
                            smtpSession.State = SmtpSession.SmtpState.Data;
                        else if (replyCodeAndArgument.Key == 250) { //"Requested mail action okay, completed"
                            if (smtpSession.State == SmtpSession.SmtpState.Footer) {
                                //smtpSession.DataStream.Seek(0, System.IO.SeekOrigin.Begin);
                                smtpSession.DataStream = new System.IO.MemoryStream();
                                //System.Diagnostics.Debugger.Break();
                            }
                            smtpSession.State = SmtpSession.SmtpState.None;//Added in order to reset state when multiple SMTP sessions are sent within the same TCP session
                        }
                        else if(replyCodeAndArgument.Key == 220) {
                            if (smtpSession.State == SmtpSession.SmtpState.StartTlsRequested)
                                tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Ssl, false);
                        }
                    }
                }
                //There was a SMTP packet, so treat this as a sucsessfull extraction
                return tcpPacket.PayloadDataLength;
            }
            else //smtpPacket == null
                return 0;

        }

        /*
        public static string GetFileId(System.Collections.Specialized.NameValueCollection rootAttributes) {

            if (rootAttributes["Message-ID"] != null && rootAttributes["Message-ID"].Length > 0)
                return rootAttributes["Message-ID"];
            StringBuilder sb = new StringBuilder();
            if (rootAttributes["Subject"] != null)
                sb.Append(rootAttributes["Subject"]);
            if (rootAttributes["Date"] != null)
                sb.Append(rootAttributes["Date"]);
            return sb.ToString();
        }
        */

        public void Reset() {
            this.smtpSessionList.Clear();
        }

        #endregion
    }
}
