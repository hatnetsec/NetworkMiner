using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class ImapPacket : AbstractPacket, ISessionPacket {
        //https://tools.ietf.org/html/rfc3501 IMAP
        //https://www.ietf.org/rfc/rfc2342.txt IMAP4 NAMESPACE command
        //https://tools.ietf.org/html/rfc6237 IMAP4 ESEARCH command
        //https://www.ietf.org/rfc/rfc2971.txt IMAP ID extension
        //https://tools.ietf.org/html/rfc2177 IMAP4 IDLE command
        //https://tools.ietf.org/html/rfc4466 Collected Extensions to IMAP4 ABNF
        //https://tools.ietf.org/html/rfc2822 Size Message Attribute
        //https://tools.ietf.org/html/rfc5034 AUTH
        //https://tools.ietf.org/html/rfc2595 AUTH PLAIN
        //http://www.fehcom.de/qmail/smtpauth.html AUTH PLAIN
        //https://tools.ietf.org/html/rfc2088 LITERAL+ extension


        /**
         * Commands in the POP3 consist of a case-insensitive keyword, possibly
         * followed by one or more arguments.  All commands are terminated by a
         * CRLF pair.  Keywords and arguments consist of printable ASCII
         * characters.  Keywords and arguments are each separated by a single
         * SPACE character.  Keywords are three or four characters long. Each
         * argument may be up to 40 characters long.
         */

        /**
         * LOL, this was found in RFC 1939:
         *
         *  ------------------------------------------------------------- 
         *  
         *  Normally, each POP3 session starts with a USER/PASS
         *  exchange.  This results in a server/user-id specific
         *  password being sent in the clear on the network.  For
         *  intermittent use of POP3, this may not introduce a sizable
         *  risk.  However, many POP3 client implementations connect to
         *  the POP3 server on a regular basis -- to check for new
         *  mail.  Further the interval of session initiation may be on
         *  the order of five minutes.  Hence, the risk of password
         *  capture is greatly enhanced.
         *  
         *  -------------------------------------------------------------
         *  
         *  I guess the risk of password capture has swayed a great deal since 1996
         * 
         **/

        public enum ClientCommand {
            //Any State
            CAPABILITY,//Responses:  REQUIRED untagged response: CAPABILITY
            NOOP,
            LOGOUT,
            //Not Authenticated
            STARTTLS,
            AUTHENTICATE,
            LOGIN,
            //Authenticated State
            SELECT,
            EXAMINE,
            CREATE,
            DELETE,
            RENAME,
            SUBSCRIBE,
            UNSUBSCRIBE,
            LIST,
            LSUB,
            STATUS,
            APPEND,
            //Selected State
            CHECK,
            CLOSE,
            EXPUNGE,
            SEARCH,
            FETCH,
            STORE,
            COPY,
            UID,
            //Experimental
            //X//X<atom>
            //extensions
            NAMESPACE,//rfc2342
            ESEARCH,//rfc6237
            ID,//rfc2971
            IDLE,//rfc2177
            CHILDREN, ENABLE, MOVE, SORT, THREAD, UIDPLUS, UNSELECT, WITHIN, AUTH,
            ACL,
            BINARY,
            CATENATE,
            IMAP4,
            IMAP4rev1,
            METADATA,
            MULTIAPPEND,
            QUOTA,
            SCAN,
            SURGEMAIL


            //LIST-EXTENDED, LIST-STATUS, LITERAL+,  SASL-IR, SPECIAL-USE, THREAD=ORDEREDSUBJECT, AUTH=LOGIN, AUTH=PLAIN
            /**
             * AUTH=ANONYMOUS
             * AUTH=CRAM-MD5
             * AUTH=DIGEST-MD5
             * AUTH=GSSAPI
             * AUTH=LOGIN
             * AUTH=NTLM
             * AUTH=PLAIN
             * AUTH=SCRAM-MD5
             * LITERAL+
             * LOGIN-REFERRALS
             * MAILBOX-REFERRALS
             * THREAD=ORDEREDSUBJECT
             * THREAD=REFERENCES
             * X-MERCURY
             * X-NON-HIERARCHICAL-RENAME
             * X-VERSION
             **/
        }

        public enum ServerResult {
            OK,
            NO,
            BAD
        }

        public static readonly byte[] MULTILINE_RESPONSE_TERMINATOR = { 0x0d, 0x0a, 0x2e, 0x0d, 0x0a }; //CRLF.CRLF

        //Responses in the POP3 consist of a status indicator and a keyword possibly followed by additional information.
        //There are currently two status indicators: positive("+OK") and negative("-ERR").

        private bool clientToServer;
        private string fullRequestOrResponseLine;
        private int parsedBytesCount;
        //private List<string> responseLines = null;
        //private bool packetHeaderIsComplete;
        private ClientCommand? clientCommand = null;
        private ServerResult? serverResult = null;
        //private byte[] body;
        private int bodyLength;

        //An opened parenthesis gives +1, a closed gives -1
        private int parenthesesDiff = 0;

        public string FullRequestOrResponseLine { get { return this.fullRequestOrResponseLine; } }
        public bool ClientToServer { get { return this.clientToServer; } }

        public bool PacketHeaderIsComplete { get { return this.parsedBytesCount > 0; } }

        public int ParsedBytesCount
        {
            get
            {
                return this.parsedBytesCount;
            }
            set
            {
                this.parsedBytesCount = value;
            }
        }
        public ClientCommand? Command { get { return this.clientCommand; } }
        public ServerResult? Result { get { return this.serverResult; } }

        //public byte[] Body { get { return this.body; } }
        public int BodyLength { get { return this.bodyLength; } }

        /// <summary>
        /// An opened parenthesis gives +1, a closed gives -1
        /// </summary>
        public int ParenthesesDiff { get { return this.parenthesesDiff; } }

        internal ImapPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
        : base(parentFrame, packetStartIndex, packetEndIndex, "IMAP") {
            this.parsedBytesCount = 0;

            this.clientToServer = clientToServer;
            int index = PacketStartIndex;

            if (clientToServer) {
                //allow unix style line feeds (0x0a) from clients
                this.fullRequestOrResponseLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                this.parsedBytesCount = index - packetStartIndex;
                if (fullRequestOrResponseLine != null && this.fullRequestOrResponseLine.Contains(" ")) {
                    //skip tag
                    string command = this.fullRequestOrResponseLine.Split(new char[] { ' ' })[1];
                    if (Enum.IsDefined(typeof(ClientCommand), command.ToUpper())) {
                        this.clientCommand = (ClientCommand)Enum.Parse(typeof(ClientCommand), command, true);//allow lowercase
                        if(this.clientCommand == ClientCommand.APPEND) {
                            this.tryParseLiteral(this.fullRequestOrResponseLine, out this.bodyLength);
                        }
                    }

                }
            }
            else {
                this.fullRequestOrResponseLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                if (this.fullRequestOrResponseLine != null) {
                    if (this.fullRequestOrResponseLine.StartsWith("* ")) {
                        this.parsedBytesCount = index - packetStartIndex;
                        //TODO parse respose field to see if we have a FETCH response

                        /**
                         * * 1 FETCH (UID 1 RFC822.SIZE 26648 BODY[] {26648}
                         * Return-Path: <>
                         * Received: from mout-bounce.gmx.net ([212.227.17.26]) by mx-ha.gmx.net
                         * [...]
                         **/
                        string[] requestFields = this.fullRequestOrResponseLine.Split(new char[] { ' ' });
                        if (requestFields.Length > 2 && Enum.IsDefined(typeof(ClientCommand), requestFields[2])) {
                            this.clientCommand = (ClientCommand)Enum.Parse(typeof(ClientCommand), requestFields[2]);
                            if (this.clientCommand == ClientCommand.FETCH) {
                                //FETCH response
                                //int bodyLength;
                                if (this.tryParseLiteral(this.fullRequestOrResponseLine, out this.bodyLength)) {
                                    //int openingParenthesesCount = this.fullRequestOrResponseLine.Split('(').Length - 1;
                                    //int closingParenthesesCount = this.fullRequestOrResponseLine.Split(')').Length - 1;
                                    this.parenthesesDiff += this.fullRequestOrResponseLine.Split('(').Length - 1;
                                    this.parenthesesDiff -= this.fullRequestOrResponseLine.Split(')').Length - 1;

                                    /*
                                    if (index + bodyLength <= packetEndIndex + 1) {
                                        this.body = new byte[bodyLength];
                                        Array.Copy(parentFrame.Data, index, this.body, 0, bodyLength);
                                        index += bodyLength;
                                        if (openingParenthesesCount > closingParenthesesCount) {
                                            string trailinLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                                            if(trailinLine != null) {
                                                openingParenthesesCount += trailinLine.Split('(').Length - 1;
                                                closingParenthesesCount += trailinLine.Split(')').Length - 1;
                                            }
                                        }
                                        if (openingParenthesesCount == closingParenthesesCount)
                                            this.parsedBytesCount = index - packetStartIndex;
                                        else
                                            this.parsedBytesCount = 0;
                                    }
                                    else
                                        this.parsedBytesCount = 0;//wait untill we have the whole response? What if the email contains a big attachment?
                                        */
                                }

                            }
                        }
                    }
                    else if (this.fullRequestOrResponseLine.StartsWith("+ ")) {//command continuation request response
                        this.parsedBytesCount = index - packetStartIndex;
                    }
                    else {
                        //see if the response starts with a tag followed by a ServerResult
                        if (this.fullRequestOrResponseLine.Contains(" ")) {
                            string[] responseFields = this.fullRequestOrResponseLine.Split(new char[] { ' ' });
                            //skip tag
                            if (responseFields.Length > 1) {
                                if (Enum.IsDefined(typeof(ServerResult), responseFields[1])) {
                                    this.serverResult = (ServerResult)Enum.Parse(typeof(ServerResult), responseFields[1]);
                                    this.parsedBytesCount = index - packetStartIndex;
                                }
                            }
                        }
                        if (this.parsedBytesCount == 0) {
                            //Check if we are seing a trailing closing parenthesis after a FETCH response
                            if(this.fullRequestOrResponseLine.Contains(")")) {
                                this.parenthesesDiff += this.fullRequestOrResponseLine.Split('(').Length - 1;
                                this.parenthesesDiff -= this.fullRequestOrResponseLine.Split(')').Length - 1;
                                if(this.parenthesesDiff < 0) {
                                    //we have closed some parenthesis
                                    parsedBytesCount = index - PacketStartIndex;
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Parses a literal according to https://tools.ietf.org/html/rfc3501#section-9
        /// </summary>
        /// <param name="lineWithLiteralEnding">Something like "* 1 FETCH (UID 1 RFC822.SIZE 26648 BODY[] {26648}"</param>
        /// <param name="number">The parsed number</param>
        /// <returns>If the line ends with a proper literal</returns>
        private bool tryParseLiteral(string lineWithLiteralEnding, out int number) {
            
            //https://tools.ietf.org/html/rfc3501#section-9
            //literal         = "{" number "}" CRLF
            if (lineWithLiteralEnding != null && lineWithLiteralEnding.Length > 2 && lineWithLiteralEnding.Contains("{") && lineWithLiteralEnding.EndsWith("}")) {
                lineWithLiteralEnding = lineWithLiteralEnding.Substring(lineWithLiteralEnding.LastIndexOf('{'));

                //remove trailing '+' sign from non-synchronizing literals
                char[] trimChars = new char[] { '{', '+', '}' };
                lineWithLiteralEnding = lineWithLiteralEnding.Trim(trimChars);

                return Int32.TryParse(lineWithLiteralEnding, out number);
            }
            else {
                number = -1;
                return false;
            }
        }



        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            //yield break;
        }
    }
}
