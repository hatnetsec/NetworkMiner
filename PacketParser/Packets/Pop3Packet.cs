using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class Pop3Packet : AbstractPacket, ISessionPacket {
        //https://tools.ietf.org/html/rfc1939
        //https://tools.ietf.org/html/rfc2449
        //https://tools.ietf.org/html/rfc5034 AUTH
        //http://www.fehcom.de/qmail/smtpauth.html AUTH PLAIN


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
            APOP,
            DELE,
            LIST,
            LIST_WITH_ARGS,
            NOOP,
            PASS,
            QUIT,
            RETR,
            RSET,
            STAT,
            TOP,
            UIDL,
            UIDL_WITH_ARGS,
            USER,
            CAPA,//rfc2449
            AUTH,//rfc2449
            AUTH_PLAIN//rfc5034
        }

        public static readonly byte[] MULTILINE_RESPONSE_TERMINATOR = { 0x0d, 0x0a, 0x2e, 0x0d, 0x0a }; //CRLF.CRLF

        //Responses in the POP3 consist of a status indicator and a keyword possibly followed by additional information.
        //There are currently two status indicators: positive("+OK") and negative("-ERR").

        public const string RESPONSE_OK = "+OK";
        public const string RESPONSE_ERR = "-ERR";

        private bool clientToServer;
        private string fullRequestOrResponseLine;
        private int parsedBytesCount;
        //private List<string> responseLines = null;
        //private bool packetHeaderIsComplete;

        public string FullRequestOrResponseLine { get { return this.fullRequestOrResponseLine; } }
        public bool ClientToServer { get { return this.clientToServer; } }

        public bool PacketHeaderIsComplete { get { return this.parsedBytesCount > 0; } }

        public int ParsedBytesCount
        {
            get
            {
                return this.parsedBytesCount;
            }
        }

        internal Pop3Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
        : base(parentFrame, packetStartIndex, packetEndIndex, "POP3") {
            this.parsedBytesCount = 0;

            this.clientToServer = clientToServer;
            int index = PacketStartIndex;

            if (clientToServer) {
                //allow unix style line feeds (0x0a) from clients
                this.fullRequestOrResponseLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                this.parsedBytesCount = index - packetStartIndex;
            }
            else {
                /**
                 * https://tools.ietf.org/html/rfc1939
                 * 
                 * Responses to certain commands are multi-line.  In these cases, which
                 * are clearly indicated below, after sending the first line of the
                 * response and a CRLF, any additional lines are sent, each terminated
                 * by a CRLF pair.  When all lines of the response have been sent, a
                 * final line is sent, consisting of a termination octet (decimal code
                 * 046, ".") and a CRLF pair.  If any line of the multi-line response
                 * begins with the termination octet, the line is "byte-stuffed" by
                 * pre-pending the termination octet to that line of the response.
                 * Hence a multi-line response is terminated with the five octets
                 * "CRLF.CRLF".  When examining a multi-line response, the client checks
                 * to see if the line begins with the termination octet.  If so and if
                 * octets other than CRLF follow, the first octet of the line (the
                 * termination octet) is stripped away.  If so and if CRLF immediately
                 * follows the termination character, then the response from the POP
                 * server is ended and the line containing ".CRLF" is not considered
                 * part of the multi-line response.
                 */
                this.fullRequestOrResponseLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                if(this.fullRequestOrResponseLine != null && this.fullRequestOrResponseLine.StartsWith(RESPONSE_ERR) || this.fullRequestOrResponseLine.StartsWith(RESPONSE_OK)) {
                    this.parsedBytesCount = index - packetStartIndex;
                }
                /*
                if (this.requestOrResponseCommand.StartsWith(RESPONSE_OK) && index < packetEndIndex) {
                    //we have a multi-line response
                    this.responseLines = new List<string>();
                    string line = this.readResponseData(parentFrame.Data, ref index);
                    while (line != null && line != ".") {
                        
                        line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                    }
                }*/
            }
            

        }

        public string GetCommandOrResponse() {
            int splitIndex = this.FullRequestOrResponseLine.IndexOf(' ');
            if (splitIndex > 0)
                return this.FullRequestOrResponseLine.Substring(0, splitIndex).Trim();
            else
                return this.fullRequestOrResponseLine;
        }

        public string GetCommandOrResponseArguments() {
            int splitIndex = this.FullRequestOrResponseLine.IndexOf(' ');
            if (splitIndex > 0)
                return this.FullRequestOrResponseLine.Substring(splitIndex).Trim();
            else
                return "";
        }

        public IEnumerable<string> ReadResponseLines() {
            int index = this.PacketStartIndex + this.parsedBytesCount;

            //this.packetHeaderIsComplete = false;
            string line = Utils.ByteConverter.ReadLine(this.ParentFrame.Data, ref index);//this command requires CR-LF endings
            while (line != null && line != ".") {
                if (line.StartsWith("."))
                    line = line.Substring(1);
                yield return line;
                line = Utils.ByteConverter.ReadLine(this.ParentFrame.Data, ref index);
            }
            //this.packetHeaderIsComplete = );
            if (line == ".")
                this.parsedBytesCount = index - this.PacketStartIndex;
            else
                this.parsedBytesCount = 0;
        }

        /*
        private string readResponseData(byte[] data, ref int index) {
            string line = Utils.ByteConverter.ReadLine(data, ref index);
            if (line != null && line.Length > 0 && line != ".")
                this.responseLines.Add(line);
            return line;
        }
        */

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            //yield break;
        }
    }
}
