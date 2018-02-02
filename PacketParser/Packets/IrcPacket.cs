//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    //http://www.ietf.org/rfc/rfc1459.txt
    //http://www.irchelp.org/irchelp/rfc/

    public class IrcPacket : AbstractPacket, ISessionPacket{

        /**
         * <message>  ::= [':' <prefix> <SPACE> ] <command> <params> <crlf>
         * <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
         * <command>  ::= <letter> { <letter> } | <number> <number> <number>
         * <SPACE>    ::= ' ' { ' ' }
         * <params>   ::= <SPACE> [ ':' <trailing> | <middle> <params> ]
         * 
         * <middle>   ::= <Any *non-empty* sequence of octets not including SPACE
         * or NUL or CR or LF, the first of which may not be ':'>
         * <trailing> ::= <Any, possibly *empty*, sequence of octets not including
         * NUL or CR or LF>
         * 
         * <crlf>     ::= CR LF
         * */


        /**
         * IRC messages are always lines of characters terminated with a CR-LF
         * (Carriage Return - Line Feed) pair, and these messages shall not
         * exceed 512 characters in length, counting all characters including
         * the trailing CR-LF. Thus, there are 510 characters maximum allowed
         * for the command and its parameters.  There is no provision for
         * continuation message lines.
         **/
        private const int MAX_MESSAGE_LENGTH = 510;

        private enum ircChars : byte {
            Space = 0x20, //separator
            Colon = 0x3a, //prefix (used by servers to indicate the true origin of the message) [RFC 1459 states 0x3b, but should be 0x3a]
            Nul = 0x00,
            CR = 0x0d,
            LF = 0x0a
        }

        public class Message {
            private byte[] prefix; //<servername> | <nick> [ '!' <user> ] [ '@' <host> ]
            private byte[] command; //<letter> { <letter> } | <number> <number> <number>
            private ICollection<byte[]> parameters; //<middle> as well as <trailing>

            public string Prefix {
                get {
                    if(prefix == null)
                        return null;
                    else
                        return Utils.ByteConverter.ReadString(prefix);
                }
            }
            public string Command {
                get {
                    if(command == null)
                        return null;
                    else
                        return Utils.ByteConverter.ReadString(command);
                }
            }
            public IEnumerable<string> Parameters {
                get {
                    foreach(byte[] p in this.parameters)
                        yield return Utils.ByteConverter.ReadString(p);
                }
            }

            internal Message(byte[] prefix, byte[] command, ICollection<byte[]> parameters) {
                this.prefix = prefix;//prefix can be null
                this.command = command;
                this.parameters = parameters;
            }

            public override string  ToString() {
                StringBuilder returnString = new StringBuilder();
                if(this.prefix!=null && this.prefix.Length>0)
                    returnString.Append(":"+this.Prefix);
                returnString.Append(" "+this.Command);
                foreach(string p in this.Parameters)
                    returnString.Append(" "+p);
                return returnString.ToString();
            }
            
        }

        //IRC messages are always lines of characters terminated with a CR-LF pair (0x0d, 0x0a)
        //there are 510 characters maximum allowed for the command and its parameters
        private List<Message> messages;//CR-LF removed from each message
        private bool packetHeaderIsComplete;
        private int parsedBytesCount;
        
        public ICollection<Message> Messages { get { return this.messages; } }
        public bool PacketHeaderIsComplete {
            get { return this.packetHeaderIsComplete; }
        }

        public int ParsedBytesCount { get { return this.parsedBytesCount; } }
        

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            //do some checks to see if it is an IRC packet...
            //the first character should be ':', a number or a letter
            char firstChar=(char)parentFrame.Data[packetStartIndex];
            if(!Char.IsDigit(firstChar) && !Char.IsLetter(firstChar) && firstChar!=':')
                return false;
            //the RFC says that there should be CR-LF, but some implementations only use LF
            if(Array.IndexOf<byte>(parentFrame.Data, (byte)ircChars.LF, packetStartIndex)==-1)
                if(packetEndIndex - packetStartIndex > MAX_MESSAGE_LENGTH) //some implementations ignore line breaks for short messages
                    return false;//no LF
            //there should usually be one CR and it should be followed by a LF
            int crIndex=Array.IndexOf<byte>(parentFrame.Data, (byte)ircChars.CR, packetStartIndex);
            if(crIndex>=packetEndIndex || (crIndex!=-1 && parentFrame.Data[crIndex+1]!=(byte)ircChars.LF))
                if(packetEndIndex - packetStartIndex > MAX_MESSAGE_LENGTH) //some implementations ignore line breaks for short messages
                    return false;
            /*
            for(int i=packetStartIndex; i<=packetEndIndex; i++) {
                if(parentFrame.Data[i]==(byte)ircChars.CR) {
                    if(i<packetEndIndex && parentFrame.Data[i+1]==(byte)ircChars.LF)
                        containsLf=true;
                    break;
                }
                else if(parentFrame.Data[i]==(byte)ircChars.LF) {
                    containsLf=true;
                    break;
                }
            }
            if(!containsLf)
                return false;
            */

            try {
                result = new IrcPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result = null;
            }

            if(result == null)
                return false;
            else
                return true;
        }

        //use TryParse instead
        private IrcPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IRC") {
            this.parsedBytesCount = 0;
            this.packetHeaderIsComplete = false;
            this.messages = new List<Message>();
            //start creating messages
            int index=packetStartIndex;
            while(index < packetEndIndex) {
                //check for prefix
                byte[] prefix=null;
                if(parentFrame.Data[index] == (byte)ircChars.Colon) //':'
                    prefix = Utils.ByteConverter.ToByteArray(parentFrame.Data, ref index, (byte)ircChars.Space, false);
                //consume any additional spaces
                while(parentFrame.Data[index] == (byte)ircChars.Space)
                    index++;
                //get the command
                byte[] command = Utils.ByteConverter.ToByteArray(parentFrame.Data, ref index, (byte)ircChars.Space, false);
                while(parentFrame.Data[index] == (byte)ircChars.Space)
                    index++;
                //get all the parameters
                byte[] lineBreakers = { (byte)ircChars.CR, (byte)ircChars.LF };
                byte[] allParameterData = Utils.ByteConverter.ToByteArray(parentFrame.Data, ref index, lineBreakers, false);

                //the next char should be LF
                if(index<parentFrame.Data.Length) {
                    if(parentFrame.Data[index] == (byte)ircChars.LF)
                        index++;
                    this.packetHeaderIsComplete = true;
                    this.parsedBytesCount = index-packetStartIndex;
                }
                else if (this.parsedBytesCount>0) {
                    //do nothing, just break out of the loop
                    break;
                }
                /*
                else {
                    throw new Exception("Not a complete IRC packet");
                }*/

                //split the parameterData into separate parameters
                LinkedList<byte[]> parameters = new LinkedList<byte[]>();
                int pi=0;
                while(pi < allParameterData.Length) {
                    //see if we have <middle> or <trialing>
                    if(allParameterData[pi] == (byte)ircChars.Colon) {//we have a trailing
                        byte[] trailing = new byte[allParameterData.Length-pi-1];//dont include ':'
                        Array.Copy(allParameterData, pi+1, trailing, 0, trailing.Length);
                        parameters.AddLast(trailing);
                        pi=allParameterData.Length;
                    }
                    else { //middle
                        parameters.AddLast(Utils.ByteConverter.ToByteArray(allParameterData, ref pi, (byte)ircChars.Space, false));
                        while(pi < allParameterData.Length && allParameterData[pi] == (byte)ircChars.Space)
                            pi++;
                    }
                }
                messages.Add(new Message(prefix, command, parameters));
            }
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }



    }
}
