using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://www.ietf.org/rfc/rfc3261.txt
    class SipPacket : AbstractPacket{

        private string messageLine=null;
        private string to=null;
        private string from=null;
        private string callId=null;
        private string contact=null;

        private string contentType=null;
        private int contentLength;

        internal string MessageLine { get { return this.messageLine; } }
        internal string To { get { return this.to; } }
        internal string From { get { return this.from; } }

        internal SipPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SIP") {
            //The first line of the text-encoded message contains the method name
            int index=PacketStartIndex;
            this.messageLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Message Line", messageLine);

            string headerLine="dummy value";
            System.Collections.Specialized.NameValueCollection headerCollection=new System.Collections.Specialized.NameValueCollection();
            while(index<PacketEndIndex && headerLine.Length>0) {
                headerLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                if(headerLine.Contains(":")) {
                    string headerName=headerLine.Substring(0, headerLine.IndexOf(':'));
                    string headerValue=headerLine.Substring(headerLine.IndexOf(':')+1).Trim();
                    if(headerName.Length>0 && headerValue.Length>0) {
                        headerCollection[headerName]=headerValue;

                        if(headerName=="To" || headerName=="t")
                            this.to=headerValue;
                        else if(headerName=="From" || headerName=="f")
                            this.from=headerValue;
                        else if(headerName=="Call-ID")
                            this.callId=headerValue;
                        else if(headerName=="Contact")
                            this.contact=headerValue;
                        else if(headerName=="Content-Type" || headerName=="c")
                            this.contentType=headerValue;
                        else if(headerName=="Content-Length" || headerName=="l")
                            Int32.TryParse(headerValue, out contentLength);
                    }
                }
            }
            base.Attributes.Add(headerCollection);
            

            //the rest is the message body
        
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            yield break;//no sub packets
        }
    }
}
