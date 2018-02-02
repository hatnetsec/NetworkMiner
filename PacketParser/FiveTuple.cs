using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser {

    //from CASE
    public class FiveTuple {
        public enum TransportProtocol : byte { TCP, UDP, SCTP, ICMP };

        private string clientServerString, serverClientString;
        //isActive(Boolean)
        //DateTime StartTime { get; }
        //DateTime EndTime { get; }
        public NetworkHost ClientHost { get; }
        public NetworkHost ServerHost { get; }
        public ushort ClientPort { get; }
        public ushort ServerPort { get; }
        public TransportProtocol Transport { get; }
        public System.Net.IPEndPoint ServerEndPoint { get; }


        //TODO: Make this constructor private and force all constructions to go through a Factory that ensures that all FiveTuple objects with the same value are the same object!
        public FiveTuple(NetworkHost clientHost, ushort clientPort, NetworkHost serverHost, ushort serverPort, TransportProtocol transport) {
            this.ClientHost = clientHost;
            this.ServerHost = serverHost;
            this.ClientPort = clientPort;
            this.ServerPort = serverPort;
            this.Transport = transport;
            this.clientServerString = null;//cached string for performance
            this.serverClientString = null;//cached string for performance
            this.ServerEndPoint = new System.Net.IPEndPoint(this.ServerHost.IPAddress, this.ServerPort);
        }

        public override string ToString() {
            //return this.ServerHost.ToString() + " " + Transport.ToString() + " " + this.ServerPort + " - "  + this.ClientHost.ToString() + " "+ this.Transport.ToString() +" " + this.ClientPort;
            return this.ToString(false);
        }

        public string ToString(bool printClientFirst) {
            if (printClientFirst) {
                if(this.clientServerString == null) {
                    StringBuilder sb = new StringBuilder();
                    sb.Append(this.ClientHost.ToString());
                    sb.Append(" ");
                    sb.Append(this.Transport.ToString());
                    sb.Append(" ");
                    sb.Append(this.ClientPort);
                    sb.Append(" - ");
                    sb.Append(this.ServerHost.ToString());
                    sb.Append(" ");
                    sb.Append(this.Transport.ToString());
                    sb.Append(" ");
                    sb.Append(this.ServerPort);
                    this.clientServerString = sb.ToString();
                }
                return this.clientServerString;
            }
            else {//print server first
                if (this.serverClientString == null) {
                    StringBuilder sb = new StringBuilder();
                    sb.Append(this.ServerHost.ToString());
                    sb.Append(" ");
                    sb.Append(this.Transport.ToString());
                    sb.Append(" ");
                    sb.Append(this.ServerPort);
                    sb.Append(" - ");
                    sb.Append(this.ClientHost.ToString());
                    sb.Append(" ");
                    sb.Append(this.Transport.ToString());
                    sb.Append(" ");
                    sb.Append(this.ClientPort);
                    this.serverClientString = sb.ToString();
                }
                return this.serverClientString;
            }
            
        }
    }
}
