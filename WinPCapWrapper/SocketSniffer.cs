//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
//using System.Net;
using System.Net.Sockets;
using System.Net;

namespace NetworkWrapper{
    public class SocketSniffer : ISniffer{

        private Socket socket;
        private byte[] buffer;
        private bool snifferActive;
        private PacketReceivedEventArgs.PacketTypes basePacketType;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get { return basePacketType; } }

        public static event PacketReceivedHandler PacketReceived;

        public SocketSniffer(SocketAdapter adapter) {
            this.basePacketType=adapter.BasePacketType;

            this.snifferActive=false;
            buffer=new byte[65535];

            //this does not seem to work for IPv6 traffic.
            //Others seem to have similar problems: http://social.technet.microsoft.com/Forums/en-US/netfxnetcom/thread/95fba78d-aa40-44df-9575-dc98138455f3
            //I would like to do somthing like this:
            if(adapter.IP.AddressFamily==AddressFamily.InterNetworkV6) {
                socket=new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Raw);
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, true);
            }
            else
                socket=new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            IPEndPoint endPoint=new IPEndPoint(adapter.IP, 0);
            socket.Bind(endPoint);
            byte[] optionInValue={1,0,0,0};
            socket.IOControl(IOControlCode.ReceiveAll, optionInValue, null);
       }

        public void StartSniffing() {
            IAsyncResult sniffResult=socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(this.ReceivePacketListener), null);
            this.snifferActive=true;
            //result.
        
        }

        public void StopSniffing() {
            //socket.EndReceive(null);
            this.snifferActive=false;

        }

        //destructor
        ~SocketSniffer() {
            if(socket!=null)
                socket.Close();
        }

        private void ReceivePacketListener(IAsyncResult result) {
            //try {
                int received = socket.EndReceive(result);
                try {
                    byte[] data = new byte[received];
                    Array.Copy(buffer, 0, data, 0, received);
                    /*
                    //ensure that the IP type is correct
                    if(this.basePacketType==PacketReceivedEventArgs.PacketTypes.IPv4Packet) {
                        if(data!=null && data.Length>0 && (data[0]>>4)==0x06)
                            this.basePacketType= PacketReceivedEventArgs.PacketTypes.IPv6Packet;
                    }
                    else if(this.basePacketType== PacketReceivedEventArgs.PacketTypes.IPv6Packet) {
                        if(data!=null && data.Length>0 && (data[0]>>4)==0x04)
                            this.basePacketType= PacketReceivedEventArgs.PacketTypes.IPv4Packet;
                    }
                     * */
                    PacketReceivedEventArgs eventArgs=new PacketReceivedEventArgs(data, DateTime.Now, this.BasePacketType);
                    PacketReceived(this, eventArgs);

                    //OnNewPacket(new Packet(packet));
                }
                catch { } // invalid packet; ignore
            if(this.snifferActive)
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(this.ReceivePacketListener), null);
           // }
            //catch {
                //Stop();
            //}
        }
    }
}
