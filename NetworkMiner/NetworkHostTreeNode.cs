//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner {


    public class NetworkHostTreeNode : TreeNode, ToolInterfaces.IBeforeExpand{
        private PacketParser.NetworkHost networkHost;
        private ToolInterfaces.IIPLocator ipLocator;
        private ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator;
        
        

        public PacketParser.NetworkHost NetworkHost { get { return this.networkHost; } }

        internal NetworkHostTreeNode(PacketParser.NetworkHost networkHost, ToolInterfaces.IIPLocator ipLocator, ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator) {
            
            this.networkHost=networkHost;
            this.ipLocator=ipLocator;
            this.hostDetailsGenerator = hostDetailsGenerator;

            this.Text=networkHost.ToString();
            this.Nodes.Add("dummie node");

            if(networkHost.SentPackets.Count==0)
                this.ForeColor=System.Drawing.Color.Gray;
            
            if (this.networkHost.FaviconKey != null)
                this.ImageKey = this.networkHost.FaviconKey;
            else if (GetIpImageKey() != null)
                this.ImageKey = GetIpImageKey();
            else if (GetOsImageKey() != null)
                this.ImageKey = GetOsImageKey();
            else if (networkHost.SentPackets.Count > 0)
                this.ImageKey = "computer";
            else
                this.ImageKey = "white";

            this.SelectedImageKey=this.ImageKey;


            this.ToolTipText="Sent packets: "+networkHost.SentPackets.Count+"\nReceived packets: "+networkHost.ReceivedPackets;

        }

        /// <summary>
        /// Returns the correct imageKey (based on IP) if one exists, otherwise null
        /// </summary>
        /// <returns></returns>
        private string GetIpImageKey() {
            if(networkHost.IpIsReserved)
                return "iana";
            else if(networkHost.IpIsMulticast)
                return "multicast";
            else if(networkHost.IpIsBroadcast)
                return "broadcast";
            else
                return null;
        }
        private string GetOsImageKey() {
            return NetworkHostTreeNode.GetOsImageKey(networkHost);
        }

        public static string GetOsImageKey(PacketParser.NetworkHost networkHost) {
            if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Windows)
                return "windows";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Linux)
                return "linux";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.MacOS || networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Apple_iOS)
                return "apple";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.UNIX)
                return "unix";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.FreeBSD)
                return "freebsd";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.NetBSD)
                return "netbsd";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Solaris)
                return "solaris";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Cisco)
                return "cisco";
            else if (networkHost.OS == PacketParser.NetworkHost.OperatingSystemID.Android)
                return "android";
            else
                return null;
        }

        public void BeforeExpand() {
            this.Nodes.Clear();
            TreeNode ipNode=new TreeNode("IP: "+networkHost.IPAddress.ToString());

            if(networkHost.IpIsReserved)
                ipNode.Text+=" (IANA Reserved)";
            if(networkHost.IpIsMulticast)
                ipNode.Text+=" (Multicast)";
            if(networkHost.IpIsBroadcast)
                ipNode.Text+=" (Broadcast)";

            if(GetIpImageKey()!=null)
                ipNode.ImageKey=GetIpImageKey();
            ipNode.SelectedImageKey=ipNode.ImageKey;

            ipNode.Tag = networkHost.IPAddress.ToString();
 
            this.Nodes.Add(ipNode);

            if (networkHost.MacAddress != null) {

                //TreeNode nicNode = this.Nodes.Add("nic", "MAC: " + networkHost.MacAddress.ToString() + " (" + macVendor + ")", "nic", "nic");
                TreeNode nicNode = this.Nodes.Add("nic", "MAC: " + networkHost.MacAddress.ToString(), "nic", "nic");
                nicNode.Tag = networkHost.MacAddress.ToString();

                TreeNode nicVendorNode;
                string macVendor;
                if (PacketParser.Fingerprints.MacCollection.GetMacCollection(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)).TryGetMacVendor(networkHost.MacAddress, out macVendor)) {
                    nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + macVendor, "nic", "nic");
                    nicVendorNode.Tag = macVendor;
                }
                else {
                    nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + "Unknown", "nic", "nic");
                    nicVendorNode.Tag = "";
                }
                
                
            }
            else {
                TreeNode nicNode = this.Nodes.Add("nic", "MAC: Unknown", "nic", "nic");
                nicNode.Tag = "Unknown";
                TreeNode nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + "Unknown", "nic", "nic");
                nicVendorNode.Tag = "";
            }
            TreeNode hostnameNode = this.Nodes.Add("Hostname: "+networkHost.HostName);
            hostnameNode.Tag = networkHost.HostName;


            if(this.ipLocator!=null) {
                string countryString = ipLocator.GetCountry(networkHost.IPAddress);
                if (countryString != null && countryString.Length > 0) {
                    TreeNode geoIpNode = this.Nodes.Add("GeoIP", "GeoIP: " + countryString);
                    geoIpNode.Tag = countryString;
                    
                }

            }

            TreeNode osNode=this.Nodes.Add("OS", "OS: "+networkHost.OS.ToString(), GetOsImageKey(), GetOsImageKey());
            osNode.Tag = networkHost.OS.ToString();
            lock(networkHost.OsFingerprinters)
                foreach (PacketParser.Fingerprints.IOsFingerprinter fingerprinter in networkHost.OsFingerprinters) {
                    osNode.Nodes.Add(fingerprinter.Name, fingerprinter.Name+": "+networkHost.GetOsDetails(fingerprinter));
                }
            if (networkHost.Ttl > 0) {
                TreeNode ttlNode = this.Nodes.Add("TTL: " + networkHost.Ttl + " (distance: " + networkHost.TtlDistance + ")");
                ttlNode.Tag = networkHost.TtlDistance.ToString();
            }
            else {
                TreeNode ttlNode = this.Nodes.Add("TTL: Unknown");
                ttlNode.Tag = "Unknown";
            }

            this.Nodes.Add(new ServiceListTreeNode(networkHost));

            //add packets
            this.Nodes.Add(new SentReceivedTreeNode(networkHost, true));
            this.Nodes.Add(new SentReceivedTreeNode(networkHost, false));

            //add sessions
            this.Nodes.Add(new SessionListTreeNode(networkHost, true));
            this.Nodes.Add(new SessionListTreeNode(networkHost, false));

            //Details

            if (this.hostDetailsGenerator != null && !networkHost.ExtraDetailsList.ContainsKey(this.hostDetailsGenerator.GetDefaultKeyName())) {
                System.Collections.Specialized.NameValueCollection extraDetails = this.hostDetailsGenerator.GetExtraDetails(networkHost.IPAddress);
                
                for (int i = 0; i < extraDetails.Count; i++) {
                    lock(networkHost.ExtraDetailsList)
                        if(!networkHost.ExtraDetailsList.ContainsKey(extraDetails.Keys[i]))
                            networkHost.ExtraDetailsList.Add(extraDetails.Keys[i], extraDetails[i]);
                }
            }
            if(networkHost.HostDetailCollection.Count>0) {
                this.Nodes.Add(new HostDetailListTreeNode(networkHost.HostDetailCollection));
            }

        }

        internal class ServiceListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private PacketParser.NetworkHost host;

            internal ServiceListTreeNode(PacketParser.NetworkHost host) {
                this.host=host;
                {
                    StringBuilder sb=new StringBuilder("Open TCP Ports:");
                    foreach(uint port in host.OpenTcpPorts) {
                        sb.Append(" "+port);
                        if(host.NetworkServiceMetadataList.ContainsKey((ushort)port) && host.NetworkServiceMetadataList[(ushort)port].ApplicationLayerProtocol != PacketParser.ApplicationLayerProtocol.Unknown)
                            sb.Append(" ("+host.NetworkServiceMetadataList[(ushort)port].ApplicationLayerProtocol.ToString()+")");
                    }

                    this.Text=sb.ToString();
                    //this.Nodes.Add(sb.ToString());
                }
                if(host.NetworkServiceMetadataList.Count > 0) {
                    this.Nodes.Add("dummie node");//so that it can be expanded
                }
            }
            #region IBeforeExpand Members

            public void BeforeExpand() {
                this.Nodes.Clear();
                //List<NetworkSession> serviceList;
                //I want the services sorted by port, so I'll have to complicate things a bit
                //SortedList<string, TreeNode> sessionServerNodes=new SortedList<string, TreeNode>();
                lock (host.NetworkServiceMetadataList) {
                    foreach (PacketParser.NetworkServiceMetadata networkService in host.NetworkServiceMetadataList.Values) {
                        StringBuilder sb = new StringBuilder("TCP " + networkService.TcpPort);
                        if (networkService.ApplicationLayerProtocol != PacketParser.ApplicationLayerProtocol.Unknown)
                            sb.Append(" (" + networkService.ApplicationLayerProtocol.ToString() + ")");
                        sb.Append(" - " +
                            "Entropy (in \\ out): " + networkService.IncomingTraffic.CalculateEntropy().ToString("#.00") + " \\ " + networkService.OutgoingTraffic.CalculateEntropy().ToString("#.00") +//wildcard integers and 2 decimals?
                            " Typical data (in \\ out): " + networkService.IncomingTraffic.GetTypicalData() + " \\ " + networkService.OutgoingTraffic.GetTypicalData());
                        this.Nodes.Add(sb.ToString());
                    }
                }

            }

            #endregion
        }

        internal class SessionListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private PacketParser.NetworkHost host;
            private bool sessionsAreIncoming;
            internal SessionListTreeNode(PacketParser.NetworkHost host, bool sessionsAreIncoming) {
                this.host=host;
                this.sessionsAreIncoming=sessionsAreIncoming;
                if(sessionsAreIncoming){
                    int sessionCount=host.IncomingSessionList.Count;
                    this.Text="Incoming sessions: "+sessionCount;
                    if(sessionCount>0) {
                        this.Nodes.Add("dummie node");
                        this.ImageKey="incoming";
                    }
                }
                else{
                    int sessionCount=host.OutgoingSessionList.Count;
                    this.Text="Outgoing sessions: "+sessionCount;
                    if(sessionCount>0) {
                        this.Nodes.Add("dummie node");
                        this.ImageKey="outgoing";
                    }
                }
                this.SelectedImageKey=this.ImageKey;
            }

            public void BeforeExpand() {
                this.Nodes.Clear();
                List<PacketParser.NetworkTcpSession> sessionList;
                if(sessionsAreIncoming)//host is server
                    sessionList=host.IncomingSessionList;
                else
                    sessionList=host.OutgoingSessionList;
                //I want the session servers sorted by IP and port, so I'll have to complicate things a bit
                SortedList<string, TreeNode> sessionServerNodes=new SortedList<string, TreeNode>();
                lock (sessionList) {
                    foreach (PacketParser.NetworkTcpSession networkSession in sessionList) {
                        byte[] ipBytes = networkSession.ServerHost.IPAddress.GetAddressBytes();
                        string sessionServerKey = "";
                        foreach (byte b in ipBytes)
                            sessionServerKey += b.ToString("X2");
                        sessionServerKey += networkSession.ServerTcpPort.ToString("X2");
                        string sessionServerString = "Server: " + networkSession.ServerHost.ToString() + " TCP " + networkSession.ServerTcpPort;
                        if (!sessionServerNodes.ContainsKey(sessionServerKey))
                            sessionServerNodes.Add(sessionServerKey, new TreeNode(sessionServerString));
                        sessionServerNodes[sessionServerKey].Nodes.Add(networkSession.ToString());
                    }
                }
                foreach(TreeNode sessionServerNode in sessionServerNodes.Values)
                    this.Nodes.Add(sessionServerNode);
            }
        }

        internal class SentReceivedTreeNode : TreeNode/*, ToolInterfaces.IBeforeExpand*/ {
            private PacketParser.NetworkHost host;
            private bool hostIsSender;
            //private TreeNode treeNode;
            internal SentReceivedTreeNode(PacketParser.NetworkHost host, bool hostIsSender) {
                this.host=host;
                this.hostIsSender=hostIsSender;
                if(hostIsSender) {
                    this.Text="Sent: "+host.SentPackets.ToString();
                    this.ImageKey="sent";

                }
                else {//host is reciever
                    this.Text="Received: "+host.ReceivedPackets.ToString();
                    this.ImageKey="received";
                }
                this.SelectedImageKey=this.ImageKey;
            }

            /*
            [Obsolete("This function will be removed")]
            public void BeforeExpand() {
                //if(sourceHost.SentPackets.Count>0) {
                    this.Nodes.Clear();
                
                    if(hostIsSender) {
                        foreach(KeyValuePair<PacketParser.NetworkHost, PacketParser.NetworkPacketList> hostList in host.GetSentPacketListsPerDestinationHost()) {
                            this.Nodes.Add(new SubNetworkHostTreeNode(host, hostList.Key, hostList.Value));
                        }
                    }
                    else {
                        foreach(KeyValuePair<PacketParser.NetworkHost, PacketParser.NetworkPacketList> hostList in host.GetReceivedPacketListsPerSourceHost()) {
                            this.Nodes.Add(new SubNetworkHostTreeNode(hostList.Key, host, hostList.Value));
                        }
                    }
                //}
              */
        }


        /*
        /// <summary>
        /// Holds information regarding sub hosts that the host has communicated with
        /// </summary>
        internal class SubNetworkHostTreeNode : TreeNode {
                private PacketParser.NetworkHost sourceHost, destinationHost;
                private PacketParser.NetworkPacketList packetList;

                internal SubNetworkHostTreeNode(PacketParser.NetworkHost sourceHost, PacketParser.NetworkHost destinationHost, PacketParser.NetworkPacketList packetList) {
                    this.sourceHost=sourceHost;
                    this.destinationHost=destinationHost;
                    this.packetList=packetList;
                    this.Text=sourceHost.ToString()+" -> "+destinationHost.ToString()+" : "+packetList.ToString();
                    if(packetList.Count>0)
                        this.Nodes.Add("dummie node");//so that it can be expanded
                }

                [Obsolete("This function will be removed")]
                public void BeforeExpand() {
                    this.Nodes.Clear();
                    
                    ICollection<KeyValuePair<ushort[], PacketParser.NetworkPacketList>> tcpPortPairLists=packetList.GetSubsetPerTcpPortPair();
                    foreach(KeyValuePair<ushort[], PacketParser.NetworkPacketList> portPairList in tcpPortPairLists)
                        this.Nodes.Add("REMOVEME TCP: "+portPairList.Key[0]+" -> "+portPairList.Key[1]+" : "+portPairList.Value.ToString());

                    ICollection<KeyValuePair<ushort[], PacketParser.NetworkPacketList>> udpPortPairLists=packetList.GetSubsetPerUdpPortPair();
                    foreach(KeyValuePair<ushort[], PacketParser.NetworkPacketList> portPairList in udpPortPairLists)
                        this.Nodes.Add("REMOVEME UDP: "+portPairList.Key[0]+" -> "+portPairList.Key[1]+" : "+portPairList.Value.ToString());
                    
                }
            }


        }
        */

        internal class HostDetailListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private System.Collections.Specialized.NameValueCollection details;

            internal HostDetailListTreeNode(System.Collections.Specialized.NameValueCollection details) {
                this.details=details;
                this.Text="Host Details";
                this.ImageKey="details";
                this.Nodes.Add("dummie node");//so that it can be expanded
            }

            #region IBeforeExpand Members

            public void BeforeExpand() {
                this.Nodes.Clear();
                for(int i=0; i<details.Count; i++) {
                    TreeNode tn = this.Nodes.Add(details.Keys[i]+" : "+details[i]);
                    if (details.Keys[i].StartsWith("favicon")) {
                        tn.ImageKey = details[i];
                    }

                }
            }

            #endregion
        }
        

    }
}
