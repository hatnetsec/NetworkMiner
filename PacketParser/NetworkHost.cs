//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;
using System.Xml;
using System.Xml.Schema;

using System.ComponentModel;

namespace PacketParser {
    public class NetworkHost : IComparable, System.Xml.Serialization.IXmlSerializable {
        
        public enum OperatingSystemID { Windows, Linux, UNIX, FreeBSD, NetBSD, Solaris, MacOS, Apple_iOS, Cisco, Android, BlackBerry, PlayStation, Nintendo, Other, Unknown }

        #region Comparators for extended sorting
        public class MacAddressComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                string xMac="";
                if(x.MacAddress!=null)
                    xMac=x.MacAddress.ToString();
                string yMac="";
                if(y.MacAddress!=null)
                    yMac=y.MacAddress.ToString();

                return String.Compare(xMac, yMac);
            }
        }
        public class HostNameComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return String.Compare(x.HostName, y.HostName);
            }
        }
        public class SentPacketsComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return y.SentPackets.Count-x.SentPackets.Count;
            }
        }
        public class ReceivedPacketsComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return y.ReceivedPackets.Count-x.ReceivedPackets.Count;
            }
        }
        public class SentBytesComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return (int)(y.SentPackets.TotalBytes-x.SentPackets.TotalBytes);
            }
        }
        public class ReceivedBytesComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return (int)(y.ReceivedPackets.TotalBytes-x.ReceivedPackets.TotalBytes);
            }
        }
        public class OpenTcpPortsCountComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return y.OpenTcpPorts.Length-x.OpenTcpPorts.Length;
            }
        }
        public class OperatingSystemComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return String.Compare(x.OS.ToString(), y.OS.ToString());
            }
        }
        public class TimeToLiveDistanceComparer : System.Collections.Generic.IComparer<NetworkHost> {

            public int Compare(NetworkHost x, NetworkHost y) {
                //make sure large senders are sorted first
                return x.TtlDistance-y.TtlDistance;
            }
        }
        #endregion

        #region Basic Private Data
        private IPAddress ipAddress;
        private PhysicalAddress macAddress;//the MAC address the host is behind
        //private string macAddressVendor;
        private PopularityList<string, PhysicalAddress> recentMacAdresses;
        private System.Collections.Generic.List<string> hostNameList;//DNS, NetBIOS, HTTP-GET-host-value or similar
        

        private System.Collections.Generic.List<ushort> openTcpPortList;//I shouldn't really need this since the networkServiceList has almost the same information
        

        private System.Collections.Generic.SortedList<byte, int> ttlCount;//TTL values from host packets
        private System.Collections.Generic.SortedList<byte, int> ttlDistanceCount;//the guessed distance to the host

        //private System.Collections.Generic.SortedList<string, System.Collections.Generic.SortedList<string, double>> operatingSystemCounterList;
        private SortedList<Fingerprints.IOsFingerprinter, SortedList<string, double>> fingerprinterOsCounterList;
        private KeyValuePair<double, string> fingerprintedDeviceCategory;
        private KeyValuePair<double, string> fingerprintedDeviceFamily;

        private NetworkPacketList sentPackets, receivedPackets;

        private List<NetworkTcpSession> incomingSessionList, outgoingSessionList;
        private SortedList<ushort, NetworkServiceMetadata> networkServiceMetadataList;//the key is identified by the TCP port number of the service (on the server)
        private List<ushort> vlanIdList;

        #endregion

        #region Extra (detailed) Private Data
        private List<IPAddress> queriedIpList;
        private List<string> domainNameList;
        private List<string> queriedNetBiosNameList;
        private List<string> queriedDnsNameList;
        private List<string> httpUserAgentBannerList;
        private List<string> httpServerBannerList;
        private List<string> ftpServerBannerList;
        private List<string> dhcpVendorCodeList;
        private SortedList<string, string> universalPlugAndPlayFieldList;

        private List<string> acceptedSmbDialectsList;
        private string preferredSmbDialect;

        private SortedList<string, string> extraDetailsList;//a simple list to store extra details about the host

        #endregion

        public IEnumerable<string> HostNames { get { return this.hostNameList; } }

        public PhysicalAddress MacAddress { 
            get { return this.macAddress; }
            set {
                this.macAddress=value;

                //PacketParser.Fingerprints.MacCollection.GetMacCollection("").TryGetMacVendor(this.macAddress, out this.macAddressVendor);
                if (value != null)
                    lock(this.recentMacAdresses)
                        this.recentMacAdresses.Add(value.ToString(), value);
            }
        }
        //public string MacVendor { get { return this.macAddressVendor; } }

        public IPAddress IPAddress { get { return this.ipAddress; } }
        //public string IPAddressString { get { return this.ipAddress.ToString(); } }
        public string HostName {
            get {
                StringBuilder sb = new StringBuilder("");
                lock (this.hostNameList) {
                    foreach (string hostname in this.hostNameList)
                        sb.Append(hostname + ", ");
                }
                //remove the last ", "
                if(sb.Length>=2)
                    sb.Remove(sb.Length-2, 2);
                return sb.ToString();
            }
        }
        
        [Browsable(false)]
        public ushort[] OpenTcpPorts {
            get {
                lock(this.openTcpPortList)
                    return openTcpPortList.ToArray();
            }
        }
        [Browsable(false)]
        public NetworkPacketList SentPackets { get { return sentPackets; } }
        [Browsable(false)]
        public NetworkPacketList ReceivedPackets { get { return receivedPackets; } }
        [Browsable(false)]
        public List<NetworkTcpSession> IncomingSessionList { get { return incomingSessionList; } }
        [Browsable(false)]
        public List<NetworkTcpSession> OutgoingSessionList { get { return outgoingSessionList; } }
        [Browsable(false)]
        public SortedList<ushort, NetworkServiceMetadata> NetworkServiceMetadataList { get { return networkServiceMetadataList; } }
        [Browsable(false)]
        public SortedList<string, string> UniversalPlugAndPlayFieldList { get { return this.universalPlugAndPlayFieldList; } set { this.universalPlugAndPlayFieldList=value; } }

        //public string FaviconKey = null;
        [Browsable(false)]
        public string FaviconKey { get; set; }

        [Browsable(false)]
        public System.Collections.Concurrent.ConcurrentDictionary<string, string> FaviconPerHost { get; }


        [Browsable(false)]
        public System.Collections.Specialized.NameValueCollection HostDetailCollection { 
            get{
                
                System.Collections.Specialized.NameValueCollection details=new System.Collections.Specialized.NameValueCollection();
                lock (this.vlanIdList) {
                    if (this.vlanIdList.Count > 0) {
                        foreach (ushort vlan in this.vlanIdList)
                            details.Add("VLAN", vlan.ToString());
                    }
                }
                if(this.FaviconPerHost.Count > 1) {
                    foreach (var icon in this.FaviconPerHost)
                        details.Add("favicon " + icon.Key, icon.Value);
                }
                else if (this.FaviconKey != null) {
                    details.Add("favicon", this.FaviconKey);
                }
                lock (this.queriedIpList) {
                    if (this.queriedIpList.Count > 0) {
                        StringBuilder queriedIPs = new StringBuilder();
                        foreach (IPAddress ip in this.queriedIpList) {
                            details.Add("Queried IP Addresses", ip.ToString());
                        }
                    }
                }
                if(this.queriedNetBiosNameList.Count>0) {
                    StringBuilder queriedNames=new StringBuilder();
                    lock (this.queriedNetBiosNameList) {
                        foreach (string name in this.queriedNetBiosNameList) {
                            details.Add("Queried NetBIOS names", name);
                        }
                    }
                }
                if(this.queriedDnsNameList.Count>0) {
                    StringBuilder queriedNames=new StringBuilder();
                    lock (this.queriedDnsNameList) {
                        foreach (string name in this.queriedDnsNameList) {
                            details.Add("Queried DNS names", name);
                        }
                    }
                }
                lock (this.domainNameList) {
                    for (int i = 0; i < this.domainNameList.Count; i++)
                        details.Add("Domain Name " + (i + 1), domainNameList[i]);
                }
                lock(this.httpUserAgentBannerList)
                    for(int i=0; i<this.httpUserAgentBannerList.Count; i++)
                        details.Add("Web Browser User-Agent "+(i+1), httpUserAgentBannerList[i]);
                lock (this.httpServerBannerList)
                    for (int i = 0; i < this.httpServerBannerList.Count; i++)
                        details.Add("Web Server Banner " + (i + 1), httpServerBannerList[i]);
                lock(this.ftpServerBannerList)
                    for(int i=0; i<this.ftpServerBannerList.Count; i++)
                        details.Add("FTP Server Banner "+(i+1), ftpServerBannerList[i]);
                lock(this.dhcpVendorCodeList)
                    for(int i=0; i<this.dhcpVendorCodeList.Count; i++)
                        details.Add("DHCP Vendor Code "+(i+1), dhcpVendorCodeList[i]);
                if (this.universalPlugAndPlayFieldList != null)
                    lock (this.universalPlugAndPlayFieldList) {
                        foreach (string field in this.universalPlugAndPlayFieldList.Values) {
                            if (field.Contains(":")) {
                                details.Add("UPnP field : " + field.Substring(0, field.LastIndexOf(':')), field.Substring(field.LastIndexOf(':') + 1));
                            }
                            else
                                details.Add("UPnP field", field);
                    }
                }
                if (this.acceptedSmbDialectsList != null)
                    lock (this.acceptedSmbDialectsList) {
                        foreach (string dialectName in this.acceptedSmbDialectsList)
                            details.Add("Accepted SMB dialects", dialectName);
                    }
                if(this.preferredSmbDialect!=null)
                    details.Add("Preferred SMB dialect", this.preferredSmbDialect);

                if (this.DeviceFamily.Length > 0)
                    details.Add("Device Family", this.DeviceFamily);
                if (this.DeviceCategory.Length > 0)
                    details.Add("Device Category", this.DeviceCategory);

                lock(this.extraDetailsList)
                    foreach(KeyValuePair<string, string> keyValue in extraDetailsList) {
                        details.Add(keyValue.Key, keyValue.Value);
                }
                return details;
                
            }
        }

        [Browsable(false)]
        public bool IpIsMulticast {
            get{
                byte[] ip=this.ipAddress.GetAddressBytes();
                if(ip.Length==4){//let's start with IPv4
                    //http://en.wikipedia.org/wiki/Multicast_address
                    if(ip[0]>=224 && ip[0]<=239)
                        return true;
                }
                return false;
            }
        }
        [Browsable(false)]
        public bool IpIsBroadcast {//this one isn't 100% correct, since we don't know the subnet mask
            get {
                if(this.sentPackets.Count==0) {
                    byte[] ip=this.ipAddress.GetAddressBytes();
                    //let's assume we need a subnet mask of 6 bits or more
                    byte mask=0x3f;
                    if((ip[ip.Length-1]&mask)==mask)
                        return true;
                }
                return false;
            }
        }
        [Browsable(false)]
        public bool IpIsReserved {//IANA Reserved IP
            get {
                return Utils.IpAddressUtil.IsIanaReserved(this.ipAddress);
            }
        }
        
        public string DeviceCategory {
            get {
                if (this.fingerprintedDeviceCategory.Value == null)
                    return "";
                else
                    return this.fingerprintedDeviceCategory.Value;
            }
        }
        public string DeviceFamily {
            get {
                if (this.fingerprintedDeviceFamily.Value == null)
                    return "";
                else
                    return this.fingerprintedDeviceFamily.Value;
            }
        }

        public OperatingSystemID OS {//there is something called System.PlatformID, but it isn't good enough
            get{

                System.Collections.Generic.Dictionary<OperatingSystemID, double> totalOsCount=new Dictionary<OperatingSystemID,double>();

                lock (this.fingerprinterOsCounterList) {
                    foreach (Fingerprints.IOsFingerprinter fingerprinter in this.fingerprinterOsCounterList.Keys) {
                        SortedList<string, double> operatingSystemCount = this.fingerprinterOsCounterList[fingerprinter];
                        System.Collections.Generic.Dictionary<OperatingSystemID, double> fingerprinterOsCount = new Dictionary<OperatingSystemID, double>();


                        //foreach(System.Collections.Generic.SortedList<string, double> operatingSystemCount in operatingSystemCounterList.Values) {
                        //foreach (System.Collections.Generic.SortedList<string, double> operatingSystemCount in this.fingerprinterOsCounterList.Values) {
                        foreach (string os in operatingSystemCount.Keys) {
                            if (os.ToLower().Contains("windows")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Windows))
                                    fingerprinterOsCount.Add(OperatingSystemID.Windows, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Windows] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("linux")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Linux))
                                    fingerprinterOsCount.Add(OperatingSystemID.Linux, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Linux] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("unix")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.UNIX))
                                    fingerprinterOsCount.Add(OperatingSystemID.UNIX, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.UNIX] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("freebsd") || os.ToLower().Contains("free bsd")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.FreeBSD))
                                    fingerprinterOsCount.Add(OperatingSystemID.FreeBSD, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.FreeBSD] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("netbsd") || os.ToLower().Contains("net bsd")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.NetBSD))
                                    fingerprinterOsCount.Add(OperatingSystemID.NetBSD, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.NetBSD] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("solaris")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Solaris))
                                    fingerprinterOsCount.Add(OperatingSystemID.Solaris, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Solaris] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("macos") || os.ToLower().Contains("mac os") || os.Contains("OSX") || os.Contains("OS X")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.MacOS))
                                    fingerprinterOsCount.Add(OperatingSystemID.MacOS, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.MacOS] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("apple") || os.Contains("iOS")) {//Case sensitive "iOS" to avoid confusion with Cisco IOS
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Apple_iOS))
                                    fingerprinterOsCount.Add(OperatingSystemID.Apple_iOS, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Apple_iOS] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("cisco") || os.Contains("IOS")) {//Case sensitive "IOS" to avoid confusion with Apple iOS
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Cisco))
                                    fingerprinterOsCount.Add(OperatingSystemID.Cisco, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Cisco] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("android")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Android))
                                    fingerprinterOsCount.Add(OperatingSystemID.Android, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Android] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("blackberry")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.BlackBerry))
                                    fingerprinterOsCount.Add(OperatingSystemID.BlackBerry, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.BlackBerry] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("nintendo")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Nintendo))
                                    fingerprinterOsCount.Add(OperatingSystemID.Nintendo, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Nintendo] += operatingSystemCount[os];
                            }
                            else if (os.ToLower().Contains("playstation")) {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.PlayStation))
                                    fingerprinterOsCount.Add(OperatingSystemID.PlayStation, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.PlayStation] += operatingSystemCount[os];
                            }
                            else {
                                if (!fingerprinterOsCount.ContainsKey(OperatingSystemID.Other))
                                    fingerprinterOsCount.Add(OperatingSystemID.Other, operatingSystemCount[os]);
                                else
                                    fingerprinterOsCount[OperatingSystemID.Other] += operatingSystemCount[os];
                            }
                        }

                        //done with this particular fingerprinter
                        double totalCount = 0.0;
                        foreach (double count in fingerprinterOsCount.Values)
                            totalCount += count;
                        if (totalCount > 0.0) {
                            foreach (KeyValuePair<OperatingSystemID, double> kvp in fingerprinterOsCount) {
                                if (totalOsCount.ContainsKey(kvp.Key))
                                    totalOsCount[kvp.Key] += fingerprinter.Confidence * kvp.Value / totalCount;
                                else
                                    totalOsCount.Add(kvp.Key, fingerprinter.Confidence * kvp.Value / totalCount);
                            }
                        }
                    }
                }
                //we now have counted all the OS's and want to get the one with best count
                OperatingSystemID probableOS=OperatingSystemID.Unknown;
                double bestOsCount=0.0;
                foreach (OperatingSystemID os in totalOsCount.Keys)
                    if (totalOsCount[os] > bestOsCount) {
                        probableOS=os;
                        bestOsCount = totalOsCount[os];
                    }
                return probableOS;
            }
        }

        //public IList<string> OsCounterNames {
        public IList<Fingerprints.IOsFingerprinter> OsFingerprinters {
            get {
                return this.fingerprinterOsCounterList.Keys;
                /*

                List<string> names = new List<string>();
                foreach (Fingerprints.IOsFingerprinter f in this.fingerprinterOsCounterList.Keys)
                    names.Add(f.Name);
                return names;
                 * */
                //return this.operatingSystemCounterList.Keys;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="osCounterName">for example "p0f" or "Ettercap"</param>
        /// <returns></returns>
        //public string GetOsDetails(string osCounterName) {
        public string GetOsDetails(Fingerprints.IOsFingerprinter fingerprinter) {
            //SortedList<string, double> operatingSystemCount=operatingSystemCounterList[osCounterName];
            lock (fingerprinterOsCounterList) {
                SortedList<string, double> operatingSystemCount = this.fingerprinterOsCounterList[fingerprinter];

                if (operatingSystemCount.Count == 0)
                    return "";
                else {
                    StringBuilder osString = new StringBuilder("");
                    double totalOsCount = 0.0;

                    foreach (string os in operatingSystemCount.Keys) {
                        totalOsCount += operatingSystemCount[os];
                    }
                    if (totalOsCount == 0)//just an extra check to avoid zero division
                        return "";
                    else {
                        string[] osNames = new string[operatingSystemCount.Count];
                        double[] percentages = new double[operatingSystemCount.Count];

                        operatingSystemCount.Keys.CopyTo(osNames, 0);
                        operatingSystemCount.Values.CopyTo(percentages, 0);

                        Array.Sort<double, string>(percentages, osNames);
                        for (int i = osNames.Length - 1; i >= 0; i--) {
                            osString.Append(osNames[i] + " (" + ((double)(percentages[i] / totalOsCount)).ToString("p") + ") ");
                        }

                        /*
                        foreach(string os in operatingSystemCount.Keys)
                            osString.Append(os+" ("+((double)(operatingSystemCount[os]/totalOsCount)).ToString("p")+") ");
                         * */
                        return osString.ToString();
                    }
                }
            }
        }
        public byte Ttl {
            get {
                lock (this.ttlCount) {
                    if (ttlCount.Count == 0)
                        return byte.MinValue;
                    else {
                        int bestTtlCount = 0;
                        byte bestTtl = 0x00;
                        foreach (byte ttl in ttlCount.Keys) {
                            int count = ttlCount[ttl];
                            if (count > bestTtlCount) {
                                bestTtl = ttl;
                                bestTtlCount = count;
                            }
                        }
                        return bestTtl;
                    }
                }
            }
        }
        public byte TtlDistance {
            get {
                lock (this.ttlDistanceCount) {
                    if (ttlDistanceCount.Count == 0)
                        return byte.MaxValue;
                    else {
                        int bestTtlDistanceCount = 0;
                        byte bestTtlDistance = 0x00;
                        foreach (byte ttlDistance in ttlDistanceCount.Keys) {
                            int count = ttlDistanceCount[ttlDistance];
                            if (count >= bestTtlDistanceCount) {//if several are of equal value, I wan the largest TTL Distance
                                bestTtlDistance = ttlDistance;
                                bestTtlDistanceCount = count;
                            }
                        }
                        return bestTtlDistance;
                    }
                }
            }
        }
        [Browsable(false)]
        public List<string> AcceptedSmbDialectsList { get { return this.acceptedSmbDialectsList; } set { this.acceptedSmbDialectsList=value; } }
        [Browsable(false)]
        public string PreferredSmbDialect { get { return this.preferredSmbDialect; } set { this.preferredSmbDialect=value; } }
        [Browsable(false)]
        public SortedList<string, string> ExtraDetailsList { get { return this.extraDetailsList; } }

        private NetworkHost() { throw new NotImplementedException(); }//for serialization purposes

        public NetworkHost(IPAddress ipAddress) {
            this.ipAddress=ipAddress;
            this.macAddress=null;
            this.recentMacAdresses = new PopularityList<string, PhysicalAddress>(255);
            this.ttlCount=new SortedList<byte, int>();
            this.ttlDistanceCount=new SortedList<byte, int>();
            //this.operatingSystemCounterList=new SortedList<string, SortedList<string, double>>();
            this.fingerprinterOsCounterList = new SortedList<Fingerprints.IOsFingerprinter, SortedList<string, double>>();
            this.fingerprintedDeviceCategory = new KeyValuePair<double, string>(0.0, "");
            this.fingerprintedDeviceFamily = new KeyValuePair<double,string>(0.0, "");
            this.hostNameList=new List<string>();
            this.domainNameList=new List<string>();
            this.openTcpPortList=new List<ushort>();
            this.networkServiceMetadataList=new SortedList<ushort, NetworkServiceMetadata>();
            this.vlanIdList = new List<ushort>();

            this.sentPackets=new NetworkPacketList();
            this.receivedPackets=new NetworkPacketList();
            this.incomingSessionList=new List<NetworkTcpSession>();
            this.outgoingSessionList=new List<NetworkTcpSession>();
            this.queriedIpList=new List<IPAddress>();
            this.queriedNetBiosNameList=new List<string>();
            this.queriedDnsNameList=new List<string>();
            this.httpUserAgentBannerList=new List<string>();
            this.httpServerBannerList=new List<string>();
            this.ftpServerBannerList=new List<string>();
            this.dhcpVendorCodeList=new List<string>();
            this.extraDetailsList=new SortedList<string, string>();

            this.FaviconPerHost = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();

            this.universalPlugAndPlayFieldList=null;//I could just as well set this to null 'cause it is not often used. I'll initialize it when it is needed.
            this.acceptedSmbDialectsList=null;
            this.preferredSmbDialect=null;
        }

        public override int GetHashCode() {
            return ipAddress.GetHashCode();
            //return base.GetHashCode();
        }
        public override string ToString() {
            StringBuilder str = new StringBuilder(ipAddress.ToString());
            lock (this.hostNameList) {
                foreach (string hostname in this.hostNameList) {
                    str.Append(" [");
                    str.Append(hostname);
                    str.Append("]");
                }
            }
            //if(this.operatingSystemCounterList.Count>0)
            if (this.fingerprinterOsCounterList.Count > 0) {
                str.Append(" (");
                str.Append(this.OS);
                str.Append(")");
            }
            return str.ToString();
        }
        /*
        public SortedList<NetworkHost, NetworkPacketList> GetSentPacketListsPerDestinationHost() {
            SortedList<NetworkHost, NetworkPacketList> masterList=new SortedList<NetworkHost, NetworkPacketList>();
            lock (sentPackets) {
                foreach (NetworkPacket p in sentPackets) {
                    if (!masterList.ContainsKey(p.DestinationHost)) {
                        masterList.Add(p.DestinationHost, new NetworkPacketList());
                    }
                    masterList[p.DestinationHost].Add(p);
                }
            }
            return masterList;
        }
        public SortedList<NetworkHost, NetworkPacketList> GetReceivedPacketListsPerSourceHost() {
            SortedList<NetworkHost, NetworkPacketList> masterList=new SortedList<NetworkHost, NetworkPacketList>();
            lock (this.receivedPackets) {
                foreach (NetworkPacket p in this.receivedPackets) {
                    if (!masterList.ContainsKey(p.SourceHost)) {
                        masterList.Add(p.SourceHost, new NetworkPacketList());
                    }
                    masterList[p.SourceHost].Add(p);
                }
            }
            return masterList;
        }
        */

        internal void AddProbableDeviceCategory(string deviceCategory, PacketParser.Fingerprints.IOsFingerprinter fingerprinter, double probability) {
            double p = fingerprinter.Confidence*probability;
            if (p > this.fingerprintedDeviceCategory.Key && deviceCategory != null && deviceCategory.Length > 0)
                this.fingerprintedDeviceCategory = new KeyValuePair<double, string>(p, deviceCategory);
        }
        internal void AddProbableDeviceFamily(string deviceFamily, PacketParser.Fingerprints.IOsFingerprinter fingerprinter, double probability) {
            double p = fingerprinter.Confidence * probability;
            if (p > this.fingerprintedDeviceFamily.Key && deviceFamily != null && deviceFamily.Length > 0)
                this.fingerprintedDeviceFamily = new KeyValuePair<double, string>(p, deviceFamily);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="operatingSystem"></param>
        /// <param name="probability">A number between 0.0 and 1.0</param>
        //internal void AddProbableOs(string fingerprinterName, string operatingSystem, double probability) {
        internal void AddProbableOs(string operatingSystem, PacketParser.Fingerprints.IOsFingerprinter fingerprinter, double probability) {

            lock (this.fingerprinterOsCounterList) {
                //string fingerprinterName = fingerprinter.Name;

                /*
                if(!this.operatingSystemCounterList.ContainsKey(fingerprinterName))
                    this.operatingSystemCounterList.Add(fingerprinterName, new SortedList<string, double>());
                 * */
                if (!this.fingerprinterOsCounterList.ContainsKey(fingerprinter))
                    this.fingerprinterOsCounterList.Add(fingerprinter, new SortedList<string, double>());


                //SortedList<string, double> operatingSystemCount=this.operatingSystemCounterList[fingerprinterName];
                SortedList<string, double> operatingSystemCount = this.fingerprinterOsCounterList[fingerprinter];

                if (operatingSystemCount.ContainsKey(operatingSystem))
                    operatingSystemCount[operatingSystem] += probability;
                else
                    operatingSystemCount.Add(operatingSystem, probability);
            }
        }

        internal void AddVlanID(ushort vlanID) {
            lock (this.vlanIdList) {
                if (!this.vlanIdList.Contains(vlanID))
                    this.vlanIdList.Add(vlanID);
            }
        }

        internal void AddTtl(byte ttl) {
            lock (this.ttlCount) {
                if (this.ttlCount.ContainsKey(ttl))
                    this.ttlCount[ttl]++;
                else
                    this.ttlCount.Add(ttl, 1);
            }
        }
        internal void AddProbableTtlDistance(byte ttlDistance){
            lock (this.ttlDistanceCount) {
                if (this.ttlDistanceCount.ContainsKey(ttlDistance))
                    this.ttlDistanceCount[ttlDistance]++;
                else
                    this.ttlDistanceCount.Add(ttlDistance, 1);
            }
        }

        /// <summary>
        /// Adds a host name of some form
        /// </summary>
        /// <param name="hostname">DNS address, NetBIOS name or simiar</param>
        internal void AddHostName(string hostname) {
            lock (this.hostNameList)
                if (!this.hostNameList.Contains(hostname))
                    this.hostNameList.Add(hostname);
        }
        internal void AddDomainName(string domainName) {
            lock (this.domainNameList) {
                if (!this.domainNameList.Contains(domainName))
                    this.domainNameList.Add(domainName);
            }
        }
        internal void AddQueriedIP(IPAddress ip) {
            lock (this.queriedIpList) {
                if (!this.queriedIpList.Contains(ip))
                    this.queriedIpList.Add(ip);
            }
        }
        internal void AddQueriedNetBiosName(string netBiosName) {
            lock (this.queriedNetBiosNameList) {
                if (!this.queriedNetBiosNameList.Contains(netBiosName))
                    this.queriedNetBiosNameList.Add(netBiosName);
            }
        }
        internal void AddQueriedDnsName(string dnsName) {
            lock (this.queriedDnsNameList) {
                if (!this.queriedDnsNameList.Contains(dnsName))
                    this.queriedDnsNameList.Add(dnsName);
            }
        }
        internal void AddHttpUserAgentBanner(string banner) {
            lock (this.httpUserAgentBannerList) {
                if (!this.httpUserAgentBannerList.Contains(banner))
                    this.httpUserAgentBannerList.Add(banner);
            }
        }
        internal void AddHttpServerBanner(string banner, ushort serverTcpPort) {
            lock(this.httpServerBannerList)
                if(!this.httpServerBannerList.Contains("TCP "+serverTcpPort+" : "+banner))
                    this.httpServerBannerList.Add("TCP "+serverTcpPort+" : "+banner);
        }
        internal void AddFtpServerBanner(string banner, ushort serverTcpPort) {
            lock(this.ftpServerBannerList)
                if(!this.ftpServerBannerList.Contains("TCP "+serverTcpPort+" : "+banner))
                    this.ftpServerBannerList.Add("TCP "+serverTcpPort+" : "+banner);
        }
        internal void AddDhcpVendorCode(string vendorCode) {
            lock(this.dhcpVendorCodeList)
                if(!this.dhcpVendorCodeList.Contains(vendorCode))
                    this.dhcpVendorCodeList.Add(vendorCode);
        }
        internal void AddNumberedExtraDetail(string name, string value) {
            lock (this.ExtraDetailsList) {
                for (int i = 1; i < 100; i++)
                    if (this.ExtraDetailsList.ContainsKey(name + " " + i)) {
                        if (this.ExtraDetailsList[name + " " + i].Equals(value, StringComparison.InvariantCultureIgnoreCase))
                            break;//the value is already stored
                    }
                    else {
                        this.ExtraDetailsList.Add(name + " " + i, value);
                        break;
                    }
            }
        }
        internal void AddOpenTcpPort(ushort port) {
            lock(this.openTcpPortList)
                this.openTcpPortList.Add(port);
        }
        internal bool TcpPortIsOpen(ushort port) {
            return this.openTcpPortList.Contains(port);
        }

        internal bool IsRecentMacAddress(PhysicalAddress macAddress) {
            return this.recentMacAdresses.ContainsKey(macAddress.ToString());
        }
        


        #region IComparable Members
        
        public int CompareTo(NetworkHost host) {

            if(this.IPAddress.Equals(host.IPAddress))
                return 0;
            else {
                byte[] localBytes=this.IPAddress.GetAddressBytes();
                byte[] remoteBytes=host.IPAddress.GetAddressBytes();
                if (localBytes.Length != remoteBytes.Length)
                    return localBytes.Length - remoteBytes.Length;
                for(int i=0; i<localBytes.Length && i<remoteBytes.Length; i++) {
                    if(localBytes[i]!=remoteBytes[i])
                        return localBytes[i]-remoteBytes[i];
                }
                return 0;
            }
        }

        public int CompareTo(object obj) {
            NetworkHost host=(NetworkHost)obj;
            return CompareTo(host);
        }
        #endregion

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("IPAddress", this.IPAddress.ToString());
            if (this.MacAddress != null)
                writer.WriteElementString("MacAddress", this.MacAddress.ToString());
            lock(this.hostNameList)
                foreach (string hostname in this.hostNameList)
                    writer.WriteElementString("HostName", hostname);
            if (this.OS != NetworkHost.OperatingSystemID.Unknown)
                writer.WriteElementString("OS", this.IPAddress.ToString());
            if (!String.IsNullOrEmpty(this.DeviceCategory))
                writer.WriteElementString("DeviceCategory", this.DeviceCategory);
            if (!String.IsNullOrEmpty(this.DeviceFamily))
                writer.WriteElementString("DeviceFamily", this.DeviceFamily);
            writer.WriteElementString("TTL", this.Ttl.ToString());
            writer.WriteElementString("TTL-distance", this.TtlDistance.ToString());
            lock(this.openTcpPortList)
                foreach (ushort port in this.openTcpPortList)
                    writer.WriteElementString("OpenTcpPort", port.ToString());
            lock (this.queriedDnsNameList) {
                foreach (string dns in this.queriedDnsNameList)
                    writer.WriteElementString("QueriedDnsName", dns);
            }
        }
       

    }
}
