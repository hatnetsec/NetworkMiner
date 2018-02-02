//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.IO;

namespace PacketParser.Fingerprints {
    class SatoriTcpOsFingerprinter : IOsFingerprinter, IComparable<IOsFingerprinter>, IComparable {
        private List<TcpFingerprint> fingerprintList;

        public double Confidence {
            get { return 0.4; }
        }

        internal SatoriTcpOsFingerprinter(string satoriTcpXmlFilename) {
            fingerprintList=new List<TcpFingerprint>();
            System.IO.FileStream fileStream=new FileStream(satoriTcpXmlFilename, FileMode.Open, FileAccess.Read);

            System.Xml.XmlDocument tcpXml=new System.Xml.XmlDocument();
            tcpXml.Load(fileStream);
            XmlNode fingerprintsNode=tcpXml.DocumentElement.FirstChild;

            //System.Xml.XPath.XPathNavigator navigator=tcpXml.CreateNavigator();
            System.Xml.XPath.XPathNavigator navigator=fingerprintsNode.CreateNavigator();
            foreach(XPathNavigator fingerprintNavigator in navigator.Select("fingerprint")) {
                string osClass=fingerprintNavigator.GetAttribute("os_class", "");
                string os=fingerprintNavigator.GetAttribute("os_name", "");
                if(os==null || os.Length==0)
                    os=fingerprintNavigator.GetAttribute("name", "");
                //string os=fingerprintNavigator.GetAttribute("os","");
                TcpFingerprint fingerprint=new TcpFingerprint(os, osClass);
                this.fingerprintList.Add(fingerprint);
                foreach(XPathNavigator testNav in fingerprintNavigator.Select("tcp_tests/test")) {//used to be "tests/test"
                    fingerprint.AddTest(testNav.Clone());

                }
            }


        }

        public int CompareTo(object obj) {
            if (obj is IOsFingerprinter)
                return this.CompareTo((IOsFingerprinter)obj);
            else
                throw new NotImplementedException();
        }

        public int CompareTo(IOsFingerprinter other) {
            return this.Name.CompareTo(other.Name);
        }

        #region IOsFingerprinter Members



        //public bool TryGetOperatingSystems(out IList<string> osList, IEnumerable<Packets.AbstractPacket> packetList) {
        public bool TryGetOperatingSystems(out IList<DeviceFingerprint> osList, IEnumerable<Packets.AbstractPacket> packetList) {
            try {
                //throw new Exception("The method or operation is not implemented.");
                Packets.TcpPacket tcpPacket=null;
                Packets.IPv4Packet ipPacket=null;

                foreach(Packets.AbstractPacket p in packetList) {
                    if(p.GetType()==typeof(Packets.TcpPacket))
                        tcpPacket=(Packets.TcpPacket)p;
                    else if(p.GetType()==typeof(Packets.IPv4Packet))
                        ipPacket=(Packets.IPv4Packet)p;
                }

                if(tcpPacket!=null) {//It is OK if the ipPacket is null (which is unlikely)

                    //osList=new List<string>();
                    osList = new List<DeviceFingerprint>();
                    int osListWeight=3;//in order to avoid getting hits on tests with weight 1 and 2

                    foreach(TcpFingerprint f in this.fingerprintList) {
                        int w=f.GetHighestMatchWeight(tcpPacket, ipPacket);
                        if(w>osListWeight) {
                            osListWeight=w;
                            osList.Clear();
                            //osList.Add(f.ToString());
                            osList.Add(new DeviceFingerprint(f.ToString()));
                        }
                        else if(w==osListWeight)
                            //osList.Add(f.ToString());
                            osList.Add(new DeviceFingerprint(f.ToString()));
                    }
                    if(osList.Count>0) {
                        //packetList=osList;
                        return true;
                    }

                }
            }
            catch(Exception e){
                System.Diagnostics.Debug.Print(e.ToString());
            }
            osList=null;
            return false;
        }

        public string Name {
            get { return "Satori TCP"; }
        }

        #endregion

        private class TcpFingerprint {

            private string os, osClass;
            private List<Test> testList;

            internal TcpFingerprint(string os, string osClass) {
                this.os=os;
                this.osClass=osClass;
                this.testList=new List<Test>();
            }

            public override string ToString() {
                
                if(os!=null && os.Length>0 && osClass!=null && osClass.Length>0)
                    return osClass+" - "+os;
                else if(os!=null && os.Length>0)
                    return os;
                else if(osClass!=null && osClass.Length>0)
                    return osClass;
                else
                    return base.ToString();

            }

            internal void AddTest(XPathNavigator testNavigator) {
                testList.Add(new Test(testNavigator.Clone(), this.osClass, this.os));
            }

            //returns -1 if there was no match
            internal int GetHighestMatchWeight(Packets.TcpPacket tcpPacket, Packets.IPv4Packet ipPacket) {
                int highestWeight=-1;
                foreach(Test t in testList) {
                    if(t.Weight>=3 && t.Weight>highestWeight && t.Matches(tcpPacket, ipPacket))
                        highestWeight=t.Weight;
                }
                return highestWeight;
            }

            /// <summary>
            /// Holds test information in order to see if a TCP packet matches the fingerprint
            /// </summary>
            private class Test : AbstractTtlDistanceCalculator {
                private int weight;
                //private System.Collections.Specialized.NameValueCollection attributeList;
                private System.Collections.Generic.HashSet<char> tcpflags;
                private P0fOsFingerprintCollection.P0fFingerprint p0fFingerprint;//Satori TCP uses p0f fingerprint format

                internal int Weight { get { return this.weight; } }

                //Typical data in navigator: <test weight="5" type="exact" flag="SA" tcpsig="65535:128:1:48:M1460,N,N,S:."/>
                internal Test(XPathNavigator testXPathNavigator, string osClass, string osDetails) {
                    testXPathNavigator.MoveToFirstAttribute();
                    //attributeList=new System.Collections.Specialized.NameValueCollection();
                    this.tcpflags = new HashSet<char>();

                    this.p0fFingerprint=null;

                    do{
                        //attributeList.Add(testXPathNavigator.Name, testXPathNavigator.Value);
                        if(testXPathNavigator.Name=="weight")
                            this.weight=Convert.ToInt32(testXPathNavigator.Value);
                        if(testXPathNavigator.Name=="tcpsig")
                            this.p0fFingerprint=new P0fOsFingerprintCollection.P0fFingerprint(testXPathNavigator.Value+":"+osClass+":"+osDetails);
                        if (testXPathNavigator.Name == "tcpflag")
                            foreach(char c in testXPathNavigator.Value.ToCharArray())
                                tcpflags.Add(c);

                    }while(testXPathNavigator.MoveToNextAttribute());

                }

                internal bool Matches(Packets.TcpPacket tcpPacket, Packets.IPv4Packet ipPacket) {

                    
                    if (tcpPacket.FlagBits.Synchronize != this.tcpflags.Contains('S'))
                        return false;
                    else if (tcpPacket.FlagBits.Acknowledgement != this.tcpflags.Contains('A'))
                        return false;
                    else if (tcpPacket.FlagBits.Fin != this.tcpflags.Contains('F'))
                        return false;
                    else if (this.p0fFingerprint == null)
                        return false;
                    else if (!p0fFingerprint.Matches(ipPacket, tcpPacket, base.GetOriginalTimeToLive(ipPacket.TimeToLive)))
                        return false;
                    else return true;
                    
                    /*
                    foreach(string key in attributeList.Keys){
                        if(key=="weight") {
                            //do nothing
                        }
                        else if(key=="matchtype") {
                            //do nothing, I will alway require an exact match
                        }
                        else if(key=="tcpflag") {//used to be "flag"
                            if(tcpPacket.FlagBits.Synchronize && !attributeList[key].Contains("S"))
                                return false;
                            else if(!tcpPacket.FlagBits.Synchronize && attributeList[key].Contains("S"))
                                return false;
                            else if(tcpPacket.FlagBits.Acknowledgement && !attributeList[key].Contains("A"))
                                return false;
                            else if(!tcpPacket.FlagBits.Acknowledgement && attributeList[key].Contains("A"))
                                return false;
                            else if(tcpPacket.FlagBits.Fin && !attributeList[key].Contains("F"))
                                return false;
                            else if(!tcpPacket.FlagBits.Fin && attributeList[key].Contains("F"))
                                return false;
                        }
                        else if(key=="tcpsig") {
                            //this is the really important part!
                            //now make sure to identify if the fingerprint doesn't match!
                            if(this.p0fFingerprint==null)
                                return false;
                            else {
                                if(!p0fFingerprint.Matches(ipPacket, tcpPacket, base.GetOriginalTimeToLive(ipPacket.TimeToLive)))
                                    return false;
                            }
                        }

                    }
                    //since no mis-match was found I guess it was a match...
                    return true;
                    */
                }

            }

        }

    }
}
