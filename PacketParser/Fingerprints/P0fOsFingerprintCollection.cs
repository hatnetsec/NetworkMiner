//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser.Fingerprints {
    internal class P0fOsFingerprintCollection : AbstractTtlDistanceCalculator, IOsFingerprinter, ITtlDistanceCalculator, IComparable<IOsFingerprinter>, IComparable {

        private List<P0fFingerprint> synOsFingerprints, synAckOsFingerprints;
        private int maxTtlDistance;
        private bool[] timeToLiveExists;

        private string name = "p0f";
        private double confidence = 0.3;

        public double Confidence {
            get { return this.confidence; }
        }

        public string Name {
            get { return this.name; }
        }

        internal P0fOsFingerprintCollection(string synFingerprintFile, string synAckFingerprintFile, string name, double confidence)
            : this(synFingerprintFile, synAckFingerprintFile) {
            this.name = name;
            this.confidence = confidence;
        }

        internal P0fOsFingerprintCollection(string synFingerprintFile, string synAckFingerprintFile) {
            this.maxTtlDistance=31;
            timeToLiveExists=new bool[256];
            synOsFingerprints=GetFingerprintList(synFingerprintFile);
            synAckOsFingerprints=GetFingerprintList(synAckFingerprintFile);
          
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

        private List<P0fFingerprint> GetFingerprintList(string fingerprintFile) {
            System.IO.FileStream fileStream=new FileStream(fingerprintFile, FileMode.Open, FileAccess.Read);
            StreamReader reader=new StreamReader(fileStream);
            List<P0fFingerprint> fingerprintList=new List<P0fFingerprint>();

            while(!reader.EndOfStream) {

                string line=reader.ReadLine();
                //see if it is an empty or commented line
                if(line.Length>10 && line[0]!='#') {
                    P0fFingerprint fingerprint=new P0fFingerprint(line);
                    fingerprintList.Add(fingerprint);
                    timeToLiveExists[fingerprint.InitialTTL]=true;
                }
            }
            return fingerprintList;
        }




        #region IOsFingerprinter Members

        public bool TryGetOperatingSystems(out IList<DeviceFingerprint> osList, IEnumerable<Packets.AbstractPacket> packetList) {
            //throw new Exception("The method or operation is not implemented.");
            Packets.IPv4Packet ipv4Packet=null;
            Packets.TcpPacket tcpPacket=null;

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.IPv4Packet))
                    ipv4Packet=(Packets.IPv4Packet)p;
                else if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
            }
            if(ipv4Packet!=null && tcpPacket!=null && tcpPacket.FlagBits.Synchronize) {
                List<P0fFingerprint> osFingerprintList;
                if(tcpPacket.FlagBits.Acknowledgement) {//ack
                    osFingerprintList=this.synAckOsFingerprints;
                }
                else {//syn
                    osFingerprintList=this.synOsFingerprints;
                }
                byte originalTTL=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
                foreach(P0fFingerprint fingerprint in osFingerprintList) {
                    if(fingerprint.Matches(ipv4Packet, tcpPacket, originalTTL)) {
                        //return the first (and best) match
                        //osList=new List<string>();
                        osList = new List<DeviceFingerprint>();
                        osList.Add(new DeviceFingerprint(fingerprint.OS, fingerprint.OsGenre));
                        //osList.Add(fingerprint.OS);
                        return true;
                    }
                }
            }
            osList=null;
            return false;
        }

        #endregion
        /*
        private string[] GetOperatingSystems(NetworkMiner.Packets.IPv4Packet ipv4Packet, NetworkMiner.Packets.TcpPacket tcpPacket) {
            //string os=null;
            List<P0fFingerprint> osList;
            if(tcpPacket.FlagBits.Acknowledgement) {//ack
                osList=this.synAckOsFingerprints;
            }
            else {//syn
                osList=this.synOsFingerprints;
            }
            byte originalTTL=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
            foreach(P0fFingerprint fingerprint in osList) {
                if(fingerprint.Matches(ipv4Packet, tcpPacket, originalTTL)) {
                    string[] s=new string[1];
                    s[0]=fingerprint.OS;
                    return s;
                }
            }
            return new string[0];
        }*/



        


        internal class P0fFingerprint {
            /*
            #
            # wwww:ttt:D:ss:OOO...:QQ:OS:Details
            #
            # wwww     - window size (can be * or %nnn or Sxx or Txx)
            #	     "Snn" (multiple of MSS) and "Tnn" (multiple of MTU) are allowed.
            # ttt      - initial TTL 
            # D        - don't fragment bit (0 - not set, 1 - set)
            # ss       - overall SYN packet size (* has a special meaning)
            # OOO      - option value and order specification (see below)
            # QQ       - quirks list (see below)
            # OS       - OS genre (Linux, Solaris, Windows)
            # details  - OS description (2.0.27 on x86, etc)
             * */

            string windowSize;
            byte initialTtl;
            bool dontFragment;//(false - not set, true - set)
            string overallSynPacketSize;//could this maybe be an int?
            string optionValue, quirksList;
            string osGenre, osDetails;

            internal string OsGenre { get { return this.osGenre; } }
            internal string OsDetails { get { return this.osDetails; } }
            internal string OS { get { return this.osGenre+" "+this.osDetails; } }
            internal byte InitialTTL { get { return initialTtl; } }

            internal P0fFingerprint(string fingerprintString) {
                char[] separator={':'};
                string[] f=fingerprintString.Split(separator);
                this.windowSize=f[0];
                this.initialTtl=Convert.ToByte(f[1],10);
                this.dontFragment=f[2].Equals("1");
                this.overallSynPacketSize=f[3];
                this.optionValue=f[4];
                this.quirksList=f[5];
                this.osGenre=f[6].TrimStart(new char[] {'-'});//because of a bug in p0f.fp
                this.osDetails=f[7];
            }

            internal bool Matches(Packets.IPv4Packet ipPacket, Packets.TcpPacket tcpPacket, byte originalTimeToLive) {
                //window size (can be * or %nnn or Sxx or Txx)
                //"Snn" (multiple of MSS) and "Tnn" (multiple of MTU) are allowed.
                if(this.windowSize.StartsWith("S")) {
                    int multipleMSS=Convert.ToInt32(this.windowSize.Substring(1));
                    int mss=0;
                    
                    foreach(KeyValuePair<Packets.TcpPacket.OptionKinds,byte[]> keyValuePair in tcpPacket.OptionList)
                        if(keyValuePair.Key.Equals(Packets.TcpPacket.OptionKinds.MaximumSegmentSize))
                            mss = (int)Utils.ByteConverter.ToUInt32(keyValuePair.Value);
                    if(tcpPacket.WindowSize!=multipleMSS*mss)
                        return false;
                }
                else if(this.windowSize.StartsWith("T")) {
                    int multipleMTU=Convert.ToInt32(this.windowSize.Substring(1));
                    int mtu=1500;
                    //MTU is defined by Michal Zalewski (p0f author) as MSS+40 however in reality I guess it could be different.
                    //For Ethernet the MTU is 1500 bytes (http://en.wikipedia.org/wiki/MTU_%28networking%29)
                    //It can also be calculated from MSS, depending on the IP and TCP header size. See: http://www.faqs.org/rfcs/rfc879.html for more details
                    foreach(KeyValuePair<Packets.TcpPacket.OptionKinds, byte[]> keyValuePair in tcpPacket.OptionList)
                        if(keyValuePair.Key.Equals(Packets.TcpPacket.OptionKinds.MaximumSegmentSize))
                            mtu = (int)Utils.ByteConverter.ToUInt32(keyValuePair.Value) + 40;
                    if(tcpPacket.WindowSize!=multipleMTU*mtu)
                        return false;
                }
                else if(this.windowSize.StartsWith("%")){
                    int modulo=Convert.ToInt32(windowSize.Substring(1));
                    if(tcpPacket.WindowSize%modulo!=0)
                        return false;
                }
                else if(this.windowSize.StartsWith("*")) {
                    //do noting
                }
                else if(!this.windowSize.Equals(tcpPacket.WindowSize.ToString())) {
                    return false;
                }
                if(originalTimeToLive!=this.initialTtl)
                    return false;
                if(ipPacket.DontFragmentFlag!=this.dontFragment)
                    return false;
                if(!this.overallSynPacketSize.Equals("!") && !this.overallSynPacketSize.Equals(ipPacket.PacketByteCount.ToString()))
                    return false;
               
                //options
                char[] separator={ ',' };
                string[] optionValues=this.optionValue.Split(separator);
                if(optionValues.Length!=tcpPacket.OptionList.Count)
                    return false;
                for(int i=0; i<optionValues.Length; i++){
                    //string o in this.optionValue.Split(separator)) {//the options must be in the same order!

                    if(optionValues[i].Equals("N")) {//N	   - NOP option
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.NoOperation))
                            return false;
                    }
                    else if(optionValues[i].Equals("E")) {//E	   - EOL option
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.EndOfOptionList))
                            return false;
                    }
                    else if(optionValues[i].StartsWith("W")) {//Wnnn	   - window scaling option, value nnn (or * or %nnn)
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.WindowScaleFactor))
                            return false;
                        else {
                            int signatureScaleFactor;
                            if(optionValues[i][1]=='%') {
                                int windowScaleFactor = (int)Utils.ByteConverter.ToUInt32(tcpPacket.OptionList[i].Value);
                                int modulo=Convert.ToInt32(optionValues[i].Substring(2));
                                if(windowScaleFactor%modulo!=0)
                                    return false;
                            }
                            else if(optionValues[i][1]=='*') {
                                //do nothing
                            }
                            else if(Int32.TryParse(optionValues[i].Substring(1), out signatureScaleFactor)) {
                                int packetScaleFactor = (int)Utils.ByteConverter.ToUInt32(tcpPacket.OptionList[i].Value);
                                if(signatureScaleFactor!=packetScaleFactor)
                                    return false;
                            }
                            else
                                return false;
                        }
                    }
                    else if(optionValues[i].StartsWith("M")) {//Mnnn	   - maximum segment size option, value nnn (or * or %nnn)
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.MaximumSegmentSize))
                            return false;
                        else {
                            int signatureMSS;
                            if(optionValues[i][1]=='%') {
                                int packetMSS = (int)Utils.ByteConverter.ToUInt32(tcpPacket.OptionList[i].Value);
                                int modulo=Convert.ToInt32(optionValues[i].Substring(2));
                                if(packetMSS%modulo!=0)
                                    return false;
                            }
                            else if(optionValues[i][1]=='*') {
                                //do nothing
                            }
                            else if(Int32.TryParse(optionValues[i].Substring(1), out signatureMSS)) {
                                int packetMSS = (int)Utils.ByteConverter.ToUInt32(tcpPacket.OptionList[i].Value);
                                if(signatureMSS!=packetMSS)
                                    return false;
                            }
                            else
                                return false;
                        }
                    }
                    else if(optionValues[i].Equals("S")) {//S	   - selective ACK OK
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.SackPermitted))
                            return false;
                    }
                    else if(optionValues[i].Equals("K")) {//K = SACK. This is a special extension for the Satori TCP database
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.Sack))
                            return false;
                    }
                    else if(optionValues[i].Equals("T")) {//T 	   - timestamp
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.Timestamp))
                            return false;
                    }
                    else if(optionValues[i].Equals("T0")) {//T0	   - timestamp with zero value
                        if(!tcpPacket.OptionList[i].Key.Equals(Packets.TcpPacket.OptionKinds.Timestamp))
                            return false;
                        foreach(byte b in tcpPacket.OptionList[i].Value)
                            if(b!=0x00)
                                return false;
                    }
                    else if(optionValues[i].StartsWith("?")) {//?n       - unrecognized option number n.
                        //i'll skip this one for now...
                    }

                }

                //quirks list... i'll skip it also
                return true;
            }

            public override string ToString() {
                return "P0f";
            }
        }

        private byte GetOriginalTimeToLive(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket) {
            for(int ttlOffset=0; ttlOffset<maxTtlDistance && ipv4Packet.TimeToLive+ttlOffset<=Byte.MaxValue; ttlOffset++) {
                if(timeToLiveExists[ipv4Packet.TimeToLive+ttlOffset]) {
                    if(ipv4Packet.TimeToLive+ttlOffset == (int)GetOriginalTimeToLive(ipv4Packet.TimeToLive))
                        return (byte)(ipv4Packet.TimeToLive+ttlOffset);
                }
            }
            for(int ttlOffset=0; ttlOffset<maxTtlDistance && ipv4Packet.TimeToLive+ttlOffset<=Byte.MaxValue; ttlOffset++) {
                if(timeToLiveExists[ipv4Packet.TimeToLive+ttlOffset]) {
                    return (byte)(ipv4Packet.TimeToLive+ttlOffset);
                }
            }
            //if we still havn't found any OS we will have to guess the time to live
            return base.GetOriginalTimeToLive(ipv4Packet.TimeToLive);//from base class
        }

        public byte GetTtlDistance(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket) {
            byte originalTimeToLive=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
            return (byte)(originalTimeToLive-ipv4Packet.TimeToLive);
        }

        #region ITtlDistanceCalculator Members

        public override bool TryGetTtlDistance(out byte ttlDistance, IEnumerable<Packets.AbstractPacket> packetList) {
            Packets.IPv4Packet ipv4Packet=null;
            Packets.TcpPacket tcpPacket=null;

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.IPv4Packet))
                    ipv4Packet=(Packets.IPv4Packet)p;
                else if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
            }

            if(ipv4Packet!=null && tcpPacket!=null) {
                ttlDistance=GetTtlDistance(ipv4Packet, tcpPacket);
                return true;
            }
            else {
                ttlDistance=0;
                return false;
            }
        }

        public override byte GetTtlDistance(byte ipTimeToLive) {
            byte originalTimeToLive=GetOriginalTimeToLive(ipTimeToLive);
            return (byte)(originalTimeToLive-ipTimeToLive);
        }

        /*
        public bool TryGetTtlDistance(out byte ttlDistance, IList<NetworkMiner.Packets.AbstractPacket> packetList) {
            throw new Exception("The method or operation is not implemented.");
        }

        byte GetTtlDistance(byte ipTimeToLive) {
            throw new Exception("The method or operation is not implemented.");
        }*/

        #endregion
    }
}
