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
    internal class EttarcapOsFingerprintCollection : AbstractTtlDistanceCalculator, IOsFingerprinter, ITtlDistanceCalculator, IComparable<IOsFingerprinter>, IComparable {
        private SortedDictionary<string, List<string>> osDictionary;
        private int maxTtlDistance;
        private bool[] timeToLiveExists;
        //internal enum OsFingerprintFileFormat{Ettercap}

        public string Name {
            get { return "Ettercap"; }
        }

        public double Confidence {
            get { return 0.2; }
        }

        internal EttarcapOsFingerprintCollection(string osFingerprintFilename) {
            this.maxTtlDistance=31;

            System.IO.FileStream fileStream=new FileStream(osFingerprintFilename, FileMode.Open, FileAccess.Read);
            StreamReader reader=new StreamReader(fileStream);
            osDictionary=new SortedDictionary<string, List<string>>();
            timeToLiveExists=new bool[256];

            while(!reader.EndOfStream) {

                string line=reader.ReadLine();
                //see if it is an empty or commented line
                if(line.Length>0 && line[0]!='#') {
                    string osKey=null;
                    string vendor=null;
                    if(line.Length>29) {
                        osKey=line.Substring(0, 28);//for example 16A0:0564:40:WS:1:0:1:1:A:38
                        vendor=line.Substring(29);
                    }
                    if(osKey!=null && vendor!=null) {
                        if(!osDictionary.ContainsKey(osKey)){
                            List<string> vendorList=new List<string>();
                            vendorList.Add(vendor);
                            osDictionary.Add(osKey, vendorList);
                        }
                        else
                            osDictionary[osKey].Add(vendor);
                        byte ttl=Byte.Parse(osKey.Substring(10,2), System.Globalization.NumberStyles.HexNumber);
                        timeToLiveExists[ttl]=true;
                    }
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


        private string[] GetOperatingSystems(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket, byte originalTimeToLive) {
            string osFingerprint=GetEttercapOperatingSystemFingerprint(ipv4Packet, tcpPacket, originalTimeToLive);

            if(osDictionary.ContainsKey(osFingerprint))
                return osDictionary[osFingerprint].ToArray();
            else if(osDictionary.ContainsKey(osFingerprint.Substring(0, osFingerprint.Length-3)+":LT"))
                return osDictionary[osFingerprint.Substring(0, osFingerprint.Length-3)+":LT"].ToArray();
            else
                return new string[0];
        }
        
        private string GetEttercapOperatingSystemFingerprint(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket, byte originalTimeToLive) {
            if(tcpPacket.OptionList==null || tcpPacket.OptionList.Count==0) {
                return GetEttercapOperatingSystemFingerprint(tcpPacket.WindowSize,
                    null,
                    originalTimeToLive,
                    null,
                    false,
                    false,
                    ipv4Packet.DontFragmentFlag,
                    false,
                    tcpPacket.FlagBits.Synchronize,
                    tcpPacket.FlagBits.Acknowledgement,
                    ipv4Packet.ParentFrame.Data.Length-ipv4Packet.PacketStartIndex);
            }
            else {
                ushort? maximumSegmentSize=null;
                byte? windowScaleFactor=null;
                bool sackPermitted=false;
                bool noOperation=false;
                bool timestamp=false;

                foreach(KeyValuePair<Packets.TcpPacket.OptionKinds, byte[]> optionKeyValue in tcpPacket.OptionList) {
                    if(optionKeyValue.Key.Equals(Packets.TcpPacket.OptionKinds.MaximumSegmentSize)) {
                        if(optionKeyValue.Value!=null && optionKeyValue.Value.Length>1)
                            maximumSegmentSize = Utils.ByteConverter.ToUInt16(optionKeyValue.Value, 0);
                    }
                    else if(optionKeyValue.Key.Equals(Packets.TcpPacket.OptionKinds.WindowScaleFactor)) {
                        if(optionKeyValue.Value!=null && optionKeyValue.Value.Length>0)
                            windowScaleFactor=optionKeyValue.Value[0];
                    }
                    else if(optionKeyValue.Key.Equals(Packets.TcpPacket.OptionKinds.SackPermitted))
                        sackPermitted=true;
                    else if(optionKeyValue.Key.Equals(Packets.TcpPacket.OptionKinds.NoOperation))
                        noOperation=true;
                    else if(optionKeyValue.Key.Equals(Packets.TcpPacket.OptionKinds.Timestamp))
                        timestamp=true;
                }

                /*if(tcpPacket.OptionList.ContainsKey(NetworkMiner.Packets.TcpPacket.OptionKinds.MaximumSegmentSize))
                    maximumSegmentSize=ByteConverter.ToUInt16(tcpPacket.OptionList[NetworkMiner.Packets.TcpPacket.OptionKinds.MaximumSegmentSize], 0);
                
                if(tcpPacket.OptionList.ContainsKey(NetworkMiner.Packets.TcpPacket.OptionKinds.WindowScaleFactor))
                  */  

                return GetEttercapOperatingSystemFingerprint(
                    tcpPacket.WindowSize,
                    maximumSegmentSize,
                    originalTimeToLive,
                    windowScaleFactor,
                    sackPermitted,
                    //tcpPacket.OptionList.ContainsKey(NetworkMiner.Packets.TcpPacket.OptionKinds.SackPermitted),
                    noOperation,
                    //tcpPacket.OptionList.ContainsKey(NetworkMiner.Packets.TcpPacket.OptionKinds.NoOperation),
                    ipv4Packet.DontFragmentFlag,
                    timestamp,
                    //tcpPacket.OptionList.ContainsKey(NetworkMiner.Packets.TcpPacket.OptionKinds.Timestamp),
                    tcpPacket.FlagBits.Synchronize,
                    tcpPacket.FlagBits.Acknowledgement,
                    ipv4Packet.ParentFrame.Data.Length-ipv4Packet.PacketStartIndex);
            }
        }

        private string GetEttercapOperatingSystemFingerprint(
            ushort tcpWindowSize,
            ushort? tcpOptionMaximumSegmentSize,
            byte ipTimeToLive,
            byte? tcpOptionWindowScaleFactor,
            bool tcpOptionSackPermitted,
            bool tcpOptionNoOperation,
            bool ipFlagDontFragment,
            bool tcpOptionTimestampPresent,
            bool tcpFlagSyn,
            bool tcpFlagAck,
            int? ipPacketTotalLength) {
            StringBuilder osKey=new StringBuilder(tcpWindowSize.ToString("X4"));//or X4???
            if(tcpOptionMaximumSegmentSize==null)
                osKey.Append(":_MSS");
            else
                osKey.Append(":"+((ushort)tcpOptionMaximumSegmentSize).ToString("X4"));
            osKey.Append(":"+ipTimeToLive.ToString("X2"));
            if(tcpOptionWindowScaleFactor==null)
                osKey.Append(":WS");
            else
                osKey.Append(":"+((byte)tcpOptionWindowScaleFactor).ToString("X2"));
            if(tcpOptionSackPermitted)
                osKey.Append(":1");
            else
                osKey.Append(":0");
            if(tcpOptionNoOperation)
                osKey.Append(":1");
            else
                osKey.Append(":0");
            if(ipFlagDontFragment)
                osKey.Append(":1");
            else
                osKey.Append(":0");
            if(tcpOptionTimestampPresent)
                osKey.Append(":1");
            else
                osKey.Append(":0");
            if(tcpFlagSyn && !tcpFlagAck)
                osKey.Append(":S");
            else if(tcpFlagSyn && tcpFlagAck)
                osKey.Append(":A");
            else
                return null;
            if(ipPacketTotalLength==null)
                osKey.Append(":LT");
            else
                osKey.Append(":"+((int)ipPacketTotalLength).ToString("X2"));
            return osKey.ToString();
        }

        public override string ToString() {
            return "Ettercap";
        }

        /*
        public string[] GetOperatingSystems(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket) {
            byte originalTimeToLive=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
            return GetOperatingSystems(ipv4Packet, tcpPacket, originalTimeToLive);
        }*/

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
                byte originalTimeToLive=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
                //osList=new List<string>();
                osList = new List<DeviceFingerprint>();
                foreach (string os in GetOperatingSystems(ipv4Packet, tcpPacket, originalTimeToLive))
                    osList.Add(new DeviceFingerprint(os));
                if(osList.Count>0)
                    return true;
            }
            osList=null;
            return false;
        }

        #endregion


        public byte GetTtlDistance(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket) {
            byte originalTimeToLive=GetOriginalTimeToLive(ipv4Packet, tcpPacket);
            return (byte)(originalTimeToLive-ipv4Packet.TimeToLive);
        }


        private byte GetOriginalTimeToLive(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket) {
            for(int ttlOffset=0; ttlOffset<maxTtlDistance && ipv4Packet.TimeToLive+ttlOffset<=Byte.MaxValue; ttlOffset++) {
                if(timeToLiveExists[ipv4Packet.TimeToLive+ttlOffset]) {
                    string[] oss=GetOperatingSystems(ipv4Packet, tcpPacket, (byte)(ipv4Packet.TimeToLive+ttlOffset));
                    if(oss!=null && oss.Length>0)
                        return (byte)(ipv4Packet.TimeToLive+ttlOffset);
                }
            }
            //if we still havn't found any OS we will have to guess the time to live
            return base.GetOriginalTimeToLive(ipv4Packet.TimeToLive);//from the abstract base class
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

        public override byte  GetTtlDistance(byte ipTimeToLive){
            byte originalTimeToLive=GetOriginalTimeToLive(ipTimeToLive);
            return (byte)(originalTimeToLive-ipTimeToLive);
        }

        #endregion




        
    }


}
