//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://www.radiotap.org/
    public class IEEE_802_11RadiotapPacket : AbstractPacket{
        private ushort radiotapHeaderLength;
        private System.Collections.Specialized.BitVector32 fieldsPresentFlags;
        private ushort frequency;//in MHz
        private int signalStrength;

        public ushort Frequency { get { return this.frequency; } }
        public int SignalStrength { get { return this.signalStrength; } }

        internal IEEE_802_11RadiotapPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IEEE 802.11 Radiotap") {

            //the most important part is to read the length in order to locate the starting point of the 802.11 packet
            this.radiotapHeaderLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, true);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Header length", radiotapHeaderLength.ToString());

            try {
                this.fieldsPresentFlags = new System.Collections.Specialized.BitVector32((int)Utils.ByteConverter.ToUInt32(parentFrame.Data, 4, 4, true));

                int offset=packetStartIndex+8;
                //try to find some interresting fields
                //http://netbsd.gw.com/cgi-bin/man-cgi?ieee80211_radiotap+9+NetBSD-current
                for(int i=0; i<8; i++) {
                    if(this.fieldsPresentFlags[1<<i]) {
                        if(i==0)//IEEE80211_RADIOTAP_TSFT
                            offset+=8;
                        else if(i==1)//IEEE80211_RADIOTAP_FLAGS
                            offset+=1;
                        else if(i==2)//IEEE80211_RADIOTAP_RATE
                            offset+=1;
                        else if(i==3) {//IEEE80211_RADIOTAP_CHANNEL
                            this.frequency = Utils.ByteConverter.ToUInt16(parentFrame.Data, offset, true);
                            if (!this.ParentFrame.QuickParse)
                                this.Attributes.Add("Frequency", ""+frequency+" MHz");
                            offset+=4;
                        }
                        else if(i==4)//IEEE80211_RADIOTAP_FHSS
                            offset+=2;
                        else if(i==5) {//IEEE80211_RADIOTAP_DBM_ANTSIGNAL
                            //This field contains a single signed 8-bit value, which indicates
                            //the RF signal power at the antenna, in decibels difference from
                            //1mW.
                            this.signalStrength=parentFrame.Data[offset];
                            while(signalStrength>70)//I don't expect to get more than 10kW !!!
                                signalStrength-=256;
                            if (!this.ParentFrame.QuickParse)
                                this.Attributes.Add("Signal strength", ""+signalStrength+" dBm ("+Math.Pow(10, (signalStrength/10.0))+" mW)");
                            offset+=1;
                        }
                    }
                }


            }
            catch {
                //do nothing
            }


        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+radiotapHeaderLength<PacketEndIndex) {
                AbstractPacket packet;
                try {
                    packet=new IEEE_802_11Packet(ParentFrame, PacketStartIndex+radiotapHeaderLength, PacketEndIndex);
                }
                catch(Exception e) {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+radiotapHeaderLength, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;

            }

            yield break;

            //throw new Exception("The method or operation is not implemented.");
        }
    }
}
