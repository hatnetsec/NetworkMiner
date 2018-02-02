//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    /// <summary>
    /// This class is intended for storage of information that can be used to identify
    /// for example what protocol that is being used in a TCP session.
    /// It can also used to calculate the entropy (ammount of information) in a session
    /// </summary>
    public class NetworkServiceMetadata {
        private NetworkHost serverHost;
        private ushort tcpPort;
        private PacketParser.ApplicationLayerProtocol applicationLayerProtocol = ApplicationLayerProtocol.Unknown;
        //private int incomingPacketsCount, outgoingPacketsCount;//counts total number of recieved packets
        //private int[] incomingByteCount, outgoingByteCount;//contains counts of each possible byte
        //private int[,] firstFourIncomingBytesCount, firstFourOutgoingBytesCount;//contains counts of each possible byte for different offsets in the TCP packet
        //private int[] first256IncomingTrueBitsCount, first256OutgoingTrueBitsCount;//First 32 Bytes are counted. Total number if recieved bytes must me known. Cna be calculated using incomingBytesCount
        //private int[] dataLengthCount;//int[0]=#0-length packets, int[32]=#32-byte packets, 

        private TrafficMetadata incomingTraffic, outgoingTraffic;

        public ushort TcpPort { get { return tcpPort; } }
        public TrafficMetadata IncomingTraffic { get { return incomingTraffic; } }
        public TrafficMetadata OutgoingTraffic { get { return outgoingTraffic; } }
        public PacketParser.ApplicationLayerProtocol ApplicationLayerProtocol {
            get { return this.applicationLayerProtocol; }
            set { 
                if(value != ApplicationLayerProtocol.Unknown)
                    this.applicationLayerProtocol = value;
            }
        }


        public NetworkServiceMetadata(NetworkHost serverHost, ushort tcpPort) {
            this.serverHost=serverHost;
            this.tcpPort=tcpPort;

            this.incomingTraffic=new TrafficMetadata(true);
            this.outgoingTraffic=new TrafficMetadata(false);
        }

        /// <summary>
        /// Only holds data for traffic in one direction (incoming or outgoing)
        /// </summary>
        public class TrafficMetadata {
            bool incomingTraffic;
            private int packetsCount;//counts total number of recieved packets
            private int[] byteCount;//contains counts of each possible byte
            //private int[,] firstFourIncomingBytesCount, firstFourOutgoingBytesCount;//contains counts of each possible byte for different offsets in the TCP packet
            private int[] first256TrueBitsCount;//First 32 Bytes are counted. Total number if recieved bytes must me known. Cna be calculated using incomingBytesCount
            private int[] dataLengthCount;//int[0]=#0-length packets, int[32]=#32-byte packets, 

            internal TrafficMetadata(bool incomingTraffic) {
                this.incomingTraffic=incomingTraffic;
                this.packetsCount=0;
                this.byteCount=new int[1+byte.MaxValue];//one box for each possible byte value. Consumes 256*4 bytes=1kB
                //this.firstFourIncomingBytesCount=new int[4, 1+byte.MaxValue];//x=byteIndex, y=byte value
                this.first256TrueBitsCount=new int[256];//every '1' or 'true' adds 1 to the cound of the bits location in the packet
                this.dataLengthCount=new int[33];//I could make this one longer if needed...
            }

            internal void AddTcpPayloadData(byte[] tcpPayloadData) {
                if(tcpPayloadData.Length<this.dataLengthCount.Length)
                    this.dataLengthCount[tcpPayloadData.Length]++;
                this.packetsCount++;
                for(int i=0; i<tcpPayloadData.Length; i++) {
                        this.byteCount[tcpPayloadData[i]]++;
                    if(i<32) {
                        for(int bitPos=0; bitPos<8; bitPos++) {
                            if(((tcpPayloadData[i]>>(7-bitPos))&0x01)==0x01) {
                                this.first256TrueBitsCount[i*8+bitPos]++;
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Calculates the frequency for each possible byte. Calculations are based on data in byteCount[]
            /// </summary>
            /// <returns></returns>
            private double[] GetByteFrequencies() {
                int totalBytes=0;
                double[] byteFreq=new double[byteCount.Length];
                for(int i=0; i<byteCount.Length; i++)
                    totalBytes+=byteCount[i];
                for(int i=0; i<byteCount.Length; i++)
                    byteFreq[i]=(1.0*byteCount[i])/totalBytes;
                return byteFreq;
            }

            public double CalculateEntropy() {
                //int totalBytes=0;
                double entropy=0.0;


                double[] byteFreq=GetByteFrequencies();

                for(int i=0;i<byteFreq.Length;i++)
                    if(byteFreq[i]>0.0)
                        entropy-=byteFreq[i]*Math.Log(byteFreq[i], 2);
                //return entropy;
                return entropy*100.0/8.0;//I'll multiply by 100/8 so that 100=maximum entropy=compressed or encrypted
            }

            public string GetTypicalData() {
                //char[] typicalData=new char[32];//shall be returned, sort of
                string typicalData="";
                int packetsCountCurrentLength=this.packetsCount;//-dataLengthCount[0];//removes the number of 0-length packets...

                for(int i=0; i<32; i++) {
                    packetsCountCurrentLength-=dataLengthCount[i];//first removes number of 0-lenth packets for example...

                    
                    //I'll try another more advanced (but heavier method) using ByteFrequencies.
                    double[] byteProbability=GetByteFrequencies();
                    //now I'll have to try the possibility of all bytes!!!
                    double bestProbability=0.0;
                    int bestProbabilityIndex=0;
                    for(int bpi=0; bpi<byteProbability.Length; bpi++) {
                        //double currentProbability=byteProbability[bpi];
                        //now check how probable it is that this specific byte is at this location...
                        for(int bit=0; bit<8; bit++){
                            if(((bpi>>(7-bit))&0x01) == 0x01)//if true
                                byteProbability[bpi]*=(1.0*first256TrueBitsCount[i*8+bit])/packetsCountCurrentLength;
                            else//if false
                                byteProbability[bpi]*=1.0-((1.0*first256TrueBitsCount[i*8+bit])/packetsCountCurrentLength);
                        }
                        if(byteProbability[bpi]>bestProbability){
                            bestProbability=byteProbability[bpi];
                            bestProbabilityIndex=bpi;
                        }
                    }
                    typicalData+=(char)((byte)bestProbabilityIndex);
                    
                }
                return typicalData;
            }
        }



        public override string ToString() {
            return "TCP "+tcpPort;
            //return base.ToString();
        }
    }
}
