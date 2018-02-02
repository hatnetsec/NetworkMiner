//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class Frame {
        //private static int nFramesReceived;

        /**
     * https://en.wikipedia.org/wiki/IPv6_packet#Jumbogram
     * Since both TCP and UDP include fields limited to 16 bits (length, urgent data pointer),
     * support for IPv6 jumbograms requires modifications to the Transport Layer protocol implementation.
     * Jumbograms are only relevant for links that have a MTU larger than 65583 octets
     * (more than 65535 octets for the payload, plus 40 octets for the fixed header,
     * plus 8 octets for the Hop-by-Hop extension header).
     * 
     * See PacketParser.Frame.MAX_FRAME_SIZE
     * */
        private const int MAX_FRAME_SIZE = 66000; //jumbo frames can carry up to 9000 bytes of payload, IP can carry 65535 bytes, so we need to cover Max-IP + ecap-protocol + ethernet

        private long frameNumber;//eller long?
        private DateTime timestamp;
        //private int length;
        private byte[] data;

        private bool quickParse;
        
        private SortedList<int, Packets.AbstractPacket> packetList;
        bool precomputePacketList;

        private List<Error> errorList;

        public long FrameNumber { get { return frameNumber; } }
        public DateTime Timestamp { get { return timestamp.ToLocalTime(); } }
        //public int Length { get { return length; } }
        public byte[] Data { get { return data; } }
        public bool QuickParse { get { return this.quickParse; } }

        public System.Collections.Generic.IEnumerable<Packets.AbstractPacket> PacketList {
            get {
                if(!precomputePacketList && packetList.ContainsKey(0))
                    return packetList[0].GetSubPackets(true);
                    
                else {
                    return packetList.Values;
                }

            }
        }

        public Packets.AbstractPacket BasePacket {
            get {
                if(this.packetList.ContainsKey(0))
                    return this.packetList[0];
                else
                    return null;
            }
        }


        //public List<Error> ErrorList { get { return errorList; } }
        public IList<Error> Errors {
            get {
                return errorList;
            //foreach(Error er in errorList)
              //  yield return er;
            }
        }

        /// <summary>
        /// Does not care about the content, PacketList will be empty when using this constructor!
        /// </summary>
        /// <param name="timestamp"></param>
        /// <param name="data"></param>
        /// <param name="frameNumber"></param>
        public Frame(DateTime timestamp, byte[] data, long frameNumber) {
            this.timestamp = timestamp;
            this.data = data;
            this.frameNumber = frameNumber;
        }

        public Frame(DateTime timestamp, byte[] data, System.Type packetType, long frameNumber) : this(timestamp, data, packetType, frameNumber, true) {
            //nothing more...        
        }
        public Frame(DateTime timestamp, byte[] data, System.Type packetType, long frameNumber, bool precomputePacketList)
            : this(timestamp, data, packetType, frameNumber, precomputePacketList, false) {
            //nothing more...       
        }
        public Frame(DateTime timestamp, byte[] data, System.Type packetType, long frameNumber, bool precomputePacketList, bool quickParse)
            : this(timestamp, data, packetType, frameNumber, precomputePacketList, quickParse, MAX_FRAME_SIZE) {
            //nothing more, just use the fixed frame size as max
        }
        
        public Frame(DateTime timestamp, byte[] data, System.Type packetType, long frameNumber, bool precomputePacketList, bool quickParse, int maxFrameSize) {
            if (data.Length > maxFrameSize)
                throw new ArgumentException("Frame larger than max allowed size " + maxFrameSize);

            this.precomputePacketList=precomputePacketList;
            this.frameNumber=frameNumber;
            this.quickParse = quickParse;

            this.timestamp=timestamp;
            this.data=data;

            //TODO: add check for quickParse
            if(!quickParse)
                this.errorList=new List<Error>();

            this.packetList=new SortedList<int, Packets.AbstractPacket>();

            
            Packets.AbstractPacket packet=null;

            if (data.Length > 0)
                Packets.PacketFactory.TryGetPacket(out packet, packetType, this, 0, data.Length - 1);
                
            if(packet!=null) {

                packetList.Add(packet.PacketStartIndex, packet);
                if(this.precomputePacketList) {
                    foreach(Packets.AbstractPacket p in packet.GetSubPackets(false))
                        if(packetList.ContainsKey(p.PacketStartIndex))
                            packetList[p.PacketStartIndex]=p;
                        else
                            packetList.Add(p.PacketStartIndex, p);
                }

                
            }
            

            
        }
        

        public override string ToString() {
            return "Frame "+frameNumber+" ["+Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff tt")+"]";
        }

        /// <summary>
        /// Reports the index of the first occurrence of the specified ByteArray in this frame.
        /// </summary>
        /// <param name="bytes">a byte-array to search for</param>
        /// <returns>The index position of value if that character is found, or -1 if it is not.</returns>
        public int IndexOf(byte[] bytes) {
            int i=0;
            while (bytes != null && bytes.Length > 0 && i <= data.Length - bytes.Length) {
                int firstByteIndex=Array.IndexOf<byte>(data, bytes[0], i);
                if(firstByteIndex>=0 && firstByteIndex<=data.Length-bytes.Length) {
                    bool bytesFound=true;
                     for(int bytesIndex=1; bytesFound && bytesIndex<bytes.Length; bytesIndex++) {
                            if(data[firstByteIndex+bytesIndex]!=bytes[bytesIndex])
                                bytesFound=false;
                    }
                    if(bytesFound)
                        return firstByteIndex;
                    else i=firstByteIndex+1;
                }
                else
                    return -1;//bytes does not exist in data
            }
            return -1;//bytes does not exist in data
        }

        public Frame CloneWithPacketList(SortedList<int, Packets.AbstractPacket> packetList) {
            Frame newFrame = new Frame(this.timestamp, this.data, this.frameNumber);
            newFrame.packetList = packetList;
            newFrame.errorList = new List<Error>();
            return newFrame;
        }

        public class Error {
            private Frame frame;
            private int errorStartIndex;
            private int errorEndIndex;
            private string description;


            internal Error(Frame frame, int errorStartIndex, int errorEndIndex, string description) {
                this.frame=frame;
                this.errorStartIndex=errorStartIndex;
                this.errorEndIndex=errorEndIndex;
                this.description=description;
            }

            public override string ToString() {

                return description+", ["+errorStartIndex+","+errorEndIndex+"]";
            }
        }

    }
}
