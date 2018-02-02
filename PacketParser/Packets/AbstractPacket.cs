//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace PacketParser.Packets {
    /// <summary>
    /// This class shall be implemented by all packet classes such as PacketIP, PacketEthernet, PacketTCP etc.
    /// </summary>
    public abstract class AbstractPacket : IPacket {
        
        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result=null;
            return false;
        }

        private Frame parentFrame;
        private string packetTypeDescription;
        private int packetStartIndex;//first byte position
        private int packetEndIndex;//last byte position
        private NameValueCollection attributes;

        public Frame ParentFrame { get { return parentFrame; } }
        public string PacketTypeDescription { get { return packetTypeDescription; } }
        public int PacketStartIndex { get { return packetStartIndex; } }
        public int PacketEndIndex {
            get { return packetEndIndex; }
            set { if(value>=packetStartIndex && value<parentFrame.Data.Length) packetEndIndex=value; }
        }
        public int PacketLength {
            get { return this.packetEndIndex-this.packetStartIndex+1; }
        }
        public int PacketByteCount { get { return packetEndIndex-packetStartIndex+1; } }
        public NameValueCollection Attributes { get { return attributes; } }



        internal AbstractPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, string packetTypeDescription) {
            this.parentFrame = parentFrame;
            this.packetStartIndex = packetStartIndex;
            this.packetEndIndex = packetEndIndex;
            this.packetTypeDescription = packetTypeDescription;
            
            if (!parentFrame.QuickParse) {
                this.attributes = new NameValueCollection();
                if (packetStartIndex > packetEndIndex) {
                    string errorMsg = "PacketStartIndex (" + packetStartIndex + ") > PacketEndIndex (" + packetEndIndex + ")";
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetEndIndex, packetEndIndex, errorMsg));
                    throw new Exception(errorMsg);
                }
            }
        }

        /// <summary>
        /// Creates a byte array containing everything from the start to the end of the packet (including payload).
        /// </summary>
        /// <returns></returns>
        public byte[] GetPacketData() {
            byte[] data=new byte[this.PacketByteCount];
            Array.Copy(parentFrame.Data, this.PacketStartIndex, data, 0, data.Length);
            return data;
        }


        public abstract IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference);

        
        /*
        public abstract class PacketFactory {

            public abstract static PacketFactory GetInstance();

            //This is a variant of the abstract factory pattern: http://en.wikipedia.org/wiki/Abstract_factory_pattern
            //The purpose is to have the user run the TryGetPacket instead of the packet constructor in order to
            //get less Exceptions and thereby better performace
            
        }*/
    }
}
