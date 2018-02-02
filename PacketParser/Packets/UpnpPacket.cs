//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    /// <summary>
    /// I'm just doing a very simple implementation of the SSDP Notify command here
    /// So I just extract all the lines (fields) and add them to a collection
    /// </summary>
    class UpnpPacket : AbstractPacket {
        private List<string> fieldList;

        internal List<string> FieldList { get { return this.fieldList; } }

        internal UpnpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "UPnP") {
            this.fieldList=new List<string>();
            int dataIndex=packetStartIndex;
            string line;
            while(dataIndex<packetEndIndex) {
                line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref dataIndex);
                if(line!=null && line.Length>0)
                    fieldList.Add(line);
                else
                    break;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //Do nothing, no known sub packets...
            yield break;
        }
    }
}
