//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class HpSwitchProtocolPacketHandler  : AbstractPacketHandler, IPacketHandler {


        public HpSwitchProtocolPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.HpSwitchProtocolPacket)) {
                    foreach(Packets.AbstractPacket f in packetList){
                        if(f.GetType()==typeof(Packets.HpSwitchProtocolPacket.HpSwField) && ((Packets.HpSwitchProtocolPacket.HpSwField)f).TypeByte==(byte)Packets.HpSwitchProtocolPacket.HpSwField.FieldType.IpAddress){
                            System.Net.IPAddress ip=new System.Net.IPAddress(((Packets.HpSwitchProtocolPacket.HpSwField)f).ValueBytes);
                            if(sourceHost==null || sourceHost.IPAddress!=ip){
                                if(base.MainPacketHandler.NetworkHostList.ContainsIP(ip))
                                    sourceHost=base.MainPacketHandler.NetworkHostList.GetNetworkHost(ip);
                                else{
                                    sourceHost=new NetworkHost(ip);
                                    lock(base.MainPacketHandler.NetworkHostList)
                                        base.MainPacketHandler.NetworkHostList.Add(sourceHost);
                                }
                            }   
                        }
                    }
                    if(sourceHost!=null){
                        //do the same thing again, but now with the correct sourceHost
                        foreach(Packets.AbstractPacket f in packetList){
                            if(f.GetType()==typeof(Packets.HpSwitchProtocolPacket.HpSwField)){
                                ExtractData(ref sourceHost, (Packets.HpSwitchProtocolPacket.HpSwField)f);
                            }
                        }
                    }
                    
                }
            }
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion

        private void ExtractData(ref NetworkHost sourceHost, Packets.HpSwitchProtocolPacket.HpSwField hpswField) {
            if(hpswField.TypeByte==(byte)Packets.HpSwitchProtocolPacket.HpSwField.FieldType.DeviceName){
                if(!sourceHost.ExtraDetailsList.ContainsKey("HPSW Device Name")) {
                    sourceHost.ExtraDetailsList.Add("HPSW Device Name", hpswField.ValueString);
                    //sourceHost.HostNameList.Add(hpswField.ValueString);
                    sourceHost.AddHostName(hpswField.ValueString);
                }
            }
            else if(hpswField.TypeByte==(byte)Packets.HpSwitchProtocolPacket.HpSwField.FieldType.Version){
                if(!sourceHost.ExtraDetailsList.ContainsKey("HPSW Firmware version"))
                    sourceHost.ExtraDetailsList.Add("HPSW Firmware version", hpswField.ValueString);
            }
            else if(hpswField.TypeByte==(byte)Packets.HpSwitchProtocolPacket.HpSwField.FieldType.Config) {
                if(!sourceHost.ExtraDetailsList.ContainsKey("HPSW Config"))
                    sourceHost.ExtraDetailsList.Add("HPSW Config", hpswField.ValueString);
            }
            else if(hpswField.TypeByte==(byte)Packets.HpSwitchProtocolPacket.HpSwField.FieldType.MacAddress) {
                sourceHost.MacAddress=new System.Net.NetworkInformation.PhysicalAddress(hpswField.ValueBytes);
            }


        }
    }
}
