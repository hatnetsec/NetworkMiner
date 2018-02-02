//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkWrapper {
    public class WinPCapAdapter : IAdapter{
        private string npfName;// for example "\Device\NPF_{XXXXX}"
        private string description;//for example "3Com EtherLink PCI"
        private string ipAddress;//The IP-address
        private string netmask;//For example 255.255.255.0 ???

        internal string NPFName { get { return this.npfName; } }

        internal WinPCapAdapter(Device device){
            this.ipAddress=device.Address;
            this.description=device.Description;
            this.npfName=device.Name;
            this.netmask=device.Netmask;
        }

        public override string ToString() {
            StringBuilder returnString=new StringBuilder("WinPcap: "+this.description);
            if(ipAddress!=null && ipAddress.Length>6) {
                returnString.Append(" ("+ipAddress+")");
            }
            if(npfName.Contains("{"))
                returnString.Append(" "+npfName.Substring(npfName.IndexOf('{')));
            else
                returnString.Append(" "+npfName);
            return returnString.ToString();
            //return "WinPcap: "+this.description+" "+npfName.Substring(12);
        }

        public static List<IAdapter> GetAdapters() {
            

            //To use Nicolas .NET wrapper for WinPcap:
            
            List<IAdapter> deviceList=new List<IAdapter>();
            foreach(Device d in WinPCapWrapper.FindAllDevs())
                deviceList.Add(new WinPCapAdapter((Device)d));
            return deviceList;
            

            //To use the old dotNetPcap dll file:
            /*
            System.Collections.ArrayList tmpList;
            tmpList=dotnetWinpCap.FindAllDevs();

            List<IAdapter> devices=new List<IAdapter>(tmpList.Count);

            foreach(object d in tmpList) {
                devices.Add(new WinPCapAdapter((Device)d));
            }
            return devices;
            */
        }
    }
}
