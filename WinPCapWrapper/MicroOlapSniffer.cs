using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkWrapper {
    public class MicroOlapSniffer : ISniffer{

        private MicroOlapAdapter adapterWrapper;
        //private microOLAP.PSSDK.HNAdapterConfig adapterConfig;
        private microOLAP.PSSDK.HNAdapter adapter;
        private microOLAP.PSSDK.HNQueue packetQueue;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get { return PacketReceivedEventArgs.PacketTypes.Ethernet2Packet; } }

        public static event PacketReceivedHandler PacketReceived;

        public MicroOlapSniffer(MicroOlapAdapter adapterWrapper) {
            //this.adapterConfig=adapterWrapper.AdapterConfig;
            this.adapterWrapper=adapterWrapper;
            this.adapter=new microOLAP.PSSDK.HNAdapter();
            this.adapter.ThreadCount=this.adapter.MaxThreadCount;
            this.adapter.ConfigHandle=adapterWrapper.AdapterConfig;
            //this.adapter.OnPacketReceive+=new microOLAP.PSSDK.OnPacketReceiveEventHandler(packetQueue_OnPacketReceive);
            //init
            
            
            this.packetQueue=new microOLAP.PSSDK.HNQueue();
            this.packetQueue.ItemsCount=1000;
            this.packetQueue.OnPacketReceive+= new microOLAP.PSSDK.OnPacketReceiveEventHandler(packetQueue_OnPacketReceive);
            this.adapter.ReceiveQueue=this.packetQueue;
        }

        void packetQueue_OnPacketReceive(object sender, IntPtr ThParam, IntPtr hPacket, IntPtr pPacketData, uint IncPacketSize) {
            //throw new Exception("The method or operation is not implemented.");

            PacketReceivedEventArgs.PacketTypes packetBaseType;
            //byte* pPkt = (byte*)pPacketData;
            microOLAP.PSSDK.HNPacket packet=new microOLAP.PSSDK.HNPacket();
            packet.Handle=hPacket;
            if(packet.MediumType==microOLAP.PSSDK.HNNetAdapterType.atEthernet)
                packetBaseType= PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;
            else//I think it will be ethernet always...
                packetBaseType= PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;
            
            

            byte[] byteArray=new byte[packet.PacketSize];
            System.Runtime.InteropServices.Marshal.Copy(packet.PacketData, byteArray, 0, byteArray.Length);
            DateTime packetTimestamp;
            if(packet.TimeStamp < (new DateTime(1970, 1, 1)).Ticks)
                packetTimestamp=new DateTime(1601, 1, 1).AddTicks(packet.TimeStamp).ToLocalTime();
            else
                packetTimestamp=new DateTime(packet.TimeStamp).ToLocalTime();
            PacketReceivedEventArgs eventArgs=new PacketReceivedEventArgs(byteArray, packetTimestamp, packetBaseType);
            PacketReceived(this, eventArgs);
            //PacketReceived(this, 
            /*unsafe {
                byte* packetDataPointer=(byte*)pPacketData;

                PacketReceivedEventArgs eventArgs=new PacketReceivedEventArgs((byte[])packetDataPointer, new DateTime(packet.TimeStamp), packetBaseType);
                PacketReceived(this, eventArgs);
            }*/
        }

        #region ISniffer Members

        public void StartSniffing() {
            //throw new Exception("The method or operation is not implemented.");

            this.packetQueue.MaxPacketSize=this.adapterWrapper.AdapterConfig.MaxPacketSize;
            //this.packetQueue.AllocItems()
            microOLAP.PSSDK.PSSDKRES result;
            
            result=this.packetQueue.AllocItems();
            if(result!=microOLAP.PSSDK.PSSDKRES.HNERR_OK) {
                throw new Exception("Error during queue memory allocating\nResult = "+(int)result);
            }
            result=this.packetQueue.Start();
            if(result!=microOLAP.PSSDK.PSSDKRES.HNERR_OK) {
                throw new Exception("Error during start packets queue internal thread\nResult = "+(int)result);
            }

            
            //pssdkNetworkAdapter.OpenAdapter();
            result=this.adapter.OpenAdapter();
            if(result!=microOLAP.PSSDK.PSSDKRES.HNERR_OK) {
                this.StopSniffing();
                throw new Exception("Error during open netwotrk adapter\nResult = "+(int)result);
            }
            this.adapter.MacFilter= microOLAP.PSSDK.HNMacFilter.mfAll;//allows all traffic?
        }

        public void StopSniffing() {
            //throw new Exception("The method or operation is not implemented.");
            if(this.adapter.IsOpened) {
                if(this.adapter.CloseAdapter()!=microOLAP.PSSDK.PSSDKRES.HNERR_OK) {
                    throw new Exception("Error during close netwotrk adapter");
                }
            }

        }

        #endregion
    }
}
