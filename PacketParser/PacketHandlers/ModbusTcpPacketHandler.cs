using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class ModbusTcpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {


        public ModbusTcpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }


        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.ModbusTCP; }
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            int returnValue = 0;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.ModbusTcpPacket))
                    returnValue = ExtractData(tcpSession, transferIsClientToServer, (Packets.ModbusTcpPacket)p);
            }

            return returnValue;
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, Packets.ModbusTcpPacket modbusPacket) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }

            foreach (string anomaly in modbusPacket.Anomalies)
                base.MainPacketHandler.OnAnomalyDetected(anomaly + " (frame " + modbusPacket.ParentFrame.FrameNumber + ")", modbusPacket.ParentFrame.Timestamp);

            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
            //parameters.Add("Transaction ID", modbusPacket.TransactionID.ToString());

            StringBuilder pName = new StringBuilder();
            if (modbusPacket.IsResponse)
                pName.Append("RSP ");
            else
                pName.Append("QRY ");
            pName.Append("sa:" + modbusPacket.SlaveAddress.ToString().PadRight(4));
            pName.Append("fc:" + modbusPacket.FunctionCode.ToString() + " (" + modbusPacket.FunctionCodeName.ToString() + ")");

            if (modbusPacket.IsResponse) {
                if (modbusPacket.ModbusMessage == null)
                    parameters.Add(pName.ToString(), "");
                else
                    parameters.Add(pName.ToString(), modbusPacket.ModbusMessage.ToString());
            }
            else {//QUERY
                if(modbusPacket.ModbusMessage == null)
                    parameters.Add(pName.ToString(), "UNKNOWN");
                /*else if (modbusPacket.FunctionCode == (byte)Packets.ModbusTcpPacket.FunctionCodeEnum.WriteSingleCoil) {
                    Packets.ModbusTcpPacket.WriteSingleCoilQueryOrResponse writeQuery = new Packets.ModbusTcpPacket.WriteSingleCoilQueryOrResponse(modbusPacket.StartingAddress.Value, modbusPacket.NRegistersToRead.Value);
                    parameters.Add(pName.ToString(), writeQuery.ToString());
                }*/
                else {
                    parameters.Add(pName.ToString(), modbusPacket.ModbusMessage.ToString());
                }
            }
            
            ushort sourcePort = 0;
            ushort destinationPort = 0;
            if (tcpSession.ClientHost.IPAddress.Equals(tcpSession.ServerHost.IPAddress)) {
                //special case if src IP == dst IP
                foreach (Packets.AbstractPacket packet in modbusPacket.ParentFrame.PacketList) {
                    if (packet is Packets.TcpPacket) {
                        Packets.TcpPacket tcpPacket = packet as Packets.TcpPacket;
                        sourcePort = tcpPacket.SourcePort;
                        destinationPort = tcpPacket.DestinationPort;
                    }
                }
            }
            else if (tcpSession.ClientHost.IPAddress.Equals(sourceHost.IPAddress)) {
                sourcePort = tcpSession.ClientTcpPort;
                destinationPort = tcpSession.ServerTcpPort;
            }
            else {
                sourcePort = tcpSession.ServerTcpPort;
                destinationPort = tcpSession.ClientTcpPort;
            }
            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(modbusPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, modbusPacket.ParentFrame.Timestamp, "Modbus/TCP Transaction ID: " + modbusPacket.TransactionID.ToString()));

            return Math.Min(modbusPacket.Length + 6, modbusPacket.PacketLength);
        }

        public void Reset() {
            //DO nothing for now
        }
    }
}
