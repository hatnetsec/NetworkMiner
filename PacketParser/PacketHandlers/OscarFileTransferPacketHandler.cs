using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class OscarFileTransferPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public OscarFileTransferPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.OscarFileTransfer; }
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            /*
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }*/
            Packets.OscarFileTransferPacket oscarFileTransferPacket=null;
            Packets.TcpPacket tcpPacket=null;
            int parsedByteCount = 0;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.OscarFileTransferPacket))
                    oscarFileTransferPacket=(Packets.OscarFileTransferPacket)p;
                else if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
            }
            if(oscarFileTransferPacket!=null && tcpPacket!=null) {
                parsedByteCount = oscarFileTransferPacket.ParsedBytesCount;

                if(oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.SendRequest) {
                    //see if there is an old assembler that needs to be removed
                    if(base.MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer)) {
                        FileTransfer.FileStreamAssembler oldAssembler=base.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer);
                        base.MainPacketHandler.FileStreamAssemblerList.Remove(oldAssembler, true);
                    }
                    FileTransfer.FileStreamAssembler assembler=new FileTransfer.FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.OscarFileTransfer, oscarFileTransferPacket.FileName, "", (int)oscarFileTransferPacket.TotalFileSize, (int)oscarFileTransferPacket.TotalFileSize, oscarFileTransferPacket.FileName, "", oscarFileTransferPacket.ParentFrame.FrameNumber, oscarFileTransferPacket.ParentFrame.Timestamp, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source);
                    //assembler.SetRemainingBytesInFile((int)oscarFileTransferPacket.TotalFileSize);
                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                }
                else if(oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.ReceiveAccept) {
                    //reverse the order here!
                    if(base.MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer)) {
                        FileTransfer.FileStreamAssembler assembler=base.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer);
                        if(assembler != null)
                            assembler.TryActivate();
                    }

                }
                else if(oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.TransferComplete) {
                    //remove assembler from destination to client
                    if(base.MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer)) {
                        FileTransfer.FileStreamAssembler oldAssembler=base.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer);
                        base.MainPacketHandler.FileStreamAssemblerList.Remove(oldAssembler, true);
                    }
                }

                
            }
            return parsedByteCount;
        }



        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
