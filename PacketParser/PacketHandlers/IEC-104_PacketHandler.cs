using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class IEC_104_PacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        /**
         * ASDU IOA + Values => Parameters tab
         * Parameter name = IOA (IEC-101 7.2.5 INFORMATION OBJECT ADDRESS)
         * Parameter value = Value + Status
         * 
         * Status is important because status can change
         * while value remains the same.
         * 
         * Somewhere needs to go Cause of
         * transmission(CauseTx in wireshark), TypeID and Common Address of
         * ASDU(Addr in Wireshark). TypeID and CauseTx to Details field, for
         * instance "M_SP_TB_1(Single-point), interrogation". I think Common
         * address of ASDU is suited more to Hosts tab under Host Details.
         * 
         **/

        /**
         * We need a mapping like this:
         * AsduTypeID => InformationElement with ValueParser
         * */

        public IEC_104_PacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }


        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.IEC_104; }
        }


        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int returnValue = 0;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.IEC_60870_5_104Packet))
                    returnValue = ExtractData(tcpSession, transferIsClientToServer, (Packets.IEC_60870_5_104Packet)p);
            }

            return returnValue;
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, Packets.IEC_60870_5_104Packet iec104Packet) {
        
        
            //TODO extract data
            if (iec104Packet.AsduData != null && iec104Packet.AsduData.Length > 0) {
                //int addressLength = 3; //Can be 1, 2 or 3 !?
                int ioaOffset = 3;//typeID, noObjects, vauseTX
                if (iec104Packet.Settings.causeOfTransmissionHasOriginatorAddress)
                    ioaOffset++;
                ioaOffset += iec104Packet.Settings.asduAddressLength;

                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                string details = "IEC 60870-5-104 ASDU Type ID " + iec104Packet.AsduTypeID.ToString()
                    + ", CauseTX " + ((byte) iec104Packet.CauseOfTransmission)
                    + " (" + iec104Packet.CauseOfTransmission.ToString()  + ")";
                if (iec104Packet.CauseOfTransmissionNegativeConfirm)
                    details += " NEGATIVE";
                if (iec104Packet.CauseOfTransmissionTest)
                    details += " TEST";


                try {
                    while (parameters.Count < iec104Packet.AsduInformationObjectCount && ioaOffset < iec104Packet.AsduData.Length - iec104Packet.Settings.ioaLength) {
                        uint asduIOA = Utils.ByteConverter.ToUInt32(iec104Packet.AsduData, ioaOffset, iec104Packet.Settings.ioaLength, true);
                        ioaOffset += iec104Packet.Settings.ioaLength;

                        if (iec104Packet.AsduTypeID.Value == 1) {
                            //M_SP_NA_1 - 1 - Single-point information
                            Packets.IEC_60870_5_104Packet.SIQ siq = new Packets.IEC_60870_5_104Packet.SIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += siq.Length;
                            parameters.Add(asduIOA.ToString(), siq.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 3) {
                            //M_DP_NA_1 - Double-point information without time tag
                            //7.2.6.2 Double-point information (IEV 371-02-08) with quality descriptor
                            Packets.IEC_60870_5_104Packet.DIQ diq = new Packets.IEC_60870_5_104Packet.DIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += diq.Length;
                            parameters.Add(asduIOA.ToString(), diq.ToString());
                        }
                        //TODO: 7
                        else if (iec104Packet.AsduTypeID.Value == 9) {
                            //7.3.1.9 TYPE IDENT 9: M_ME_NA_1 - Measured value, normalized value

                            //NVA = Normalized value, defined in 7.2.6.6
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            //QDS 7.2.6.3
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(asduIOA.ToString(), nva.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 11) {
                            //IEC 101 - 7.3.1.11 TYPE IDENT 11: M_ME_NB_1 Measured value, scaled value

                            //SVA = 7.2.6.7 Scaled value
                            Packets.IEC_60870_5_104Packet.SVA sva = new Packets.IEC_60870_5_104Packet.SVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sva.Length;
                            //QDS 7.2.6.3
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(asduIOA.ToString(), sva.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 13) {
                            //IEC 101 - 7.3.1.13 TYPE IDENT 13: M_ME_NC_1 Measured value, short floating point number

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(asduIOA.ToString(), binary32Float.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 30) {
                            //M_SP_TB_1 - Single-point information with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.SIQ siq = new Packets.IEC_60870_5_104Packet.SIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += siq.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), siq.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 31) {
                            //7.3.1.23 TYPE IDENT 31
                            //M_DP_TB_1 Double-point information with time tag CP56Time2a

                            //DIQ = Double-point information with quality descriptor, defined in 7.2.6.2
                            Packets.IEC_60870_5_104Packet.DIQ diq = new Packets.IEC_60870_5_104Packet.DIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += diq.Length;

                            //Seven octet binary time
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), diq.ToString() + " " + time.ToString());

                        }
                        else if (iec104Packet.AsduTypeID.Value == 34) {
                            //7.3.1.26 TYPE IDENT 34: M_ME_TD_1 - Measured value, normalized value with time tag CP56Time2a

                            //nva
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), nva.ToString() + " (" + qds.ToString() + ") " + time.ToString());
                        }
                        //TODO: 35
                        else if (iec104Packet.AsduTypeID.Value == 36) {
                            //IEC 101 - 7.3.1.28 TYPE IDENT 36: M_ME_TF_1 Measured value, short floating point number with time tag CP56Time2a
                            //IEC 104 <36> := measured value, short floating point number with time tag CP56Time2a M_ME_TF_1

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), binary32Float.ToString() + " (" + qds.ToString() + ")" + time.ToString());

                        }
                        else if (iec104Packet.AsduTypeID.Value == 45) {
                            //7.3.2.1 TYPE IDENT 45: C_SC_NA_1 - Single command

                            //SCO = QU Single command, defined in 7.2.6.15
                            Packets.IEC_60870_5_104Packet.SCO sco = new Packets.IEC_60870_5_104Packet.SCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sco.Length;
                            parameters.Add(asduIOA.ToString(), sco.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 46) {
                            //7.3.2.2 TYPE IDENT 46: C_DC_NA_1 - Double command

                            //DCO = Double command, defined in 7.2.6.16
                            Packets.IEC_60870_5_104Packet.DCO dco = new Packets.IEC_60870_5_104Packet.DCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += dco.Length;
                            parameters.Add(asduIOA.ToString(), dco.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 50) {
                            //IEC 101 - 7.3.2.6 TYPE IDENT 50: C_SE_NC_1 Set-point command, short floating point number (similar to type ID 13)

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qos = quality of set-point command
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            parameters.Add(asduIOA.ToString(), binary32Float.ToString() + " (" + qos.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 58) {
                            //IEC 104 - 8.1 TYPE IDENT 58: C_SC_TA_1 Single command with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.SCO sco = new Packets.IEC_60870_5_104Packet.SCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset+=sco.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), sco.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 59) {
                            //IEC 104 - 8.2 TYPE IDENT 59: C_DC_TA_1 Double command with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.DCO dco = new Packets.IEC_60870_5_104Packet.DCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += dco.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), dco.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 61) {
                            //IEC 104 - 8.4 TYPE IDENT 61: C_SE_TA_1 Set-point command with time tag CP56Time2a, normalized value 
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), nva.ToString() + " ("+qos.ToString()+") " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 63) {
                            //IEC 104 - 8.6 TYPE IDENT 63: C_SE_TC_1 Set-point command with time tag CP56Time2a, short floating point number
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(asduIOA.ToString(), binary32Float.ToString() + " (" + qos.ToString() + ") " + time.ToString());
                        }
                        //TODO: 70 (JavaRMI_and...)
                        else if (iec104Packet.AsduTypeID.Value == 100) {
                            //7.3.4.1 TYPE IDENT 100: C_IC_NA_1


                            //QOI = Qualifier of UI8 interrogation, defined in 7.2.6.22
                            Packets.IEC_60870_5_104Packet.QOI qoi = new Packets.IEC_60870_5_104Packet.QOI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qoi.Length;
                            parameters.Add(asduIOA.ToString(), qoi.ToString());
                        }
                        /*
                    else if (iec104Packet.AsduTypeID.Value == 110) {
                        //7.3.5.1 TYPE IDENT 110: P_ME_NA_1
                        //Parameter of measured values, normalized value

                        //NVA
                        Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                        ioaOffset += nva.Length;
                        //QPM
                        ioaOffset += 1;

                        parameters.Add(asduIOA.ToString(), nva.ToString());
                    }*/
                        //TODO: P_ME_NA_1 - 110 - Parameter of measured value, normalized value
                        else {
                            //IOA value is NOT always 1 byte!
                            //let's make a qualified guess about the IOA value length!


                            int bytesPerAsduInformationObject = (iec104Packet.AsduData.Length - ioaOffset + iec104Packet.Settings.ioaLength) / (iec104Packet.AsduInformationObjectCount - parameters.Count);
                            int bytesPerValue = bytesPerAsduInformationObject - iec104Packet.Settings.ioaLength;


                            //TODO verify that the value is reasonable
                            if (bytesPerValue > 0) {
                                string ioaValueString = Utils.ByteConverter.ReadHexString(iec104Packet.AsduData, bytesPerValue, ioaOffset);
                                //uint ioaValue = Utils.ByteConverter.ToUInt32(iec104Packet.AsduData, ioaOffset, bytesPerValue);
                                //byte ioaValue = iec104Packet.AsduData[ioaOffset];
                                ioaOffset += bytesPerValue;
                                parameters.Add(asduIOA.ToString(), ioaValueString);
                            }
                            else if (bytesPerValue == 0) {
                                parameters.Add(asduIOA.ToString(), "");
                            }
                            else {
                                //System.Diagnostics.Debugger.Break();
                                //parameters.Add(asduIOA.ToString(), "");
                                //base.MainPacketHandler.OnAnomalyDetected("Incorrect IEC 60870-5-104 ASDU Information Object in Frame " + iec104Packet.ParentFrame.FrameNumber);
                                throw new Exception();
                            }
                        }
                    }
                }
                catch (Exception) {
                    base.MainPacketHandler.OnAnomalyDetected("Incorrect IEC 60870-5-104 ASDU Information Object in Frame " + iec104Packet.ParentFrame.FrameNumber, iec104Packet.ParentFrame.Timestamp);
                }
                /*
                ushort sourcePort = 0;
                ushort destinationPort = 0;
                if(tcpSession.ClientHost.IPAddress.Equals(tcpSession.ServerHost.IPAddress)) {
                    //special case if src IP == dst IP
                    foreach (Packets.AbstractPacket packet in iec104Packet.ParentFrame.PacketList) {
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
                */
                if(parameters.Count > 0)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(iec104Packet.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, iec104Packet.ParentFrame.Timestamp, details));
            }
            return Math.Min(iec104Packet.ApduLength + 2, iec104Packet.PacketLength);
        }

        public void Reset() {
            //DO nothing for now
            //TODO add resetter for identified lengths of iec104Packet.Settings (ASDU lengths and more)
        }

        
    }
}
