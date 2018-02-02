using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    public class ModbusTcpPacket : AbstractPacket, ISessionPacket{

        public abstract class AbstractModbusMessage {
            protected FunctionCodeEnum functionCode;

            public FunctionCodeEnum FunctionCode { get { return this.functionCode; } }

            protected AbstractModbusMessage(byte[] frameData, int functionCodeOffset) {
                this.functionCode = (FunctionCodeEnum)frameData[functionCodeOffset];
            }
            
            public abstract override string ToString();
        }


        /// <summary>
        /// Querys with function code 1,2,3,4
        /// </summary>
        public class GenericAddressAndInputCountRequest : AbstractModbusMessage {
            private ushort startAddress;//zero indexed
            private ushort inputCount;

            public GenericAddressAndInputCountRequest(byte[] frameData, int functionCodeOffset) : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.inputCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                if (this.inputCount == 1)
                    return (this.startAddress + 1).ToString();
                else if (this.inputCount > 1)
                    return (this.startAddress + 1).ToString() + "-" + (this.startAddress + this.inputCount).ToString();
                else
                    return "";
            }
        }

        /// <summary>
        /// Responses with function code 1,2,3,4
        /// </summary>
        public class GenericByteCountRegisterValueResponse : AbstractModbusMessage {
            private string registerValuesHex;

            public GenericByteCountRegisterValueResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                    byte byteCount = frameData[functionCodeOffset + 1];
                    this.registerValuesHex = Utils.ByteConverter.ReadHexString(frameData, byteCount, functionCodeOffset + 2);
            }

            public override string ToString() {
                return this.registerValuesHex;
            }
        }

        /// <summary>
        /// Queries and Responses with function code 5
        /// </summary>
        public class WriteSingleCoil : AbstractModbusMessage {

            private ushort outputAddress;//0 indexed
            private ushort outputValue;

            public WriteSingleCoil(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                    this.outputAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                    this.outputValue = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                int coilAddressOneIndexed = outputAddress + 1;
                if (this.outputValue == 0x0000)
                    return coilAddressOneIndexed.ToString() + "=OFF";
                else if (this.outputValue == 0xff00)
                    return coilAddressOneIndexed.ToString() + "=ON";
                else
                    return coilAddressOneIndexed.ToString() + "=invalid (" + this.outputValue.ToString("X4") + ")";
            }
        }

        /// <summary>
        /// Request function code 15
        /// </summary>
        public class WriteMultipleCoilsRequest : AbstractModbusMessage {
            private ushort startAddress;
            private System.Collections.BitArray values;

            public WriteMultipleCoilsRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                ushort outputCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                byte byteCount = frameData[functionCodeOffset + 5];

                byte[] bytes = new byte[byteCount];
                Array.Copy(frameData, functionCodeOffset + 6, bytes, 0, bytes.Length);
                System.Collections.BitArray mask = new System.Collections.BitArray(bytes);
                this.values = new System.Collections.BitArray(outputCount);
                for (int i = 0; i < outputCount; i++)
                    this.values[i] = mask[i];
            }

            public override string ToString() {
                List<string> valueStrings = new List<string>();
                foreach (bool v in this.values)
                    if (v)
                        valueStrings.Add("1");
                    else
                        valueStrings.Add("0");

                return "Coil " + (this.startAddress + 1).ToString() + "-" + (this.startAddress + this.values.Count).ToString() + " = " + string.Join(",", valueStrings.ToArray());
            }
        }

        /// <summary>
        /// Response function code 15
        /// </summary>
        public class WriteMultipleCoilsResponse : AbstractModbusMessage {
            private ushort startAddress;
            private ushort outputsWritten;//count

            public WriteMultipleCoilsResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.outputsWritten = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                return "Forced nr. cols: " + this.outputsWritten.ToString();
            }
        }

        /// <summary>
        /// Queries with function code 20
        /// </summary>
        public class ReadFileRecordRequest : AbstractModbusMessage {

            private List<string> fileRequests;

            public ReadFileRecordRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {

                    this.fileRequests = new List<string>();

                byte byteCount = frameData[functionCodeOffset + 1];
                for (int i = 0; i < byteCount; i += 7) {
                    byte referenceType = frameData[functionCodeOffset + 2 + i];
                    ushort fileNumber = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3 + i);
                    ushort recordNumber = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5 + i);
                    ushort recordLength = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 7 + i);
                    string registerString = recordNumber.ToString();
                    if(recordLength > 1)
                        registerString = registerString + "-" + ((int)recordNumber + recordLength).ToString();
                    this.fileRequests.Add("File=" + fileNumber + " Register=" + registerString);
                }
            }

            public override string ToString() {
                return string.Join("; ", fileRequests.ToArray());
            }
        }

        /// <summary>
        /// Responses with function code 20
        /// </summary>
        public class ReadFileRecordResponse : AbstractModbusMessage {

            List<List<ushort>> fileList = new List<List<ushort>>();

            public ReadFileRecordResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                byte responseDataLength = frameData[functionCodeOffset + 1];
                int offset = functionCodeOffset + 2;
                while(offset < functionCodeOffset + 2 + responseDataLength) {
                    List<ushort> fileData = new List<ushort>();
                    byte fileResponseLength = frameData[offset++];
                    byte referenceType = frameData[offset];//should be 6
                    for(int i=1; i<fileResponseLength; i+=2)
                        fileData.Add(Utils.ByteConverter.ToUInt16(frameData, offset + i));
                    this.fileList.Add(fileData);
                    offset += fileResponseLength;
                }
            }

            public override string ToString() {
                List<string> fileDataStringList = new List<string>();
                for (int fileNr = 0; fileNr < fileList.Count; fileNr++) {
                    List<ushort> fileData = fileList[fileNr];
                    StringBuilder sb = new StringBuilder("Group " + fileNr + " :");
                    for (int i = 0; i < fileData.Count; i++)
                        sb.Append("  " + fileData[i].ToString("X4"));
                    fileDataStringList.Add(sb.ToString());
                }
                return string.Join(";", fileDataStringList.ToArray());
            }
        }

        /// <summary>
        /// Function code 22, request and reponse
        /// </summary>
        public class MaskWriteRegister : AbstractModbusMessage {
            ushort referenceAddress;
            ushort andMask;
            ushort orMask;

            public MaskWriteRegister(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.referenceAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.andMask = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                this.orMask = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5);
            }

            public override string ToString() {
                return "Register=" + (referenceAddress + 1).ToString() + " AND=" + andMask.ToString("X4") + " OR=" + orMask.ToString("X4");
            }
        }

        /// <summary>
        /// Function code 24 - Request
        /// </summary>
        public class ReadFifoQueueRequest : AbstractModbusMessage {
            ushort address;

            public ReadFifoQueueRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.address = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
            }

            public override string ToString() {
                return address.ToString();
            }
        }

        /// <summary>
        /// Function code 24 - Response
        /// </summary>
        public class ReadFifoQueueResponse : AbstractModbusMessage {
            ushort[] values;

            public ReadFifoQueueResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                ushort byteCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                ushort fifoCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                values = new ushort[fifoCount];

                for (int i = 0; i < fifoCount && i < byteCount / 2 - 1; i++) {
                    values[i] = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5 + i * 2);
                }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                foreach (ushort value in this.values)
                    sb.Append(value.ToString("X4") + " ");
                return sb.ToString().TrimEnd();
            }
        }

        public class ReportSlaveIdResponse : AbstractModbusMessage {
            string slaveIdPrintable, slaveIdHex;

            public ReportSlaveIdResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                ushort byteCount = frameData[functionCodeOffset + 1];
                this.slaveIdHex = Utils.ByteConverter.ReadHexString(frameData, byteCount, functionCodeOffset + 2);
                this.slaveIdPrintable = Utils.ByteConverter.ReadString(frameData, functionCodeOffset + 2, byteCount, "");
            }

            public override string ToString() {
                if (slaveIdPrintable.Length > 0)
                    return this.slaveIdPrintable + " (" + this.slaveIdHex + ")";
                else
                    return this.slaveIdHex;
            }
        }

        public class ExceptionResponse : AbstractModbusMessage {
            private byte exceptionCode;

            public ExceptionResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                if((int)base.functionCode > 0x80)
                    base.functionCode = (FunctionCodeEnum)(base.functionCode - 0x80);
                this.exceptionCode = frameData[functionCodeOffset + 1];
            }

            public override string ToString() {
                return ("Exception: " + (ExceptionCodeEnum)this.exceptionCode).ToString();
            }
        }

        public class UnknownFunction : AbstractModbusMessage {
            private string payloadHex;

            public UnknownFunction(byte[] frameData, int functionCodeOffset, ushort length)
                : base(frameData, functionCodeOffset) {
                int payloadLength = length - 2;//remove slave address and function code from payload
                if (length > 0 && payloadLength <= frameData.Length)
                    this.payloadHex = Utils.ByteConverter.ReadHexString(frameData, payloadLength, functionCodeOffset + 1);
                else
                    this.payloadHex = "";
            }

            public override string ToString() {
                return this.payloadHex;
            }
        }

        

        public enum FunctionCodeEnum : byte {
	        ReadDiscreteInputs = 2,//single bit access
            ReadCoils = 1,//single bit access
            WriteSingleCoil = 5,//single bit access
            WriteMultipleCoils = 15,//single bit access

	        ReadInputRegisters = 4,//16-bit
            ReadHoldingRegisters = 3,//16-bit
            WriteSingleRegister = 6,//16-bit
            WriteMultipleRegisters = 16,//16-bit
            ReadWriteMultipleRegisters = 23,//16-bit
            MaskWriteRegister = 22,//16-bit
            ReadFIFOQueue = 24,//16-bit

            ReadFileRecord = 20,//file
            WriteFileRecord = 21,//file

            Read_Exception_Status = 7,//Diagnostics
            Diagnostic = 8,//Diagnostics
            GetComEventCounter = 11,//Diagnostics
            GetComEventLog = 12,//Diagnostics
            ReportSlaveID = 17,//Diagnostics
            ReadDeviceIdentification = 43,//Diagnostics

            Program484 = 9,
            Poll383 = 10,
            ProgramController = 13,
            PollController = 14,
            Program_884_M84 = 18,
            ResetCommLink = 19,

            Program584_984 = 126,

            EncapsulatedInterfaceTransport=43//other
        }
        public enum ExceptionCodeEnum : byte {
	        IllegalFunction                    = 1,
	        IllegalDataAddress                 = 2,
	        IllegalDataValue                   = 3,
	        ServerDeviceFailure                = 4,
	        Acknowledge                        = 5,
	        ServerDeviceBusy                   = 6,
	        MemoryParityError                  = 8,
	        GatewayPathUnavailable             = 10,
	        GatewayTargetDeviceFailedToRespond = 11
        }

        private ushort transactionId;
        private const ushort MODBUS_TCP_PROTOCOL_ID = 0;
        private ushort length;//remaining bytes in this frame
        private byte slaveAddress;//255 if not used aka "unit identifier
        private byte functionCode;
        //private ushort? startingAddress=null;//as sent on the wire (0-indexed)
        //private ushort? nRegistersToRead = null;
        private bool isReponse = false;
        //private AbstractResponseMessage responseMessage = null;
        private AbstractModbusMessage modbusMessage;
        internal List<string> Anomalies;

        internal const int MIN_FRAME_LENGTH = 7;

        public ushort TransactionID { get { return this.transactionId; } }
        public byte SlaveAddress { get { return this.slaveAddress; } }
        public byte FunctionCode {
            get {
                if (this.modbusMessage != null)
                    return (byte)this.modbusMessage.FunctionCode;//in order to handle exceptions where function code should be reduced by 0x80
                else
                    return this.functionCode;
            }
        }
        internal FunctionCodeEnum FunctionCodeName { get { return (FunctionCodeEnum)this.FunctionCode; } }
        public ushort Length { get { return this.length; } }
        //public ushort? StartingAddress { get { return this.startingAddress; } }
        //public ushort? NRegistersToRead { get { return this.nRegistersToRead; } }
        public bool IsResponse { get { return this.isReponse; } }
        //public AbstractResponseMessage ResponseMessage { get { return this.responseMessage; } }
        public AbstractModbusMessage ModbusMessage { get { return this.modbusMessage; } }

        

        [Obsolete("Please use overload with TCP port numbers instead", true)]
        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            throw new Exception("Not implemented");
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result) {
            result = null;
            try {
                if (packetEndIndex - packetStartIndex + 1 >= MIN_FRAME_LENGTH && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false) == MODBUS_TCP_PROTOCOL_ID) {
                    result = new ModbusTcpPacket(parentFrame, packetStartIndex, packetEndIndex, sourcePort, destinationPort);
                    return true;
                }
                else
                    return false;
            } catch {
                return false;
            }
        }

        internal ModbusTcpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Modbus/TCP") {
                this.Anomalies = new List<string>();

                if (packetEndIndex - packetStartIndex + 1 >= MIN_FRAME_LENGTH && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false) == MODBUS_TCP_PROTOCOL_ID) {
                    this.transactionId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, false);
                    this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4, false);
                    //TODO check if the whole length fits inside the TCP packet's payload.
                    if (length + packetStartIndex + 4 > parentFrame.Data.Length)
                        this.Anomalies.Add("Modbus length is larger than the received frame");
                    //There might also be several Modbus frames.
                    if (sourcePort == 502 && destinationPort != 502)
                        this.isReponse = true;
                    else if (sourcePort == 502 && this.length != 6)
                        this.isReponse = true;
                    else
                        this.isReponse = false;//this is a query
                    
                    if (length >= 2) {
                        this.slaveAddress = parentFrame.Data[packetStartIndex + 6];
                        this.functionCode = parentFrame.Data[packetStartIndex + 7];

                        if (this.isReponse) {

                            if (this.functionCode == 1 || this.functionCode == 2 || this.functionCode == 3 || this.functionCode == 4)
                                this.modbusMessage = new GenericByteCountRegisterValueResponse(parentFrame.Data, packetStartIndex + 7);
                            else if (this.FunctionCode == 5)
                                this.modbusMessage = new WriteSingleCoil(parentFrame.Data, packetStartIndex + 7);
                            else if (this.functionCode == 15)
                                this.modbusMessage = new WriteMultipleCoilsResponse(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 17)
                                this.modbusMessage = new ReportSlaveIdResponse(parentFrame.Data, packetStartIndex + 7);
                            else if (this.functionCode == 20)
                                this.modbusMessage = new ReadFileRecordResponse(parentFrame.Data, packetStartIndex + 7);
                            else if (this.functionCode == 22)//22
                                this.modbusMessage = new MaskWriteRegister(parentFrame.Data, packetStartIndex + 7);
                            else if (this.functionCode == 24)//24
                                this.modbusMessage = new ReadFifoQueueResponse(parentFrame.Data, packetStartIndex + 7);
                            else if (this.functionCode >= 0x80)//exception
                                this.modbusMessage = new ExceptionResponse(parentFrame.Data, packetStartIndex + 7);
                            else
                                this.modbusMessage = new UnknownFunction(parentFrame.Data, packetStartIndex + 7, length);
                        }
                        else {//QUERY

                            if (functionCode >= 1 && functionCode <= 4)
                                this.modbusMessage = new GenericAddressAndInputCountRequest(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 5)
                                this.modbusMessage = new WriteSingleCoil(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 15)
                                this.modbusMessage = new WriteMultipleCoilsRequest(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 20)
                                this.modbusMessage = new ReadFileRecordRequest(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 22)
                                this.modbusMessage = new MaskWriteRegister(parentFrame.Data, packetStartIndex + 7);
                            else if (functionCode == 24)
                                this.modbusMessage = new ReadFifoQueueRequest(parentFrame.Data, packetStartIndex + 7);
                            else
                                this.modbusMessage = new UnknownFunction(parentFrame.Data, packetStartIndex + 7, length);
                            //this.startingAddress = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8, false);
                            //this.nRegistersToRead = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 10, false);
                        }
                    }
                
                }
        }

        
        

        public bool PacketHeaderIsComplete {
            get { throw new NotImplementedException(); }
        }

        public int ParsedBytesCount {
            get { throw new NotImplementedException(); }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                 yield break;
        }

    }
}
