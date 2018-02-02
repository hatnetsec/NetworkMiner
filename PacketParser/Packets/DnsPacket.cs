//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //DNS
    //http://www.ietf.org/rfc/rfc1035.txt
    public class DnsPacket : AbstractPacket {
        public enum RRTypes : uint { HostAddress=0x0001, CNAME=0x0005, DomainNamePointer=0x000c, NB=0x0020, NBSTAT=0x0021 }



        /// <summary>
        /// Can retrieve a Name Label even when an offset pointer is used rather than a direct name label. Also handles combinations (such as CNAME's) of direct labels and referrers.
        /// </summary>
        /// <param name="data">The frame data in bytes</param>
        /// <param name="packetStartIndex">The start position in data of the DNS packet</param>
        /// <param name="labelStartOffset">The offset in the DNS packet where the label (or label referrer) is located</param>
        /// <returns>The extracted label</returns>
        public static List<NameLabel> GetNameLabelList(byte[] data, int packetStartIndex, int labelStartOffset, out int typeStartOffset) {
            const int TTL = 20;//max 20 iterations before generating an Exception
            return GetNameLabelList(data, packetStartIndex, labelStartOffset, TTL, out typeStartOffset);
        }

        public static List<NameLabel> GetNameLabelList(byte[] data, int packetStartIndex, int labelStartOffset, int ttl, out int typeStartOffset) {
            if (ttl <= 0)
                throw new Exception("DNS Name Label contains a pointer that loops");
            int qNameByteCount=0;
            typeStartOffset=labelStartOffset;
            List<NameLabel> nameLabels=new List<NameLabel>();
            while(data[packetStartIndex+labelStartOffset+qNameByteCount]!=0x00 && data[packetStartIndex+labelStartOffset+qNameByteCount]<64 && qNameByteCount<=255) {
                NameLabel label=new NameLabel(data, packetStartIndex+labelStartOffset+qNameByteCount);
                if(label.LabelByteCount>0) {//we have a label
                    qNameByteCount+=label.LabelByteCount+1;
                    nameLabels.Add(label);
                    typeStartOffset=labelStartOffset+qNameByteCount;
                }
                else {

                    break;
                }
            }
            if(data[packetStartIndex+labelStartOffset+qNameByteCount]==0x00)
                typeStartOffset++;//move past the last 0x00 terminator
            else if(data[packetStartIndex+labelStartOffset+qNameByteCount]>=192){//we should jump to another location
                ushort labelOffset = Utils.ByteConverter.ToUInt16(data, packetStartIndex + labelStartOffset + qNameByteCount);//denna kan komma utanför offseten!
                labelOffset=(ushort)(labelOffset&0x3fff);//mask the first 2 bits (they should be ones)
                int tmp;
                nameLabels.AddRange(GetNameLabelList(data, packetStartIndex, labelOffset, ttl-1, out tmp));
                typeStartOffset+=2;
            }
            return nameLabels;
        }

        //header
        private ushort transactionID;

        private HeaderFlags headerFlags;
        private ushort questionCount;//Unsigned 16 bit integer specifying the number of entries in the question section of a Name
        private ushort answerCount;
        private ushort nameServerCount;
        private ushort additionalCount;

        //question section
        private int questionSectionByteCount;
        //internal byte[] questionName;//ends with 0x00 (usually starts with 0x20)
        private string[] questionNameDecoded;
        private ushort questionType;//NB == 0x0020, NBSTAT == 0x0021, Domain Name Pointer=0x000c
        private ushort questionClass;//Internet Class: 0x0001

        private ResourceRecord[] answerRecords;

        public ushort TransactionId { get { return this.transactionID; } }
        public HeaderFlags Flags { get { return this.headerFlags; } }
        public ResourceRecord[] AnswerRecords { get { return this.answerRecords; } }
        public string QueriedDnsName {
            get {
                if(questionCount>0) {
                    if(questionNameDecoded!=null && questionNameDecoded.Length>0) {
                        StringBuilder sb=new StringBuilder();
                        for(int i=0; i<questionNameDecoded.Length; i++) {
                            if(i>0)
                                sb.Append(".");
                            sb.Append(questionNameDecoded[i]);
                        }
                        return sb.ToString();
                    }
                    else
                        return null;
                }
                else
                    return null;
            }
        }
        //answer

        //authority

        //additional


        internal DnsPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "DNS") {
            
            //header
            this.transactionID = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            this.headerFlags = new HeaderFlags(Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2));
            if (!this.ParentFrame.QuickParse) {
                if (this.headerFlags.Response)
                    this.Attributes.Add("Type", "Response");
                else
                    this.Attributes.Add("Type", "Request");
                if (this.headerFlags.OperationCode == (byte)HeaderFlags.OperationCodes.Query)
                    this.Attributes.Add("Operation", "Standard Query");
                else if (this.headerFlags.OperationCode == (byte)HeaderFlags.OperationCodes.InverseQuery)
                    this.Attributes.Add("Operation", "Inverse Query");
            }

            //NetworkMiner currently does not handle Dynamic Update (operation code 5)
            if(this.headerFlags.OperationCode < 5) {

                this.questionCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                this.answerCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                this.answerRecords=new ResourceRecord[answerCount];

                if(questionCount>0) {
                    //this.questionSectionByteCount=0;

                    //List<NameLabel> nameLabelList=GetNameLabelList(parentFrame.Data, packetStartIndex+12);
                    int typeStartOffset;
                    List<NameLabel> nameLabelList=GetNameLabelList(parentFrame.Data, packetStartIndex, 12, out typeStartOffset);
                    /*
                    foreach(NameLabel label in nameLabelList) {
                        questionSectionByteCount+=label.LabelByteCount+1;
                    }
                     * */


                    //this.questionSectionByteCount++;//add the last 0x00 terminator
                    this.questionSectionByteCount=typeStartOffset-12;

                    //we have now decoded the name!
                    this.questionNameDecoded=new string[nameLabelList.Count];
                    for(int i=0; i<nameLabelList.Count; i++)
                        this.questionNameDecoded[i]=nameLabelList[i].ToString();
                    
                    //this.questionType=ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex+12+questionSectionByteCount);
                    this.questionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + typeStartOffset);
                    questionSectionByteCount+=2;
                    //this.questionClass=ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex+12+questionSectionByteCount);
                    this.questionClass = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + typeStartOffset + 2);
                    questionSectionByteCount+=2;
                }
                else {
                    this.questionSectionByteCount=0;
                    this.questionNameDecoded=null;
                }
                //ANSWER RESOURCE RECORDS
                int packetPositionIndex=packetStartIndex+12+questionSectionByteCount;
                for(int i=0; i<answerRecords.Length; i++) {
                    //ResourceRecord answerRecord in answerRecords) {
                    answerRecords[i]=new ResourceRecord(this, packetPositionIndex);
                    packetPositionIndex+=answerRecords[i].ByteCount;


                    //decodedName.ToString();
                    if (!this.ParentFrame.QuickParse) {
                        if (answerRecords[i].Type == (ushort)RRTypes.HostAddress) {
                            if (answerRecords[i].IP != null)
                                this.Attributes.Add("IP", answerRecords[i].IP.ToString());
                            if (answerRecords[i].DNS != null)
                                this.Attributes.Add("DNS", answerRecords[i].DNS);
                        }
                    }
                }
                //AUTHORITY RESOURCE RECORDS    
                //I'll just skip the rest of the packet!
            }

        }

   
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //Do nothing, no known sub packets...
            yield break;
        }


        public class HeaderFlags {
            internal enum OperationCodes : byte { Query=0, InverseQuery=1, ServerStatusRequest=2 };
            internal enum ResultCodes : byte { NoErrorCondition=0, FormatError=1, ServerFailure=2, NameError_NXDOMAIN=3, NotImplemented=4, Refused=5 };

            private ushort headerData;
            //private static uint OpcodeMask=0x7000;

            internal bool Response { get { return ((headerData>>15)==1); } }
            internal byte OperationCode { get { return (byte)((headerData>>11)&0x000F); } }//nibble
            internal bool Truncated { get { return (headerData>>9)==1; } }
            internal bool RecursionDesired { get { return (headerData>>8)==1; } }
            //internal byte NmFlags { get { return (byte)((headerData>>4)&0x007F); } }//from netbios
            internal byte ResultCode { get { return (byte)(headerData&0x000F); } }//nibble

            internal HeaderFlags(ushort value) {
                this.headerData=value;
            }

            public override string ToString() {
                return this.headerData.ToString("X4");
            }
            public string ToString(string format) {
                return this.headerData.ToString(format);
            }
        }

        public class NameLabel {
            //private byte[] sourceData;
            private int labelStartPosition;//the position
            private byte labelByteCount;
            private StringBuilder decodedName;

            internal byte LabelByteCount { get { return this.labelByteCount; } }//if this is zero wh have a terminator
            public override string ToString() {
                return decodedName.ToString();
            }

            internal NameLabel(byte[] sourceData, int labelStartPosition) {
                this.labelStartPosition=labelStartPosition;
                //this.labelByteCount=0;
                this.decodedName=new StringBuilder();

                labelByteCount=sourceData[labelStartPosition];//max 63
                if(labelByteCount>63)
                    throw new Exception("DNS Name label is larger than 63 : "+labelByteCount+" at position "+labelStartPosition);
                    //labelByteCount=63;//NO! of the first two bits are 1:s we will have to go somewhere else! See RFC-1035 3.1 "Name space definitions"
                
                else
                    for(byte b=0; b<labelByteCount; b++)
                        decodedName.Append((char)sourceData[labelStartPosition+1+b]);
            }

        }

        public interface IDnsResponseInfo {
            DnsPacket ParentPacket { get; }
            string DNS { get; }
            TimeSpan TimeToLive { get; }
            System.Net.IPAddress IP { get; }
            string PrimaryName { get; }
            ushort Type { get; }
        }

        public class ResponseWithErrorCode : IDnsResponseInfo {

            private DnsPacket parentPacket;
            private string queriedDns = null;

            public DnsPacket ParentPacket {
                get { return this.parentPacket; }
            }

            public string DNS {
                get { return this.parentPacket.QueriedDnsName; }
            }

            public TimeSpan TimeToLive {
                get { return new TimeSpan(0); }
            }

            public System.Net.IPAddress IP {
                get { return null; }
            }

            public string PrimaryName {
                get { return null; }
            }

            public ushort Type {
                get { return 0; }
            }

            public string GetResultCodeString() {
                return this.RCode() + " (flags 0x" + this.parentPacket.Flags.ToString() + ")";
            }

            public string RCode() {
                //http://www.ietf.org/rfc/rfc1035.txt


                byte rcode = parentPacket.Flags.ResultCode;

                if (rcode == 0) return "No error condition";
                else if (rcode == 1) return "Format error";
                else if (rcode == 2) return "SERVFAIL";//Server failure according to RFC 1035
                else if (rcode == 3) return "NXDOMAIN";//Name Error according to RFC 1035
                else if (rcode == 4) return "Not Implemented";
                else if (rcode == 5) return "Refused";
                else return "UNDEFINED RCODE";
                        
            }

            public ResponseWithErrorCode(DnsPacket parentPacket) {
                this.parentPacket = parentPacket;
               
            }
        }

        public class ResourceRecord : IDnsResponseInfo  {//for example answers/replies
            private string[] answerRequestedNameDecoded;
            private ushort answerType;//NB == 0x0020, NBSTAT == 0x0021, Domain Name Pointer=0x000c, Host address=0x0001
            private ushort answerClass;//Internet Class: 0x0001
            private uint answerTimeToLive;//seconds
            private ushort answerDataLength;
            private string[] answerRepliedNameDecoded;
            private DnsPacket parentPacket;
            private int recordByteCount;//number of bytes...

            public DnsPacket ParentPacket { get { return this.parentPacket; } }
            public ushort Type { get { return this.answerType; } }
            public TimeSpan TimeToLive { get { return new TimeSpan(0, 0, (int)answerTimeToLive); } }
            public int ByteCount { get { return this.recordByteCount; } }
            public System.Net.IPAddress IP {
                //kolla antingen answerType eller OPCODE i headerFlags

                get {
                    //if(this.questionType
                    if(parentPacket.headerFlags.OperationCode==(byte)HeaderFlags.OperationCodes.Query && this.answerType==(ushort)RRTypes.HostAddress) {//request=IP
                        try {
                            byte[] ip=new byte[4];
                            for(int i=0; i<4; i++)
                                ip[i]=Convert.ToByte(answerRepliedNameDecoded[i]);//detta kan vara fel!?
                            return new System.Net.IPAddress(ip);
                        }
                        catch {
                            return null;
                        }
                    }
                    else if(parentPacket.headerFlags.OperationCode==(byte)HeaderFlags.OperationCodes.InverseQuery) {//den har datat som typ 154.23.233.11.int-adr.arpa.net
                        try {
                            byte[] ip=new byte[4];
                            for(int i=0; i<4; i++)
                                ip[i]=Convert.ToByte(answerRequestedNameDecoded[i]);//detta kan vara fel!?
                            return new System.Net.IPAddress(ip);
                        }
                        catch {
                            return null;
                        }
                    }
                    else
                        return null;
                }
            }
            public string PrimaryName {//Instead of IP for CNAME packets
                get {
                    if(answerType==(ushort)RRTypes.CNAME) {
                        if(answerRepliedNameDecoded!=null && answerRepliedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i<answerRepliedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(answerRepliedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;

                    }
                    else
                        return null;
                }
            }
            public string DNS {
                //kolla antingen answerType eller OPCODE i headerFlags
                get {
                    if(parentPacket.headerFlags.OperationCode==(byte)HeaderFlags.OperationCodes.Query) {
                        if(answerRequestedNameDecoded!=null && answerRequestedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i<answerRequestedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(answerRequestedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;
                    }
                    else if(parentPacket.headerFlags.OperationCode==(byte)HeaderFlags.OperationCodes.InverseQuery) {//request=IP
                        if(answerRepliedNameDecoded!=null && answerRepliedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i<answerRepliedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(answerRepliedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;
                    }
                    else
                        return null;
                }

            }

            public ResourceRecord(DnsPacket parentPacket, int startIndex) {
                this.parentPacket=parentPacket;
                int typeStartOffset;
                List<NameLabel> nameLabelList=GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex-parentPacket.PacketStartIndex, out typeStartOffset);

                this.answerRequestedNameDecoded=new string[nameLabelList.Count];
                for(int i=0; i<nameLabelList.Count; i++)
                    this.answerRequestedNameDecoded[i]=nameLabelList[i].ToString();
                /*
                this.answerType=ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex+2);
                this.answerClass=ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex+4);
                this.answerTimeToLive=ByteConverter.ToUInt32(parentPacket.ParentFrame.Data, startIndex+6);
                this.answerDataLength=ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex+10);
                */
                this.answerType = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset);
                this.answerClass = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 2);
                this.answerTimeToLive = Utils.ByteConverter.ToUInt32(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 4);
                this.answerDataLength = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 8);

                //this.recordByteCount=12+answerDataLength;
                this.recordByteCount=typeStartOffset-startIndex+parentPacket.PacketStartIndex+10+answerDataLength;


                //kolla....
                if (parentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.Query && this.answerType != (ushort)RRTypes.CNAME) {
                    this.answerRepliedNameDecoded = new string[answerDataLength];
                    for (int i = 0; i < answerDataLength; i++) {
                        //this.answerRepliedNameDecoded[i] = parentPacket.ParentFrame.Data[startIndex + 12 + i].ToString();
                        this.answerRepliedNameDecoded[i] = parentPacket.ParentFrame.Data[startIndex + this.recordByteCount - answerDataLength + i].ToString();//the answer is at the end
                    }
                }
                else if (parentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.Query && this.answerType == (ushort)RRTypes.CNAME) {
                    //List<NameLabel> answerRepliedName = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + 12 - parentPacket.PacketStartIndex, out typeStartOffset);
                    List<NameLabel> answerRepliedName = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + this.recordByteCount - answerDataLength - parentPacket.PacketStartIndex, out typeStartOffset);

                    this.answerRepliedNameDecoded = new string[answerRepliedName.Count];
                    for (int i = 0; i < answerRepliedName.Count; i++)
                        this.answerRepliedNameDecoded[i] = answerRepliedName[i].ToString();
                }
                else if (parentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.InverseQuery) {
                    //nameLabelList=GetNameLabelList(parentPacket.ParentFrame.Data, startIndex+12);
                    nameLabelList = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + 12 - parentPacket.PacketStartIndex, out typeStartOffset);

                    this.answerRepliedNameDecoded = new string[nameLabelList.Count];
                    for (int i = 0; i < nameLabelList.Count; i++)
                        this.answerRepliedNameDecoded[i] = nameLabelList[i].ToString();
                }

            }
        }
    }
}
