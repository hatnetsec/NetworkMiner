//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://despotify.se/despotify/keyexchange.c
    //http://despotify.svn.sourceforge.net/viewvc/despotify/src/lib/keyexchange.c?view=markup
    //http://despotify.se/despotify/session.h
    //http://despotify.se/despotify/session.c
    class SpotifyKeyExchangePacket : AbstractPacket, ISessionPacket {

        private bool clientToServer;//if the packet is sent from client->server

        private ushort version;//DeSpotify uses 2, but later upgraded to version 3
        private ushort keyExchangePacketLength;//Total length of DeSpotify authentication packet, including random stuff at the end
        private byte clientOS;//0x00 == Windows, 0x01 == Mac OS X
        private uint clientID;//DeSpotify uses 0x01091001
        private uint clientRevision;//DeSpotify uses 42849 (0.3.11 testing, r42849)
        private byte[] random;//16 bytes of shn_encrypt() output with random key
        private byte[] publicKey;//96 bytes public key for Diffie-Hellmann
        private byte[] blob;//128 bytes blob
        private byte[] salt;//10 bytes of salt sent from server->client
        //sername length is at offset 253
        private string username;

        private const ushort CONTENT_END_USHORT=0x0140;


        public bool IsClientToServer { get { return this.clientToServer; } }
        public string ClientOperatingSystem {//only works for clientToServer packets
            get {
                if(this.clientOS==0x00)
                    return "Windows (0x00)";
                else if(this.clientOS==0x01)
                    return "Mac OS X (0x01)";
                else
                    return "(0x"+clientOS.ToString("X2")+")";
            }
        }
        public string ClientUsername { get { return this.username; } }
        public string PublicKeyHexString { get { return Utils.ByteConverter.ReadHexString(publicKey, publicKey.Length); } }


        //use this one instead of the constructor to speed things up by reducing Exceptions
        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {
            result=null;

            //start testing to see if this is a valid Spotify packet
            if(clientToServer) {
                //check if the keyExchangePacketLength equals the application data length
                ushort keyExchangePacketLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if(keyExchangePacketLength!=packetEndIndex-packetStartIndex+1)
                    return false;
                //it is now pretty probable that what we have is a spotify packet
                //but not sure enough since TDS (MS-SQL) has the length field in the same place...
                ushort version = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
                if(version!=0x02 && version!=0x03)
                    return false;
                try {
                    result=new SpotifyKeyExchangePacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                }
                catch {
                    result=null;
                }
            }
            else {
                //the best I can do with the server->client packet is to ensure that the length of the data matches what the content says it should be
                if(packetEndIndex-packetStartIndex+1<381)//from version 2
                    return false;//too short message
                //if(packetEndIndex-packetStartIndex+1>381+256+256)//from version 2
                if(packetEndIndex-packetStartIndex+1>388+256+256+4*65535)//from version 3
                    return false;//too long message

                //380+username_length+padding_length
                int v2expectedLength=-1;
                if(packetStartIndex+380+parentFrame.Data[packetStartIndex+17]<=packetEndIndex)
                    v2expectedLength=380+parentFrame.Data[packetStartIndex+17]+parentFrame.Data[packetStartIndex+380+parentFrame.Data[packetStartIndex+17]];
                int v3expectedLength=-1;
                if(packetStartIndex+0x182+1<=packetEndIndex)
                    v3expectedLength = 0x184 + parentFrame.Data[packetStartIndex + 0x17a] + parentFrame.Data[packetStartIndex + 0x17b] + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x17c) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x17e) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x180) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x182);
                //see if any of the lengths match
                if(packetEndIndex-packetStartIndex+1!=v2expectedLength && packetEndIndex-packetStartIndex+1!=v3expectedLength)
                    return false;

                try {
                    result=new SpotifyKeyExchangePacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                }
                catch {
                    result=null;
                }
            }

            if(result==null)
                return false;
            else
                return true;
        }

        private SpotifyKeyExchangePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Spotify Key Exchange") {
            this.clientToServer=clientToServer;
            
            this.random=new byte[16];
            this.publicKey=new byte[96];
            
            if(clientToServer) {//client -> server
                this.version = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
                if(this.version==0x02) {
                    this.keyExchangePacketLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                    if(packetStartIndex+this.keyExchangePacketLength-1<packetEndIndex)
                        this.PacketEndIndex=packetStartIndex+this.keyExchangePacketLength-1;
                    this.clientOS=parentFrame.Data[packetStartIndex+4];
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client OS", this.ClientOperatingSystem);
                    this.clientID = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 5);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client ID", "0x"+this.clientID.ToString("X2"));
                    this.clientRevision = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 9);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Revision", this.clientRevision.ToString());
                    Array.Copy(parentFrame.Data, packetStartIndex+13, random, 0, 16);
                    Array.Copy(parentFrame.Data, packetStartIndex+29, publicKey, 0, 96);
                    this.blob=new byte[128];
                    Array.Copy(parentFrame.Data, packetStartIndex+125, blob, 0, 128);
                    byte usernameLength=parentFrame.Data[packetStartIndex+253];
                    this.username = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex + 254, usernameLength);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Username", this.username);
                    if (Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 254 + usernameLength) != CONTENT_END_USHORT)
                        throw new Exception("Not a valid SpotifyKeyExchangePacket");
                }
                else if(this.version==0x03) {
                    this.keyExchangePacketLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                    if(packetStartIndex+this.keyExchangePacketLength-1<packetEndIndex)
                        this.PacketEndIndex=packetStartIndex+this.keyExchangePacketLength-1;
                    //4 bytes unknown
                    //4 bytes 0x00030c00
                    //client_revision
                    this.clientRevision = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 12);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Revision", this.clientRevision.ToString());
                    //4 bytes unknown
                    //4 bytes 0x01000000
                    //client_id
                    this.clientID = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 24);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client ID", "0x"+this.clientID.ToString("X2"));
                    //4 bytes unknown
                    //16 bytes client_random_16
                    //96 bytes my_pub_key
                    Array.Copy(parentFrame.Data, packetStartIndex+48, publicKey, 0, 96);
                    //128? bytes rsa_pub_exp
                    //length of random data
                    //int randomDataLengthIndex=packetStartIndex+24+4+4+16+96+128;//=si+272
                    byte randomDataLength=parentFrame.Data[packetStartIndex+272];
                    //username length
                    byte usernameLength=parentFrame.Data[packetStartIndex+273];
                    //2 bytes 0x0100
                    //skip random data...
                    //username
                    this.username = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex + 276 + randomDataLength, usernameLength);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Username", this.username);
                    //skip the last byte (unknown)
                }
            }
            else {//server -> client
                //figure out the version number
                int expectedVersionNumber=-1;

                //check for version 2
                if(packetStartIndex+380+parentFrame.Data[packetStartIndex+17]<=packetEndIndex && packetEndIndex-packetStartIndex+1==380+parentFrame.Data[packetStartIndex+17]+parentFrame.Data[packetStartIndex+380+parentFrame.Data[packetStartIndex+17]])
                    expectedVersionNumber=2;
                else if (packetStartIndex + 0x182 + 1 <= packetEndIndex && packetEndIndex - packetStartIndex + 1 == 0x184 + parentFrame.Data[packetStartIndex + 0x17a] + parentFrame.Data[packetStartIndex + 0x17b] + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x17c) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x17e) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x180) + Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 0x182))
                    expectedVersionNumber=3;

                if(expectedVersionNumber==2) {
                    Array.Copy(parentFrame.Data, packetStartIndex, random, 0, 16);
                    //skip puzzle denominator
                    byte usernameLength=parentFrame.Data[PacketStartIndex+17];
                    this.username = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex + 18, usernameLength);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Username", this.username);
                    Array.Copy(parentFrame.Data, packetStartIndex+18+usernameLength, publicKey, 0, 96);
                    //skip 256 bytes of random data
                    this.salt=new byte[10];
                    Array.Copy(parentFrame.Data, packetStartIndex+370+usernameLength, salt, 0, 10);
                    //skip padding length (+1)
                    //skip padding

                }
                else if(expectedVersionNumber==3) {
                    //16 bytes server_random_16
                    Array.Copy(parentFrame.Data, packetStartIndex, random, 0, 16);
                    //96 bytes remote_pub_key
                    Array.Copy(parentFrame.Data, packetStartIndex+16, publicKey, 0, 96);
                    //256 bytes random_256
                    //10 bytes salt
                    //1 byte read padding length (X=0xc0) (pos=0x17a)
                    byte paddingLength=parentFrame.Data[packetStartIndex+0x17a];
                    //1 byte username length (Y =0x08) (pos=0x17b)
                    byte usernameLength=parentFrame.Data[PacketStartIndex+0x17b];
                    //8 bytes challenge lengths (4 short challenge lengths) [6,1,1,1] (pos=0x17c)
                    //X bytes packet padding (pos = 0x184)
                    //Y bytes username (pos = 0x184+c0 = 0x244)
                    this.username = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex + 0x184 + paddingLength, usernameLength);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Client Username", this.username);
                    //? challenges (pos = 0x244+8 = 24c)
                }


                
            }
        }
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;//so sub packets
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            //get { throw new Exception("The method or operation is not implemented."); }
            get { return true; }//this is a one-frame-per-message protocol
        }

        public int ParsedBytesCount { get { return base.PacketLength; } }

        #endregion
    }
}
