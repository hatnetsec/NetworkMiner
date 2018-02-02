//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Collections;


namespace NetworkWrapper {

    /// <summary>
    /// Based on:
    /// "Packet sniffing with Winpcap functions ported to a .NET library"
    /// By Victor Tan. 
    /// 
    /// http://www.codeproject.com/dotnet/dotnetwinpcap.asp
    /// </summary>
    public class WinPCapSniffer: ISniffer {

        public enum DataLinkType : uint {
            WTAP_ENCAP_NULL=0,/* null encapsulation */
            WTAP_ENCAP_ETHERNET=1,
            WTAP_ENCAP_TOKEN_RING=6,/* IEEE 802 Networks - assume token ring */
            WTAP_ENCAP_ARCNET=7,
            WTAP_ENCAP_SLIP=8,
            WTAP_ENCAP_PPP=9,
            WTAP_ENCAP_FDDI=10,
            WTAP_ENCAP_REDBACK=32,
            WTAP_ENCAP_PPP_2=50,
            WTAP_ENCAP_SYMANTEC=99,/* Apparently used by the Axent Raptor firewall (now Symantec Enterprise Firewall). */
            WTAP_ENCAP_ATM_RFC1483=100,/*libpcap 0.5 and later*/
            WTAP_ENCAP_RAW_IP=101,
            WTAP_ENCAP_SLIP_BSDOS=102,
            WTAP_ENCAP_PPP_BSDOS=103,
            WTAP_ENCAP_CHDLC=104,/* Cisco HDLC */
            WTAP_ENCAP_IEEE_802_11=105, /* IEEE 802.11 */
            WTAP_ENCAP_LINUX_ATM_CLIP=106,
            WTAP_ENCAP_FRELAY=107,/* Frame Relay */
            WTAP_ENCAP_NULL_2=108,	/* OpenBSD loopback */
            WTAP_ENCAP_ENC=109,	/* OpenBSD IPSEC enc */
            WTAP_ENCAP_LANE_802_3=110,/* ATM LANE 802.3 */
            WTAP_ENCAP_HIPPI=111,	/* NetBSD HIPPI */
            WTAP_ENCAP_CHDLC_2=112,	/* NetBSD HDLC framing */

            WTAP_ENCAP_SLL=113,/* Linux cooked capture */

            WTAP_ENCAP_LOCALTALK=114,	/* Localtalk */
            WTAP_ENCAP_PFLOG=117,
            WTAP_ENCAP_CISCO_IOS=118,
            WTAP_ENCAP_PRISM_HEADER=119, /* Prism monitor mode hdr */
            WTAP_ENCAP_HHDLC=121,	/* HiPath HDLC */
            WTAP_ENCAP_IP_OVER_FC=122,   /* RFC 2625 IP-over-FC */
            WTAP_ENCAP_ATM_PDUS=123,  /* SunATM */
            WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP=127,  /* 802.11 plus radiotap WLAN header */
            WTAP_ENCAP_TZSP=128,	/* Tazmen Sniffer Protocol */
            WTAP_ENCAP_ARCNET_LINUX=129,
            WTAP_ENCAP_JUNIPER_MLPPP=130, /* Juniper MLPPP on ML-, LS-, AS- PICs */
            WTAP_ENCAP_JUNIPER_MLFR=131, /* Juniper MLFR (FRF.15) on ML-, LS-, AS- PICs */
            WTAP_ENCAP_JUNIPER_GGSN=133,
            /*
             * Values 132-134, 136 not listed here are reserved for use
             * in Juniper hardware.
             */
            WTAP_ENCAP_JUNIPER_ATM2=135, /* various encapsulations captured on the ATM2 PIC */
            WTAP_ENCAP_JUNIPER_ATM1=137, /* various encapsulations captured on the ATM1 PIC */

            WTAP_ENCAP_APPLE_IP_OVER_IEEE1394=138,
            /* Apple IP-over-IEEE 1394 */

            WTAP_ENCAP_MTP2_WITH_PHDR=139,
            WTAP_ENCAP_MTP2=140,
            WTAP_ENCAP_MTP3=141,
            WTAP_ENCAP_DOCSIS=143,
            WTAP_ENCAP_IRDA=144,	/* IrDA capture */

            /* Reserved for private use. */
            WTAP_ENCAP_USER0=147,
            WTAP_ENCAP_USER1=148,
            WTAP_ENCAP_USER2=149,
            WTAP_ENCAP_USER3=150,
            WTAP_ENCAP_USER4=151,
            WTAP_ENCAP_USER5=152,
            WTAP_ENCAP_USER6=153,
            WTAP_ENCAP_USER7=154,
            WTAP_ENCAP_USER8=155,
            WTAP_ENCAP_USER9=156,
            WTAP_ENCAP_USER10=157,
            WTAP_ENCAP_USER11=158,
            WTAP_ENCAP_USER12=159,
            WTAP_ENCAP_USER13=160,
            WTAP_ENCAP_USER14=161,
            WTAP_ENCAP_USER15=162,

            WTAP_ENCAP_IEEE_802_11_WLAN_AVS=163,  /* 802.11 plus AVS WLAN header */

            /*
             * 164 is reserved for Juniper-private chassis-internal
             * meta-information such as QoS profiles, etc..
             */

            WTAP_ENCAP_BACNET_MS_TP=165,

            /*
             * 166 is reserved for a PPP variant in which the first byte
             * of the 0xff03 header, the 0xff, is replaced by a direction
             * byte.  I don't know whether any captures look like that,
             * but it is used for some Linux IP filtering (ipfilter?).
             */

            /* Ethernet PPPoE frames captured on a service PIC */
            WTAP_ENCAP_JUNIPER_PPPOE=167,

            /*
         * 168 is reserved for more Juniper private-chassis-
         * internal meta-information.
         */

            WTAP_ENCAP_GPRS_LLC=169,

            /*
             * 170 and 171 are reserved for ITU-T G.7041/Y.1303 Generic
             * Framing Procedure.
             */

            /* Registered by Gcom, Inc. */
            WTAP_GCOM_TIE1=172,
            WTAP_GCOM_SERIAL=173,

            WTAP_ENCAP_LINUX_LAPD=177,


            WTAP_ENCAP_JUNIPER_ETHER=178, /* Ethernet frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_PPP=179,/* PPP frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_FRELAY=180,/* Frame-Relay frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_CHDLC=181,/* C-HDLC frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_VP=183,/* VOIP Frames prepended with meta-information */


            WTAP_ENCAP_USB=186,	            /* raw USB packets */
            WTAP_ENCAP_BLUETOOTH_H4=187,      /* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
            WTAP_ENCAP_IEEE802_16_MAC_CPS=188,/* IEEE 802.16 MAC Common Part Sublayer */
            WTAP_ENCAP_USB_LINUX=189,         /* USB packets with Linux-specified header */
            WTAP_ENCAP_ATM_RFC1483_2=11,
            WTAP_ENCAP_RAW_IP_2=12,
            WTAP_ENCAP_ATM_RFC1483_3=13,
            WTAP_ENCAP_RAW_IP_3=14,
            WTAP_ENCAP_LINUX_ATM_CLIP_2=16,
            WTAP_ENCAP_OLD_PFLOG=17,
            WTAP_ENCAP_LINUX_ATM_CLIP_3=18,
            WTAP_ENCAP_LINUX_ATM_CLIP_4=19
        }

        //private dotnetWinpCap wpcap;
        private WinPCapWrapper wpcap;
        private int nPacketsReceived;
        //private WinPCapAdapter adapter;
        private PacketReceivedEventArgs.PacketTypes basePacketType;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get { return this.basePacketType; } }

        public static event PacketReceivedHandler PacketReceived;

        //callback-function in order to remove packets from dotnetWinpCap
        //private void ReceivePacketListener(object sender, PacketHeader ph, byte[] data) {
        private void ReceivePacketListener(object sender, NetworkWrapper.PcapHeader ph, byte[] data) {
            nPacketsReceived++;

            //detect the DataLinkType (see PcapFileReader) to see if it is Ethernet or WLAN
            //At the moment I will just assume it is Ethernet2
            PacketReceivedEventArgs eventArgs=new PacketReceivedEventArgs(data, ph.TimeStamp, this.basePacketType);
            PacketReceived(this, eventArgs);

        }

        //constructor
        public WinPCapSniffer(WinPCapAdapter adapter) {
            

            //this.adapter=adapter;
            nPacketsReceived=0;
            //wpcap=new dotnetWinpCap();
            
            wpcap=new WinPCapWrapper();
            if(wpcap.IsOpen)
                wpcap.Close();

            //Opens an Ethernet interface with
            //source as the name of the interface obtained from a Device object,
            //snaplen is the max number of bytes to be captured from each packet,
            //flags=1 means promiscuous mode,
            //read_timeout is the blocking time of ReadNext before it returns.
            if(!wpcap.Open(adapter.NPFName, 65536, 1, 0))
                throw new Exception(wpcap.LastError);

            //sets the minimum number of bytes required to be received by the driver before
            //OnReceivePacket fires. Lowering this can increase response time,
            //but increases system calls which lowers program efficiency.
            wpcap.SetMinToCopy(100);

            WinPCapWrapper.PacketArrivalEventHandler rcvPack=new WinPCapNative.PacketArrivalEventHandler(this.ReceivePacketListener);
            //dotnetWinpCap.ReceivePacket rcvPack=new dotnetWinpCap.ReceivePacket(this.ReceivePacketListener);
            //wpcap.OnReceivePacket+=rcvPack;
            wpcap.PacketArrival+=rcvPack;

            if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_IEEE_802_11)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IEEE_802_11Packet;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_ETHERNET)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IEEE_802_11RadiotapPacket;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_RAW_IP)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_RAW_IP_2)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_RAW_IP_3)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_CHDLC)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.CiscoHDLC;
            else if(wpcap.DataLink==(int)DataLinkType.WTAP_ENCAP_SLL)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.LinuxCookedCapture;
            else if(adapter.ToString().ToLower().Contains("airpcap"))
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IEEE_802_11Packet;//could also be radiotap
            else
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;

        }
        
        //destructor
        ~WinPCapSniffer() {
            wpcap.Close();
        }

        public void StartSniffing() {
            wpcap.StartListen();
        }
        public void StopSniffing() {
            wpcap.StopListen();
            //wpcap.Close();
        }
        

    }
}
