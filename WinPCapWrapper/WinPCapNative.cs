//Credit: Nicolas
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NetworkWrapper
{
    /// <summary>
    /// Winpcap Wrapper class
    /// </summary>
    public class WinPCapNative
    {
        internal const int INFINITE = -1;
        internal const string PCAP_NAME_PREFIX = @"\Device\NPF_";
        internal const uint PCAP_IF_LOOPBACK = 0x00000001;
        internal const int MAX_ADAPTER_NAME_LENGTH = 256;
        internal const int MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
        internal const int MAX_PACKET_SIZE = 65536;
        internal const int PCAP_ERRBUF_SIZE = 256;
        internal const int PCAP_BUF_SIZE = 1024;
        internal const int MODE_CAPT = 0;
        internal const int MODE_STAT = 1;
        internal const string PCAP_SRC_IF_STRING = "rpcap://";
        internal const int PCAP_SRC_FILE = 2;
        internal const int PCAP_SRC_IFLOCAL = 3;
        internal const int PCAP_SRC_IFREMOTE = 4;
        internal const int PCAP_OPENFLAG_PROMISCUOUS = 1;

#if !MONO

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_breakloop(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_close(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_compile(IntPtr p, IntPtr fp, string str, int optimize, uint netmask);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, IntPtr program, string buf, int optimize, uint mask);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_createsrcstr(StringBuilder source, int type, string host, string port, string name, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_datalink(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_datalink_name_to_val(string name);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_datalink_val_to_description(int dlt);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_datalink_val_to_name(int dlt);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_dump(IntPtr user, IntPtr h, IntPtr sp);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_dump_close(IntPtr p);

        [Obsolete("Deprecated due to incompatibilities between the C Runtime used to compile WinPcap")]
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_dump_file(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_dump_flush(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern long pcap_dump_ftell(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_dump_open(IntPtr p, string name);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_file(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
        internal static extern int pcap_findalldevs(ref IntPtr alldevsp, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_findalldevs_ex(string source, IntPtr auth, ref IntPtr alldevs, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_freealldevs(IntPtr alldevsp);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_freecode(IntPtr fp);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_geterr(IntPtr p);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_getevent(IntPtr p);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_getnonblock(IntPtr p, string errbuf);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_is_swapped(IntPtr p);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern string pcap_lib_version();

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_list_datalinks(IntPtr p, ref IntPtr dlt_buf);

        [Obsolete("This function does not work in current version of WinPcap.")]
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_live_dump(IntPtr p, string filename, int maxsize, int maxpacks);

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_live_dump_ended(IntPtr p, int sync);

        [Obsolete("Use pcap_findalldevs() or pcap_findalldevs_ex() instead.")]
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern string pcap_lookupdev(string errbuf);

        [Obsolete("Use pcap_findalldevs() or pcap_findalldevs_ex() instead.")]
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_lookupnet(string device, uint netp, uint maskp, string errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_loop(IntPtr p, int cnt, dispatcher_handler callback, IntPtr user);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_major_version(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_minor_version(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_next(IntPtr p, IntPtr h);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_next_ex(IntPtr p, ref IntPtr pkt_header, ref IntPtr pkt_data);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern bool pcap_offilne_filter(IntPtr prog, IntPtr header, int pkt_data);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open(string source, int snaplen, int flags, int read_timeout, IntPtr auth, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open_dead(int linktype, int snaplen);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open_offline(string fname, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_parsesrctr(string source, IntPtr type, string host, string port, string name, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_geterror(IntPtr p, string prefix);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern UIntPtr pcap_remoteact_accept(string address, string port, string hostlist, string connectinghost, IntPtr auth, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_remoteact_cleanup();

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_remoteact_close(string host, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_remoteact_list(string address, string sep, int size, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_sendpacket(IntPtr p, System.Byte[] buf, int size);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_sendqueue_alloc(uint memsize);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern void pcap_sendqueue_destroy(IntPtr queue);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_sendqueue_queue(IntPtr queue, IntPtr pkt_header, IntPtr pkt_data);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern uint pcap_sendqueue_transmit(IntPtr p, IntPtr queue, int sync);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_set_datalink(IntPtr p, int dlt);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_setbuff(IntPtr p, int dim);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="p">pcap handle</param>
        /// <param name="fp">BPF filter</param>
        /// <returns></returns>
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_setfilter(IntPtr p, IntPtr fp);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_setmintocopy(IntPtr p, int size);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_setmode(IntPtr p, int mode);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_setnonblock(IntPtr p, int nonblock, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_setsampling(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_snapshot(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_stats(IntPtr p, IntPtr ps);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_stats_ex(IntPtr p, IntPtr pcap_stat_size);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern string pcap_strerror(int error);

#endif

        public enum PCAP_NEXT_EX_STATE
        {
            SUCCESS = 1,
            TIMEOUT = 0,
            ERROR = -1,
            EOF = -2,
            UNKNOWN = -3,
        }

        internal delegate void dispatcher_handler(IntPtr user, IntPtr header, IntPtr pkt_data);
        public delegate void PacketArrivalEventHandler(object sender, PcapHeader p, System.Byte[] s);
        public delegate void EndCaptureEventHandler(object sender);

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_pkthdr
        {
            public WinPCapWrapper.timeval ts;
            public int caplen;
            public int len;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_stat
        {
            public uint ps_recv;
            public uint ps_drop;
            public uint ps_ifdrop;
            public uint bs_capt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_if
        {
            public IntPtr next;
            public string name;
            public string description;
            public IntPtr addresses;
            public uint flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_addr
        {
            public IntPtr next;
            public IntPtr addr;
            public IntPtr netmask;
            public IntPtr broadaddr;
            public IntPtr dstaddr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct bpf_program
        {
            public uint bf_len;
            public IntPtr bf_insns;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct timeval
        {
            public UInt32 tv_sec;
            public UInt32 tv_usec;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_rmtauth
        {
            private int type;
            private string username;
            private string password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct in_addr
        {
            public char b1;
            public char b2;
            public char b3;
            public char b4;
            public UInt16 w1;
            public UInt16 w2;
            public UInt64 addr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct sockaddr
        {
            public short family;
            public UInt16 port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=4)]
            public System.Byte[] addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)]
            public System.Byte[] zero;
        }
    
    }
}
