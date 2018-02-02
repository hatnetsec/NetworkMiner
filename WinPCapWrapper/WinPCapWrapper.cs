//Credit: Nicolas
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NetworkWrapper
{
    public class WinPCapWrapper : WinPCapNative
    {
        private Thread ListenThread = null;
        private dispatcher_handler callback = null;
        private bool disposed = false;
        private int datalink = 0;
        private string fname = "";
        private int maxb = 0;
        private int maxp = 0;
        private bool m_islistening = false;
        private bool m_isopen = false;
        private string m_attachedDevice = null;
        private IntPtr pcap_t = IntPtr.Zero;
        private IntPtr dumper = IntPtr.Zero;
        private StringBuilder errbuf = new StringBuilder(256);

        /// <summary>
        /// Event for the arrival of a packet
        /// </summary>
        public event PacketArrivalEventHandler PacketArrival;

        /// <summary>
        /// Event for the end of the capture of a single packet
        /// </summary>
        public event EndCaptureEventHandler EndCapture;

        public virtual string AttachedDevice
        {
            get { return m_attachedDevice; }
        }
        public int DataLink
        {
            get { return datalink; }
        }
        public virtual string LastError
        {
            get { return errbuf.ToString(); }
        }
        public virtual bool IsListening
        {
            get { return m_islistening; }
        }
        public virtual bool IsOpen
        {
            get { return m_isopen; }
        }

        public static List<Device> FindAllDevs()
        {
            //ArrayList arrayList;
            List<Device> deviceList = new List<Device>();
#if !MONO


            pcap_if pcap_if;
            IntPtr i, i1;
            StringBuilder stringBuilder;
            Device device;
            pcap_addr pcap_addr;
            sockaddr sockaddr;
            sockaddr sockaddr1;
            String[] arr;

            pcap_if.addresses = IntPtr.Zero;
            pcap_if.description = new StringBuilder().ToString();
            pcap_if.flags = 0;
            pcap_if.name = new StringBuilder().ToString();
            pcap_if.next = IntPtr.Zero;
            i = IntPtr.Zero;
            i1 = IntPtr.Zero;
            stringBuilder = new StringBuilder(256);
            if (pcap_findalldevs(ref i, stringBuilder) == -1)
                return null;
            i1 = i;

            while (i.ToInt32() != 0)
            {
                device = new Device();
                deviceList.Add(device);
                pcap_if = ((pcap_if)(Marshal.PtrToStructure(i, typeof(pcap_if))));
                device.Name = pcap_if.name;
                device.Description = pcap_if.description;
                if (pcap_if.addresses.ToInt32() != 0)
                {
                    pcap_addr = ((pcap_addr)(Marshal.PtrToStructure(pcap_if.addresses, typeof(pcap_addr))));
                    if (pcap_addr.addr.ToInt32() != 0)
                    {
                        sockaddr = ((sockaddr)(Marshal.PtrToStructure(pcap_addr.addr, typeof(sockaddr))));
                        arr = new string[7];
                        arr[0] = sockaddr.addr[0].ToString();
                        arr[1] = ".";
                        arr[2] = sockaddr.addr[1].ToString();
                        arr[3] = ".";
                        arr[4] = sockaddr.addr[2].ToString();
                        arr[5] = ".";
                        arr[6] = sockaddr.addr[3].ToString();
                        device.Address = string.Concat(arr);
                    }

                    if (pcap_addr.netmask.ToInt32() != 0)
                    {
                        sockaddr1 = ((sockaddr)(Marshal.PtrToStructure(pcap_addr.netmask, typeof(sockaddr))));
                        arr = new string[7];
                        arr[0] = sockaddr1.addr[0].ToString();
                        arr[1] = ".";
                        arr[2] = sockaddr1.addr[1].ToString();
                        arr[3] = ".";
                        arr[4] = sockaddr1.addr[2].ToString();
                        arr[5] = ".";
                        arr[6] = sockaddr1.addr[3].ToString();
                        device.Netmask = string.Concat(arr);
                    }
                }

                i = pcap_if.next;
            }
            pcap_freealldevs(i1);
            //return arrayList;
#endif
            return deviceList;
        }

        public virtual bool Open(string source, int snaplen, int flags, int read_timeout)
        {
#if !MONO
            if (pcap_t != IntPtr.Zero)
            {
                throw new AlreadyOpenException();
            }

            pcap_t = pcap_open(source, snaplen, flags, read_timeout, IntPtr.Zero, errbuf);
            if (pcap_t.ToInt32() != 0)
            {
                m_isopen = true;
                m_attachedDevice = source;
                this.GetDatalink();
                return true;
            }

            m_isopen = false;
            m_attachedDevice = null;
#endif
            return false;
        }

        private void Loop()
        {
#if !MONO
            IntPtr i;
            callback = new dispatcher_handler(this.LoopCallback);
            i = IntPtr.Zero;
            new HandleRef(callback, i);
            pcap_loop(pcap_t, 0, callback, IntPtr.Zero);
            return;
#endif
        }

        private void LoopCallback(IntPtr param, IntPtr header, IntPtr pkt_data)
        {
            pcap_pkthdr pcap_pkthdr;
            System.Byte[] arr;
            Marshal.PtrToStringAnsi(param);
            pcap_pkthdr = ((pcap_pkthdr)(Marshal.PtrToStructure(header, typeof(pcap_pkthdr))));
            arr = new Byte[pcap_pkthdr.caplen];
            Marshal.Copy(pkt_data, arr, 0, pcap_pkthdr.caplen);
            Marshal.PtrToStringAnsi(pkt_data);
            return;
        }

        private bool OpenLive(string source, int snaplen, int promisc, int to_ms)
        {
#if MONO
            return false;
#else
            pcap_t = pcap_open_live(source, snaplen, promisc, to_ms, errbuf);
            if (pcap_t.ToInt32() == 0)
                return false;
            else
                return true;
#endif
        }

        private PCAP_NEXT_EX_STATE ReadNextInternal(out PcapHeader p, out System.Byte[] packet_data, out IntPtr pkthdr, out IntPtr pktdata)
        {
            pcap_pkthdr pcap_pkthdr;
            pkthdr = IntPtr.Zero;
            pktdata = IntPtr.Zero;
            p = null;
            packet_data = null;
#if MONO
            return PCAP_NEXT_EX_STATE.ERROR;
#else
            if (pcap_t.ToInt32() == 0)
            {
                errbuf = new StringBuilder("No adapter is currently open");
                return PCAP_NEXT_EX_STATE.ERROR;
            }

            int i = pcap_next_ex(pcap_t, ref pkthdr, ref pktdata);
            if (i == 1)
            {
                pcap_pkthdr = ((pcap_pkthdr)(Marshal.PtrToStructure(pkthdr, typeof(pcap_pkthdr))));
                p = new PcapHeader();
                p.CaptureLength = pcap_pkthdr.caplen;
                p.PacketLength = pcap_pkthdr.len;
                p.Timeval = pcap_pkthdr.ts;
                packet_data = new Byte[((System.UInt32)(p.PacketLength))];
                Marshal.Copy(pktdata, packet_data, 0, p.PacketLength);
                return PCAP_NEXT_EX_STATE.SUCCESS;
            }
            else if (i == 0)
                return PCAP_NEXT_EX_STATE.TIMEOUT;
            else if (i == -1)
                return PCAP_NEXT_EX_STATE.ERROR;
            else if (i == -2)
                return PCAP_NEXT_EX_STATE.EOF;
            else 
                return PCAP_NEXT_EX_STATE.UNKNOWN;
#endif
        }

        public virtual PCAP_NEXT_EX_STATE ReadNextInternal(out PcapHeader p, out System.Byte[] packet_data)
        {
            IntPtr i;
            return ReadNextInternal(out p, out packet_data, out i, out i);
        }

        public virtual bool SendPacket(System.Byte[] packet_data)
        {
#if MONO
            return false;
#else
            int i = pcap_sendpacket(pcap_t, packet_data, packet_data.Length);
            if (i == 0)
                return true;
            else 
                return false;
#endif
        }

        private void MonitorDump()
        {
#if !MONO
            if (pcap_live_dump_ended(pcap_t, 1) != 0)
            {
                if (EndCapture != null)
                    EndCapture.Invoke(this);
            }
            return;
#endif
        }

        private void DumpPacket(object sender, IntPtr header, IntPtr data)
        {
#if !MONO
            if (dumper != IntPtr.Zero)
                pcap_dump(dumper, header, data);

            return;
#endif
        }

        public virtual void StopDump()
        {
#if !MONO
            WinPCapWrapper wcap;
            wcap = this;
            if (dumper != IntPtr.Zero)
            {
                pcap_dump_close(dumper);
                dumper = IntPtr.Zero;
            }
            return;
#endif
        }

        public virtual bool StartDump(string filename)
        {
#if MONO
            return false;
#else
            WinPCapWrapper wcap;
            if (pcap_t == IntPtr.Zero)
                return false;

            try
            {
                dumper = pcap_dump_open(pcap_t, filename);
                wcap = this;
                return true;
            }
            catch
            {
                return false;
            }
#endif
        }


        void GetDatalink()
        {
#if !MONO
            datalink = pcap_datalink(pcap_t);
            return;
#endif
        }

        public virtual bool SetMinToCopy(int size)
        {
#if !MONO
            if (pcap_setmintocopy(pcap_t, size) == 0)
                return true;
#endif
            return false;
        }

        private void ReadNextLoop()
        {
            PcapHeader packetHeader;
            System.Byte[] arr;
            IntPtr i, i1;
            PCAP_NEXT_EX_STATE pcap_next_ex_state;

            while (true)
            {
                packetHeader = null;
                arr = null;
                pcap_next_ex_state = ReadNextInternal(out packetHeader, out arr, out i, out i1);
                if (pcap_next_ex_state == PCAP_NEXT_EX_STATE.SUCCESS)
                {
                    if (PacketArrival != null)
                        PacketArrival.Invoke(this, packetHeader, arr);
                }
            }
        }

        public virtual bool SetKernelBuffer(int bytes)
        {
#if !MONO
            if (pcap_setbuff(pcap_t, bytes) == 0)
                return true;
#endif
            return false;
        }

        public virtual void StartListen()
        {
            if (ListenThread != null)
                ListenThread.Abort();

            ListenThread = new Thread(new ThreadStart(this.ReadNextLoop));
            ListenThread.Start();
            m_islistening = true;
            return;
        }

        public virtual void StopListen()
        {
            if (ListenThread != null && ListenThread.IsAlive)
                ListenThread.Abort();
            ListenThread = null;
            m_islistening = false;
            return;
        }

        public virtual void Close()
        {
#if !MONO
            StopDump();
            if (IsListening)
                StopListen();
            m_isopen = false;
            m_attachedDevice = null;
            if (pcap_t != IntPtr.Zero)
            {
                pcap_close(pcap_t);
                pcap_t = IntPtr.Zero;
            }
            return;
#endif
        }

        private void Dispose(bool disposing)
        {
            if (!disposed)
            {

                if (disposing == false && ListenThread == null)
                {
#if !MONO
                    if (pcap_t != IntPtr.Zero)
                    {
                        pcap_close(pcap_t);
                        pcap_t = IntPtr.Zero;
                    }
#endif
                }
                else
                {
                    if (ListenThread.IsAlive)
                        ListenThread = null;
                }
            }

                    disposed = true;
            return;
        }
    }

    public class AlreadyOpenException : Exception
    {
        public AlreadyOpenException()
        {
            return;
        }
        public override string Message
        {
            get
            {
                return "Device attached to object already open. Close first before reopening";
            }
        }
    }

    /// <summary>
    /// Class that defines a Winpcap device
    /// </summary>
    public class Device
    {
        private string _name;
        private string _description;
        private string _address;
        private string _netmask;

        public Device()
        {
            _name = null;
            _description = null;
            _address = null;
            _netmask = null;
            return;
        }

        public Device(string name, string description, string address, string netmask)
        {
            _name = name;
            _description = description;
            _address = address;
            _netmask = netmask;
            return;
        }

        public virtual string Name
        {
            get
            {
                return _name;
            }
            set
            {
                _name = value;
                return;
            }
        }
        public virtual string Description
        {
            get
            {
                return _description;
            }
            set
            {
                _description = value;
                return;
            }
        }
        public virtual string Address
        {
            get
            {
                return _address;
            }
            set
            {
                _address = value;
                return;
            }
        }
        public virtual string Netmask
        {
            get
            {
                return _netmask;
            }
            set
            {
                _netmask = value;
                return;
            }
        }
    }

    /// <summary>
    /// Class that defines a packet header (wrapper around pcap_pkhdr structure)
    /// </summary>
    public class PcapHeader
    {
        internal WinPCapNative.pcap_pkthdr _Pkhdr = new WinPCapNative.pcap_pkthdr();

        /// <summary>
        /// Get/Set the timestamp
        /// </summary>
        public WinPCapNative.timeval Timeval
        {
            get { return _Pkhdr.ts; }
            set { _Pkhdr.ts = value; }
        }

        /// <summary>
        /// Get/Set seconds
        /// </summary>
        public int Seconds
        {
            get { return (int)_Pkhdr.ts.tv_sec; }
            set { _Pkhdr.ts.tv_sec = (uint)value; }
        }

        /// <summary>
        /// Get/Set microseconds
        /// </summary>
        public int MicroSeconds
        {
            get { return (int)_Pkhdr.ts.tv_usec; }
            set { _Pkhdr.ts.tv_usec = (uint)value; }
        }

        /// <summary>
        /// Get a DateTime representation of the timestamp
        /// </summary>
        public virtual DateTime TimeStamp
        {
            get
            {
                DateTime dateTime;
                dateTime = new DateTime(1970, 1, 1).AddSeconds(((System.Double)(_Pkhdr.ts.tv_sec)));
                dateTime.AddMilliseconds(((System.Double)(_Pkhdr.ts.tv_usec)));
                return dateTime;
            }
        }

        /// <summary>
        /// Get/Set the length of a packet
        /// </summary>
        public int PacketLength
        {
            get { return _Pkhdr.len; }
            set { _Pkhdr.len = value; }
        }

        /// <summary>
        /// Get/Set the length of the capture
        /// </summary>
        public int CaptureLength
        {
            get { return _Pkhdr.caplen; }
            set { _Pkhdr.caplen = value; }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PcapHeader()
        {
            _Pkhdr = new WinPCapNative.pcap_pkthdr();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="tv">Timestamp of the packet</param>
        /// <param name="plength">Size of the packet</param>
        /// <param name="clength">Length of the capture</param>
        public PcapHeader(WinPCapNative.timeval tv, int plength, int clength)
        {
            _Pkhdr.caplen = plength;
            _Pkhdr.len = clength;
            _Pkhdr.ts = tv;
        }

        /// <summary>
        /// Constructtor
        /// </summary>
        /// <param name="value">A valid "pcap_pkthdr" packet header.</param>
        public PcapHeader(WinPCapNative.pcap_pkthdr value)
        {
            _Pkhdr = value;
        }
    }

}