using System;
using System.Collections.Generic;
using System.Text;

using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace NetworkMiner.PcapOverIP {
    public class PcapTcpStream : IDisposable {

        public enum TcpSocketState { Listening, Connected, Receiving, Closed }

        private System.IO.Stream pcapStream;
        private System.Net.IPAddress remoteIP;
        private TcpSocketState socketState;
        private System.Net.Sockets.TcpListener tcpListener;
        private bool useSsl;
        private TcpClient tcpClient = null;
        private int idleTimeoutMS;

        public System.IO.Stream PcapStream { get { return this.pcapStream; } }
        public System.Net.IPAddress RemoteIP { get { return this.remoteIP; } }
        public TcpSocketState SocketState { get { return this.socketState; } set { this.socketState = value; } }
        public int IdleTimeoutMilliSeconds { get { return this.idleTimeoutMS; } }



        public PcapTcpStream(ushort localTcpPort, bool useSsl, int idleTimeoutMilliSeconds) : this(useSsl, idleTimeoutMilliSeconds) {
            this.socketState = TcpSocketState.Closed;
            this.tcpListener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Any, (int)localTcpPort);
            tcpListener.Start();
            this.socketState = TcpSocketState.Listening;
        }

        public PcapTcpStream(string remoteIpOrHost, ushort remotePort, bool useSSl, int idleTimeoutMilliSeconds, System.Windows.Forms.MethodInvoker streamEstablishedHandler) : this(useSSl, idleTimeoutMilliSeconds) {
            this.tcpClient = new TcpClient(remoteIpOrHost, remotePort);
            if (this.tcpClient.Connected) {
                this.SetSocketAsConnected();
                //streamEstablishedHandler. .DynamicInvoke();
            }
            else
                this.socketState = TcpSocketState.Closed;
        }

        private PcapTcpStream(bool useSsl, int idleTimeoutMilliSeconds) {
            this.useSsl = useSsl;
            this.idleTimeoutMS = idleTimeoutMilliSeconds;
        }

        public bool IsClosed() {
            return this.tcpClient == null || !this.tcpClient.Connected;
        }

        public void BeginAcceptTcpClient(System.Windows.Forms.MethodInvoker streamEstablishedHandler) {
            IAsyncResult ar = tcpListener.BeginAcceptTcpClient(new AsyncCallback(this.AcceptTcpClientCallback), streamEstablishedHandler);
            //TcpClient tcpClient = tcpListener.AcceptTcpClient();//blocking call
        }

        public void BlockingWaitForTcpClient() {
            this.tcpClient = tcpListener.AcceptTcpClient();
            this.SetSocketAsConnected();
        }

        public void AcceptTcpClientCallback(IAsyncResult ar) {
            //make sure a client is actually connecting!
            try {
                this.tcpClient = this.tcpListener.EndAcceptTcpClient(ar);
                this.SetSocketAsConnected();
            }
            catch {
                this.Dispose();
            }

            //now, make the callback to the event handler
            ((System.Windows.Forms.MethodInvoker)ar.AsyncState)();
        }

        private void SetSocketAsConnected() {
            try {
                this.socketState = TcpSocketState.Connected;
                this.remoteIP = ((System.Net.IPEndPoint)this.tcpClient.Client.RemoteEndPoint).Address;
                if (this.useSsl) {
                    //send test stream with: cat dump.pcap | socat - SSL:localhost:57012,verify=0
                    //socat GOPEN:dump.pcap SSL:localhost:57443,verify=0
                    System.Net.Security.SslStream sslStream = new System.Net.Security.SslStream(tcpClient.GetStream(), false);
                    //sslStream.ReadTimeout = idleTimeoutMS; //8 seconds
                    sslStream.AuthenticateAsServer(ServerCert.Instance, false, System.Security.Authentication.SslProtocols.Default, false);
                    this.pcapStream = sslStream;

                }
                else
                    this.pcapStream = this.tcpClient.GetStream();
                this.pcapStream.ReadTimeout = this.idleTimeoutMS;
                //this.tcpClient.ReceiveTimeout = this.idleTimeoutMS;//not required, we do  stream.ReadTimeout instead
            }
            catch {
                this.Dispose();
            }
        }

        ~PcapTcpStream() {
            this.Dispose();
        }



        public void Dispose() {
            this.socketState = TcpSocketState.Closed;
            if (this.pcapStream != null) {
                try {
                    this.pcapStream.Close();
                }
                catch { }
                this.pcapStream.Dispose();
            }
            this.pcapStream = null;
            if (this.tcpClient != null) {
                this.tcpClient.Close();
            }
            if (this.tcpListener != null) {
                try {
                    this.tcpListener.Stop();
                }
                catch { }
                //this.tcpListener = null;
            }
        }
    }
}
