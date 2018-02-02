using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Events {
    public class BufferUsageEventArgs : EventArgs {

        public int BufferUsagePercent;

        public BufferUsageEventArgs(int bufferUsagePercent) {
            this.BufferUsagePercent=bufferUsagePercent;
        }

    }
}
