using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Events {
    public class FrameEventArgs : EventArgs {
        public Frame Frame;

        public FrameEventArgs(Frame frame) {
            this.Frame=frame;
        }
    }
}
