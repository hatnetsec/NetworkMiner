using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    public class QueueThresholdSignaller<T> {
        private Queue<T> queue;
        private int threshold;
        private System.Threading.AutoResetEvent belowThresholdEvent;

        public int Threshold { get { return this.threshold; } }
        public System.Threading.AutoResetEvent BelowThresholdEvent { get { return this.belowThresholdEvent; } }

        public QueueThresholdSignaller(Queue<T> queue, int threshold) {
            this.queue = queue;
            this.threshold = threshold;
            this.belowThresholdEvent = new System.Threading.AutoResetEvent(false);
        }

        public void SignalIfBelowThreshold() {
            if (queue.Count < this.threshold)
                this.belowThresholdEvent.Set();
        }
    }
}
