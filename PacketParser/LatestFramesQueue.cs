//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    class LatestFramesQueue : System.Collections.Generic.Queue<Frame> {
        private int maxSize;//the maximum number of frames that shall be stored

        public int MaxSize { get { return this.maxSize; } }

        public  LatestFramesQueue(int maxNoFrames): base(){
            this.maxSize=maxNoFrames;
        }

        new public void Enqueue(Frame frame) {
            base.Enqueue(frame);
            if(base.Count>maxSize)
                base.Dequeue();
        }

       
    }
}
