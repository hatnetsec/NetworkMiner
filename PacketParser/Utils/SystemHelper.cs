using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Utils {
    public class SystemHelper {

        public static bool IsRunningOnMono() {
            return Type.GetType("Mono.Runtime") != null;
        }

        
    }                         
}
