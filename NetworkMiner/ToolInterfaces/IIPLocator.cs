using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IIPLocator {
        string GetCountry(System.Net.IPAddress ipAddress);
    }
}
