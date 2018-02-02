using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IHostDetailsGenerator {
        void DownloadDatabase();
        System.Collections.Specialized.NameValueCollection GetExtraDetails(System.Net.IPAddress ip);
        string GetDefaultKeyName();
        string GetVersionString();
    }
}
