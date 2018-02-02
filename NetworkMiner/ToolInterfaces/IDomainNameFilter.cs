using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IDomainNameFilter {
        bool ContainsDomain(string domainName, out string queriedDomainName);
    }
}
