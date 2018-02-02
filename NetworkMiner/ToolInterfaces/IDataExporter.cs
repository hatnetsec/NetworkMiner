using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IDataExporter : IDisposable {

        void Export(System.Windows.Forms.ListView listView, bool includeHeaders, IEnumerable<CaseFile> pcapFiles);

        void Export(IEnumerable<string> items);
    }
}
