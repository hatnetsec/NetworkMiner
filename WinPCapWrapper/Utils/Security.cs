using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkWrapper.Utils {
    public static class Security {

        public static bool DllHijackingAttempted(IList<string> paths, IList<string> dllFileNames, out string hijackedPath) {
            char[] dirsep = { System.IO.Path.DirectorySeparatorChar };
            foreach (string path in paths) {
                if (!path.Trim(dirsep).EndsWith("system32")) {
                    foreach (string dll in dllFileNames) {
                        if (DllHijackingAttempted(path, dll)) {
                            hijackedPath = path + System.IO.Path.DirectorySeparatorChar + dll;
                            return true;
                        }
                    }
                }
            }
            hijackedPath = "";
            return false;
        }

        public static bool DllHijackingAttempted(string path, string dllFileName) {
            System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(path);
            return System.IO.File.Exists(di.FullName + System.IO.Path.DirectorySeparatorChar + dllFileName);
        }
    }
}
