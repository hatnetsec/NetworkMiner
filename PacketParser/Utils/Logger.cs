using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO.IsolatedStorage;

namespace PacketParser.Utils {
    public static class Logger {

        /// <summary>
        /// Selected log-level.
        /// "Normal" log level writes log entries to the Windows Event Log when there are errors.
        /// "Debug" also writes debug messages to disk. The path for this log file can be found in an Event Log entry
        /// </summary>
        public enum LogLevel { Normal, Debug };


        public static LogLevel CurrentLogLevel = LogLevel.Normal;
        public static bool LogToConsole = false;
        private static bool logToEventLog = false;
        public static bool LogToFile = false;
        public static string ApplicationName = null;
        private static object logFileLock = new object();
        private static int debugLogEventCount = 0;
        private static System.Diagnostics.EventLog applicationEventLog = null;

        
        public static void EnableEventLog() {
            applicationEventLog = new System.Diagnostics.EventLog("Application");
            if(ApplicationName == null)
                applicationEventLog.Source = "Application";
            else
                applicationEventLog.Source = ApplicationName;
            logToEventLog = true;
        }

        public static void Log(string message, System.Diagnostics.EventLogEntryType eventLogEntryType) {
            if(eventLogEntryType == System.Diagnostics.EventLogEntryType.Error) {
                try {
                    ConsoleLog(message);
                }
                catch { }
                try {
                    eventLog(message, eventLogEntryType);
                }
                catch { }
                try {
                    fileLog(message, eventLogEntryType.ToString());
                }
                catch { }
            }
            else if (CurrentLogLevel == LogLevel.Debug) {
                if (LogToConsole)
                    ConsoleLog(message);
                if (logToEventLog)
                    eventLog(message, eventLogEntryType);
                if (LogToFile)
                    fileLog(message, eventLogEntryType.ToString());
            }
            
        }

        private static void eventLog(string message, System.Diagnostics.EventLogEntryType eventLogEntryType) {

            if (applicationEventLog != null)
                applicationEventLog.WriteEntry(message, eventLogEntryType);
            else
                System.Diagnostics.EventLog.WriteEntry("Application", message, eventLogEntryType);
            
        }

        public static void ConsoleLog(string message) {
            try {
                lock (System.Console.Out) {
                    System.Console.Out.WriteLine(DateTime.Now.ToLongTimeString() + " " + message);
                }
            }
            catch { }
        }


        private static void fileLog(string message, string entryType = "DEBUG") {
            if (CurrentLogLevel == LogLevel.Debug) {

                using (IsolatedStorageFile isoFile = IsolatedStorageFile.GetStore(IsolatedStorageScope.Assembly | IsolatedStorageScope.User, null, null)) {

                    lock (logFileLock) {
                        try {
                            //IsolatedStorage will be something like: C:\WINDOWS\system32\config\systemprofile\AppData\Local\IsolatedStorage\arpzpldm.neh\4hq14imw.y2b\Publisher.5yo4swcgiijiq5te00ddqtmrsgfhvrp4\AssemFiles\
                            using (IsolatedStorageFileStream stream = new IsolatedStorageFileStream(ApplicationName + ".log", System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.Write, System.IO.FileShare.Read, isoFile)) {
                                stream.Seek(0, System.IO.SeekOrigin.End);
                                if (debugLogEventCount == 0) {
                                    string path = stream.GetType().GetField("m_FullPath", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(stream).ToString();
                                    if (logToEventLog)
                                        eventLog("Saving debug log to " + path, System.Diagnostics.EventLogEntryType.Information);
                                    else
                                        ConsoleLog("Saving debug log to " + path);
                                }
                                using (System.IO.StreamWriter writer = new System.IO.StreamWriter(stream)) {
                                    writer.WriteLine(DateTime.UtcNow.ToString("s", System.Globalization.CultureInfo.InvariantCulture) + "\t[" + entryType + "]\t" + message);

                                }
                            }
                        }
                        catch (System.IO.IOException e) {
                            if (debugLogEventCount == 0)
                                eventLog(e.Message, System.Diagnostics.EventLogEntryType.Error);
                        }
                        catch(System.NullReferenceException) {
                            LogToFile = false;
                        }

                        System.Threading.Interlocked.Increment(ref debugLogEventCount);

                    }
                }
                
            }
        }
    }
}
