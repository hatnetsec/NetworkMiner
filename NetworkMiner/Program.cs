//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace NetworkMiner {
    public static class Program {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args) {

            SetupLogger("NetworkMiner");

            bool legacyGui = false;
            bool checkForUpdates = true;
            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--legacygui", StringComparison.CurrentCultureIgnoreCase))
                    legacyGui = true;
                else if (arg.Equals("--noupdatecheck", StringComparison.CurrentCultureIgnoreCase))
                    checkForUpdates = false;
            }

            if(!legacyGui)
                Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);//causes mono on OSX to hang?
            PacketParser.Utils.Logger.Log("Starting the application", System.Diagnostics.EventLogEntryType.Information);

            try {
                NetworkMinerForm networkMinerForm = new NetworkMinerForm();
                if(checkForUpdates)
                    NetworkMiner.UpdateCheck.ShowNewVersionFormIfAvailableAsync(networkMinerForm, System.Reflection.Assembly.GetEntryAssembly().GetName().Version);
                else
                    PacketParser.Utils.Logger.Log("Skipping update check", System.Diagnostics.EventLogEntryType.Information);
                PacketParser.Utils.Logger.Log("GUI form object created, starting application message loop", System.Diagnostics.EventLogEntryType.Information);
                Application.Run(networkMinerForm);
            }
            catch (System.IO.FileNotFoundException e) {
                if (PacketParser.Utils.SystemHelper.IsRunningOnMono()) {
                    System.Text.StringBuilder sb = new System.Text.StringBuilder("Make sure you have installed the following Mono packages: ");
                    foreach (string p in NetworkMinerForm.RecommendedMonoPackages) {
                        sb.Append(p);
                        sb.Append(" ");
                    }
                    sb.Append(Environment.NewLine);
                    PacketParser.Utils.Logger.ConsoleLog(sb.ToString());
                }
                PacketParser.Utils.Logger.Log("Error creating NetworkMiner GUI Form: " + e.Message, System.Diagnostics.EventLogEntryType.Error);
                return;
            }
#if !DEBUG
            catch (Exception e) {
                PacketParser.Utils.Logger.Log("Unable to start NetworkMiner: " + e.Message, System.Diagnostics.EventLogEntryType.Error);
                MessageBox.Show(e.Message, "Unable to start NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
#endif  
            

        }

        public static void SetupLogger(string applicationName) {
            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--debug", StringComparison.InvariantCultureIgnoreCase)) {
                    PacketParser.Utils.Logger.CurrentLogLevel = PacketParser.Utils.Logger.LogLevel.Debug;
                    PacketParser.Utils.Logger.LogToConsole = true;
                }
                else if (arg.Equals("--eventlog", StringComparison.InvariantCultureIgnoreCase)) {
                    PacketParser.Utils.Logger.CurrentLogLevel = PacketParser.Utils.Logger.LogLevel.Debug;
                    PacketParser.Utils.Logger.EnableEventLog();
                }
                else if (arg.Equals("--filelog", StringComparison.InvariantCultureIgnoreCase)) {
                    PacketParser.Utils.Logger.CurrentLogLevel = PacketParser.Utils.Logger.LogLevel.Debug;
                    PacketParser.Utils.Logger.LogToFile = true;
                }
            }
#if DEBUG
            PacketParser.Utils.Logger.CurrentLogLevel = PacketParser.Utils.Logger.LogLevel.Debug;
            PacketParser.Utils.Logger.LogToConsole = true;
            //PacketParser.Utils.Logger.EnableEventLog();
            PacketParser.Utils.Logger.LogToFile = true;
#endif

            PacketParser.Utils.Logger.ApplicationName = applicationName;
            PacketParser.Utils.Logger.Log("Environment.Is64BitOperatingSystem = " + Environment.Is64BitOperatingSystem.ToString(), System.Diagnostics.EventLogEntryType.Information);
            PacketParser.Utils.Logger.Log("Environment.Is64BitProcess = " + Environment.Is64BitProcess.ToString(), System.Diagnostics.EventLogEntryType.Information);
            PacketParser.Utils.Logger.Log(Application.ProductName + " " + Application.ProductVersion, System.Diagnostics.EventLogEntryType.Information);
            PacketParser.Utils.Logger.Log("Application.ExecutablePath = " + Application.ExecutablePath, System.Diagnostics.EventLogEntryType.Information);
            PacketParser.Utils.Logger.Log("Application.CurrentCulture = " + Application.CurrentCulture, System.Diagnostics.EventLogEntryType.Information);
            PacketParser.Utils.Logger.Log("Setting up application rendering", System.Diagnostics.EventLogEntryType.Information);

        }
    }
}