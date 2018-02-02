using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace NetworkWrapper {
    public class MicroOlapAdapter : IAdapter{

        public static List<IAdapter> GetAdapters() {
            List<IAdapter> deviceList=new List<IAdapter>();

            microOLAP.PSSDK.HNPSManager hnpsManager=new microOLAP.PSSDK.HNPSManager();
            hnpsManager.Initialize();

            microOLAP.PSSDK.PSSDKRES pssdkres=hnpsManager.RefreshAdapterList();
            IntPtr acHandle=hnpsManager.Get_FirstAdapter();

            while(acHandle.ToInt32()!=0) {
                microOLAP.PSSDK.HNAdapterConfig adapterConfig=new microOLAP.PSSDK.HNAdapterConfig();
                adapterConfig.Handle=acHandle;
                deviceList.Add(new MicroOlapAdapter(adapterConfig));
                acHandle=hnpsManager.Get_NextAdapterCfg(acHandle);
            }

            return deviceList;

        }

        private microOLAP.PSSDK.HNAdapterConfig adapterConfig;

        public microOLAP.PSSDK.HNAdapterConfig AdapterConfig { get { return this.adapterConfig; } }

        public MicroOlapAdapter(microOLAP.PSSDK.HNAdapterConfig adapterConfig) {
            this.adapterConfig=adapterConfig;

        }

        #region IAdapter Members

        public override string ToString() {
            StringBuilder returnString=new StringBuilder("MicroOLAP: "+this.adapterConfig.AdapterDescription);
            if(this.adapterConfig.AdapterName.Contains("{"))
                returnString.Append(" "+this.adapterConfig.AdapterName.Substring(this.adapterConfig.AdapterName.IndexOf('{')));
            else
                returnString.Append(" "+this.adapterConfig.AdapterName);
            return returnString.ToString();
        }

        #endregion
    }
}
