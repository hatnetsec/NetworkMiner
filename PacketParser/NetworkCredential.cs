using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class NetworkCredential : IComparable<NetworkCredential>{

        public static NetworkCredential GetNetworkCredential(System.Collections.Specialized.NameValueCollection parameters, NetworkHost client, NetworkHost server, string protocolString, DateTime timestamp) {
            if(parameters==null)
                return null;
            //check for credentials (usernames and passwords)
            string username=null;
            string usernameGuess = null;
            string password=null;
            string passwordGuess = null;
            foreach(string key in parameters) {
                /** EXACT MATCHES **/
                if (key.Equals("user[screen_name]")) //twitter
                    username = parameters[key];
                else if (key.Equals("gmailchat")) {
                    username = parameters[key];
                    if (password == null)
                        password = "N/A (unknown Google password)";
                }
                else if (key.Equals("login_str")) {
                    username = "Facebook email: " + parameters[key];
                    if(password == null)
                        password = "N/A (unknown Facebook password)";
                }
                //SquirrelMail login uses login_username / secretkey
                else if (key.Equals("login_username")) {
                    username = parameters[key];
                }
                else if (key.Equals("secretkey")) {
                    password = parameters[key];
                }
                else if (key.Equals("xml") && parameters[key].Contains("mail_inc_pass")) {
                    //Parsing of credentials from AfterLogic webmail service
                    System.Xml.XmlDocument xmlDoc = new System.Xml.XmlDocument();
                    xmlDoc.LoadXml(parameters[key]);

                    System.Xml.XmlNode passwordNode = xmlDoc.SelectSingleNode("/webmail/param[@name='mail_inc_pass']");
                    System.Xml.XmlNode emailNode = xmlDoc.SelectSingleNode("/webmail/param[@name='email']");
                    System.Xml.XmlNode loginNode = xmlDoc.SelectSingleNode("/webmail/param[@name='mail_inc_login']");

                    if (password == null && passwordNode != null && passwordNode.InnerText != null && passwordNode.InnerText.Length > 0)
                        password = passwordNode.InnerText;

                    if (username == null && emailNode != null && emailNode.InnerText != null && emailNode.InnerText.Length > 0)
                        username = emailNode.InnerText;
                    else if (username == null && loginNode != null && loginNode.InnerText != null && loginNode.InnerText.Length > 0)
                        username = loginNode.InnerText;
                }
                else if (key.Equals("profile_id")) {
                    username = "Facebook profile ID: " + parameters[key];
                    if(password == null)
                        password = "N/A (unknown Facebook password)";
                }

                /** WILDCARD MATCHES **/
                else if (key.ToLower().Contains("accountname"))//used by Moxa (Moxa EDS-508A)
                    usernameGuess = parameters[key];
                else if(key.ToLower().Contains("username"))
                    usernameGuess = parameters[key];
                else if (key.ToLower().Contains("password"))
                    passwordGuess = parameters[key];

                else if(key.ToLower().Contains("user") || key.ToLower().Contains("usr"))
                    usernameGuess = parameters[key];
                else if(key.ToLower().Contains("pass") || key.ToLower().Contains("pw"))
                    passwordGuess = parameters[key];

                else if (usernameGuess == null && key.ToLower().Contains("mail"))
                    usernameGuess = parameters[key];
                else if (usernameGuess == null && key.ToLower().Contains("log"))
                    usernameGuess = parameters[key];
                

            }
            if (username == null)
                username = usernameGuess;
            if (password == null)
                password = passwordGuess;
            if(username!=null && password!=null)
                return new NetworkCredential(client, server, protocolString, username, password, timestamp);
            else if(username!=null)
                return new NetworkCredential(client, server, protocolString, username, timestamp);
            else
                return null;
        }

        private NetworkHost client, server;
        private string protocolString;
        private string username;
        private string password;
        private bool isProvenValid;//this one shall only be set to true if you are sure that the user+pass is valid
        private DateTime loginTimestamp;

        public NetworkHost Client { get { return this.client; } }
        public NetworkHost Server { get { return this.server; } }

        public string ProtocolString { get { return this.protocolString; } }
        public string Username { get { return this.username; } }
        public string Password { get { return this.password; } set { this.password=value; } }
        public bool IsProvenValid { get { return this.isProvenValid; } set { this.isProvenValid=value; } }
        public DateTime LoginTimestamp { get { return this.loginTimestamp; } set { this.loginTimestamp=value; } }

        public string Key {
            get {
                if(password==null)
                    return this.protocolString+this.username+this.server.IPAddress.ToString()+this.client.IPAddress.ToString();
                else
                    return this.protocolString+this.username+this.password.GetHashCode()+this.server.IPAddress.ToString()+this.client.IPAddress.ToString();
            }
        }

        public static string GetCredentialSessionString(NetworkCredential credential) {
            return GetCredentialSessionString(credential.client, credential.server, credential.protocolString);
        }
        public static string GetCredentialSessionString(NetworkHost client, NetworkHost server, string protocolString) {
            return client.IPAddress.ToString()+server.IPAddress.ToString()+protocolString;
        }

        internal NetworkCredential(NetworkHost client, NetworkHost server, string protocolString, string username, DateTime loginTimestamp) : this(client, server, protocolString, username, null, loginTimestamp){
        }
        internal NetworkCredential(NetworkHost client, NetworkHost server, string protocolString, string username, string password, DateTime loginTimestamp)
        : this(client, server, protocolString, username, password, false, loginTimestamp){
        }
        internal NetworkCredential(NetworkHost client, NetworkHost server, string protocolString, string username, string password, bool isProvenValid, DateTime loginTimestamp) {
            this.client=client;
            this.server=server;
            this.protocolString=protocolString;
            this.username=username;
            this.password=password;
            this.isProvenValid=isProvenValid;
            this.loginTimestamp=loginTimestamp;
        }


        public override string ToString() {
            return server.ToString()+" "+protocolString+" "+username;//I'll not care for the password here. One username shall only have one valid password
        }

        #region IComparable<NetworkCredential> Members

        public int CompareTo(NetworkCredential other) {
            return this.Key.CompareTo(other.Key);
        }

        #endregion
    }
}
