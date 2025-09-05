using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;


namespace Framework
{
    internal sealed class Record
    {
        public Record(string dn, string nm, string sam, string sid, string guid, string sddl)
        {
            Sid = sid;
            Guid = guid;
            Sddl = sddl;
            DistinguishedName = dn;
            Name = nm;
            SamAccountName = sam;
        }

        public string DistinguishedName { get; set; }
        public string Name { get; set; }
        public string SamAccountName { get; set; }
        public string Sid { get; set; }
        public string Guid { get; set; }
        public string Sddl { get; set; }
    }

    internal class GetAllForestDACLs
    {
        /// <summary>
        ///  Добавляет DNS-домен и его DN в коллекции, если такого ещё не было
        /// </summary>
        private static void AddDomain(string dnsName,
                                      HashSet<string> dnsSet,
                                      HashSet<string> dnSet)
        {
            if (string.IsNullOrWhiteSpace(dnsName)) return;
            if (!dnsSet.Add(dnsName)) return;              // уже есть

            dnSet.Add(DnsToDn(dnsName));
        }

        /// <summary>
        ///  "contoso.local" → "DC=contoso,DC=local"
        /// </summary>
        private static string DnsToDn(string dns)
        {
            return string.Join(",",
                   dns.Split('.')
                      .Where(p => p.Length > 0)
                      .Select(p => $"DC={p}"));
        }

        public static void UsingPag(string server)
        {
            const int pageSize = 1000;                 // не больше MaxPageSize
            byte [] cookie = null;
            string OutFile = server + ".json";
            if (File.Exists(OutFile))
                return;

            var sw = new StreamWriter(OutFile, false, new UTF8Encoding(false), 1 << 16); // 64 KB буфер
            var writer = new JsonTextWriter(sw) { 
                Formatting = Formatting.Indented
            };
            
            writer.WriteStartArray();                     //  [

            // 0. Находим DN домена
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(server);
            var ldap = new LdapConnection(identifier) 
            { 
                AuthType = AuthType.Negotiate,
                Credential = CredentialCache.DefaultNetworkCredentials                
            };
            ldap.SessionOptions.Sealing = true;        // обязательно для SD            
            ldap.SessionOptions.ProtocolVersion = 3;
            ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            try
            {
                ldap.Bind();

                var root = (SearchResponse)ldap.SendRequest(
                    new SearchRequest("",
                    "(objectClass=*)",
                    System.DirectoryServices.Protocols.SearchScope.Base,
                    "defaultNamingContext")
                    );
                string defaultNc = root.Entries [0].Attributes ["defaultNamingContext"] [0].ToString();

                var results = new List<Record>();

                int i = 0;
                do
                {
                    // --- 1. Controls -------------------------------------------------                
                    var pageCtrl = new PageResultRequestControl(pageSize)
                    {
                        Cookie = cookie,
                        IsCritical = true,
                        ServerSide = true
                    };
                    var sdCtrl = new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl | System.DirectoryServices.Protocols.SecurityMasks.Group | System.DirectoryServices.Protocols.SecurityMasks.Owner)
                    {
                        IsCritical = true,
                        ServerSide = true

                    }; // IsCritical = false by default

                    // --- 2. SearchRequest -------------------------------------------
                    var req = new SearchRequest(
                        defaultNc,                       // DN домена
                        "(objectClass=*)",               // фильтр
                        System.DirectoryServices.Protocols.SearchScope.Subtree,
                        new string []
                        {
                        "name",
                        "sAMAccountName",
                        "nTSecurityDescriptor",
                        "objectGUID",
                        "objectSid",
                        "distinguishedName"
                        });

                    req.Controls.Add(pageCtrl);          // ВАЖНО: PageCtrl → всегда первый
                    req.Controls.Add(sdCtrl);

                    // --- 3. Отправляем запрос ---------------------------------------
                    var resp = (SearchResponse)ldap.SendRequest(req);
                    foreach (SearchResultEntry e in resp.Entries)
                    {
                        i++;
                        if (i % 10 == 0)
                        {
                            Console.Clear();
                            Console.Write(i);
                        }

                        var rawSD = e.Attributes.Contains("nTSecurityDescriptor")
                            ? (byte [])e.Attributes ["nTSecurityDescriptor"] [0]
                            : null;

                        if (rawSD != null)
                        {
                            var sd = new RawSecurityDescriptor(rawSD, 0);

                            if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
                                Console.WriteLine(e.DistinguishedName);
                        }

                        // ---- Атрибуты ------------------------------------------

                        string dn = e.DistinguishedName;
                        string nm = e.Attributes.Contains("name")
                            ? e.Attributes ["name"] [0].ToString()
                            : "";

                        string sam = e.Attributes.Contains("sAMAccountName")
                            ? e.Attributes ["sAMAccountName"] [0].ToString()
                            : "";

                        string guid = e.Attributes.Contains("objectGUID")
                            ? new Guid((byte [])e.Attributes ["objectGUID"] [0]).ToString("D")
                            : "";

                        var rawSID = e.Attributes.Contains("objectSid")
                            ? e.Attributes ["objectSid"].GetValues(typeof(byte [])) [0]
                            : null;

                        string sid = rawSID != null
                            ? new SecurityIdentifier((byte [])rawSID, 0).ToString()
                            : "";

                        string sddl = rawSD != null
                            ? new CommonSecurityDescriptor(false, false, rawSD, 0).GetSddlForm(AccessControlSections.All)
                            : "";

                        //results.Add(new Record(dn, nm, sam, sid, guid, sddl));

                        // ---- потоковая запись в JSON --------------------------------------
                        writer.WriteStartObject();   // {

                        writer.WritePropertyName("distinguishedName");
                        writer.WriteValue(dn);

                        writer.WritePropertyName("name");
                        writer.WriteValue(nm);

                        writer.WritePropertyName("sAMAccountName");
                        writer.WriteValue(sam);

                        writer.WritePropertyName("sid");
                        writer.WriteValue(sid);


                        writer.WritePropertyName("guid");
                        writer.WriteValue(guid);

                        writer.WritePropertyName("sddl");
                        writer.WriteValue(sddl);

                        writer.WriteEndObject();               // }

                        // При очень больших лесах полезно буфер чистить вручную:
                        if ((i & 0x3FF) == 0) writer.Flush();   // каждые 1024 объекта

                    }

                    // --- 4. Берём cookie для следующей страницы ---------------------
                    cookie = resp.Controls
                        .OfType<PageResultResponseControl>()
                        .First().Cookie;


                } while (cookie != null && cookie.Length != 0);

                writer.WriteEndArray();                   // ]
                
                writer.Close();                           // flush + dispose
                sw.Close();
                Console.WriteLine($"Saved {results.Count} objects to {OutFile}");
            }
            catch(Exception ex)
            { 
                Console.WriteLine(ex.ToString());
                writer.Close();                           // flush + dispose
                sw.Close();
                File.Delete(OutFile);
            }


        }
        static void Main(string [] args)
        {
            // ─────────────────────────────────────────────────────────────
            // 1. Получаем текущий лес и подготавливаем две коллекции:
            //    • dnsSet  – DNS-имена доменов (контроль уникальности)
            //    • dnSet   – DistinguishedName тех же доменов
            // ─────────────────────────────────────────────────────────────
            Forest forest = Forest.GetCurrentForest();
            var dnsSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dnSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            Console.WriteLine($"Current forest: {forest.Name}\n");

            // ─────────────────────────────────────────────────────────────
            // 2. Все домены в лесу
            // ─────────────────────────────────────────────────────────────
            foreach (Domain dom in forest.Domains)
            {
                AddDomain(dom.Name, dnsSet, dnSet);
                foreach (TrustRelationshipInformation tri in dom.GetAllTrustRelationships())                
                    AddDomain(tri.TargetName, dnsSet, dnSet);

                DirectoryEntry sys = dom.GetDirectoryEntry().Children.Find("CN=System");
                var ds = new DirectorySearcher(sys)
                {
                    Filter = "(objectClass=trustedDomain)",
                    SearchScope = System.DirectoryServices.SearchScope.Subtree,
                    PageSize = 500
                };
                ds.PropertiesToLoad.Add("trustPartner");

                foreach (SearchResult res in ds.FindAll())
                {
                    if (res.Properties ["trustPartner"].Count == 0) continue;

                    string partner = res.Properties ["trustPartner"] [0].ToString();
                    AddDomain(partner, dnsSet, dnSet);          // +dnSet
                }

            }


            // ─────────────────────────────────────────────────────────────
            // 3. Красивый вывод
            // ─────────────────────────────────────────────────────────────
            Console.WriteLine("Unique Distinguished Names:");
            foreach (string dn in dnSet.OrderBy(s => s, StringComparer.OrdinalIgnoreCase))            
                Console.WriteLine("  " + dn);                
            
            foreach(string server in dnsSet)
                UsingPag(server);

        }
    }
}
