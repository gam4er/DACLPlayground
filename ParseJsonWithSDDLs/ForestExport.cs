using Newtonsoft.Json;

using Spectre.Console;

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ParseJsonWithSDDLs
{
    static class ForestExport
    {
        // Собираем уникальные домены: все домены леса + внешние таргеты трастов
        public static HashSet<string> DiscoverDnsDomains()
        {
            var dns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            Forest forest = Forest.GetCurrentForest(); // текущий контекст пользователя
                                                       // Домены леса
            foreach (Domain dom in forest.Domains)
            {
                dns.Add(dom.Name);

                // Траста лесного домена
                foreach (TrustRelationshipInformation tri in dom.GetAllTrustRelationships())
                    dns.Add(tri.TargetName);

                // trustedDomain из CN=System
                DirectoryEntry sys = dom.GetDirectoryEntry().Children.Find("CN=System");
                var ds = new DirectorySearcher(sys)
                {
                    Filter = "(objectClass=trustedDomain)",
                    SearchScope = System.DirectoryServices.SearchScope.Subtree,
                    PageSize = 500
                };
                ds.PropertiesToLoad.Add("trustPartner");
                foreach (SearchResult res in ds.FindAll())
                    if (res.Properties ["trustPartner"].Count > 0)
                        dns.Add(res.Properties ["trustPartner"] [0].ToString());
            }

            return dns;
        }

        private static string DnsToDn(string dns)
            => string.Join(",", dns.Split('.').Where(p => p.Length > 0).Select(p => $"DC={p}"));

        public static void ExportAll(string outputFolder, bool overwrite)
        {
            Directory.CreateDirectory(outputFolder);

            var servers = DiscoverDnsDomains();

            // Параллельно бежим по доменам/трастам — каждая цель пишет в свой файл
            Parallel.ForEach(servers,
                new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                server =>
                {
                    try
                    {
                        ExportDomain(server, outputFolder, overwrite);
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"[red]Export failed for {server}[/]: {Markup.Escape(ex.Message)}");
                    }
                });
        }

        // Экспорт одного домена/таргета в <output>/<dns>.json

        private static void ExportDomain(string dnsName, string outputFolder, bool overwrite)
        {
            if (string.IsNullOrWhiteSpace(dnsName))
                return;

            string finalPath = Path.Combine(outputFolder, dnsName + ".json");
            string tempPath = finalPath + ".tmp";

            if (!overwrite && File.Exists(finalPath))
                return;

            const int pageSize = 1000;
            byte [] cookie = null;
            int written = 0;

            try
            {
                // записываем во временный файл
                using (var sw = new StreamWriter(tempPath, false, new UTF8Encoding(false), 1 << 16))
                using (var writer = new JsonTextWriter(sw) { Formatting = Formatting.Indented })
                using (var ldap = new LdapConnection(new LdapDirectoryIdentifier(dnsName)))
                {
                    ldap.AuthType = AuthType.Negotiate;
                    ldap.Credential = CredentialCache.DefaultNetworkCredentials;
                    ldap.SessionOptions.ProtocolVersion = 3;
                    ldap.SessionOptions.Sealing = true;
                    ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                    ldap.Bind(); // тут может вылететь при недоступности КД (LDAP_SERVER_DOWN 0x51)

                    // читаем defaultNamingContext
                    var root = (SearchResponse)ldap.SendRequest(
                        new SearchRequest("", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, "defaultNamingContext"));
                    string defaultNc = root.Entries [0].Attributes ["defaultNamingContext"] [0].ToString();

                    writer.WriteStartArray();

                    do
                    {
                        var pageCtrl = new PageResultRequestControl(pageSize) { Cookie = cookie, IsCritical = true, ServerSide = true };
                        var sdCtrl = new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl | System.DirectoryServices.Protocols.SecurityMasks.Group | System.DirectoryServices.Protocols.SecurityMasks.Owner)
                        {
                            IsCritical = true,
                            ServerSide = true
                        };

                        var req = new SearchRequest(
                            defaultNc,
                            "(objectClass=*)",
                            System.DirectoryServices.Protocols.SearchScope.Subtree,
                            new [] { "name", "sAMAccountName", "nTSecurityDescriptor", "objectGUID", "objectSid", "distinguishedName" });

                        req.Controls.Add(pageCtrl);
                        req.Controls.Add(sdCtrl);

                        var resp = (SearchResponse)ldap.SendRequest(req);

                        foreach (SearchResultEntry e in resp.Entries)
                        {
                            var rawSD = e.Attributes.Contains("nTSecurityDescriptor")
                                ? (byte [])e.Attributes ["nTSecurityDescriptor"] [0] : null;

                            string dn = e.DistinguishedName;
                            string nm = e.Attributes.Contains("name") ? e.Attributes ["name"] [0].ToString() : "";
                            string sam = e.Attributes.Contains("sAMAccountName") ? e.Attributes ["sAMAccountName"] [0].ToString() : "";
                            string guid = e.Attributes.Contains("objectGUID")
                                ? new Guid((byte [])e.Attributes ["objectGUID"] [0]).ToString("D") : "";

                            var rawSID = e.Attributes.Contains("objectSid")
                                ? e.Attributes ["objectSid"].GetValues(typeof(byte [])) [0] : null;

                            string sid = rawSID != null ? new SecurityIdentifier((byte [])rawSID, 0).ToString() : "";
                            string sddl = rawSD != null
                                ? new CommonSecurityDescriptor(false, false, rawSD, 0).GetSddlForm(AccessControlSections.All)
                                : "";

                            writer.WriteStartObject();
                            writer.WritePropertyName("distinguishedName"); writer.WriteValue(dn);
                            writer.WritePropertyName("name"); writer.WriteValue(nm);
                            writer.WritePropertyName("sAMAccountName"); writer.WriteValue(sam);
                            writer.WritePropertyName("sid"); writer.WriteValue(sid);
                            writer.WritePropertyName("guid"); writer.WriteValue(guid);
                            writer.WritePropertyName("sddl"); writer.WriteValue(sddl);
                            writer.WriteEndObject();

                            written++;
                            if ((written & 0x3FF) == 0) writer.Flush(); // каждые 1024
                        }

                        cookie = resp.Controls.OfType<PageResultResponseControl>().First().Cookie;
                    }
                    while (cookie != null && cookie.Length != 0);

                    writer.WriteEndArray();
                }

                // если что-то записали → атомарно переносим temp → final
                if (written > 0 && new FileInfo(tempPath).Length > 2) // "[]" = 2 байта
                {
                    if (File.Exists(finalPath))
                        File.Replace(tempPath, finalPath, null);     // перезапись атомарно
                    else
                        File.Move(tempPath, finalPath);               // атомарный Move на том же диске
                }
                else
                {
                    // ничего не записали → удаляем temp, домен пропускаем
                    SafeDelete(tempPath);
                    AnsiConsole.MarkupLine($"[yellow]Skip empty export[/] for [bold]{Markup.Escape(dnsName)}[/].");
                }
            }
            catch (LdapException lex) when (lex.ErrorCode == 81 /*LDAP_SERVER_DOWN*/)
            {
                SafeDelete(tempPath);
                AnsiConsole.MarkupLine($"[yellow]Domain unreachable (LDAP 0x51):[/] {Markup.Escape(dnsName)}");
            }
            catch (COMException cex) when ((uint)cex.ErrorCode == 0x8007203A /* server not operational */)
            {
                SafeDelete(tempPath);
                AnsiConsole.MarkupLine($"[yellow]Domain unreachable (0x8007203A):[/] {Markup.Escape(dnsName)}");
            }
            catch (Exception ex)
            {
                SafeDelete(tempPath);
                AnsiConsole.MarkupLine($"[red]Export failed for {Markup.Escape(dnsName)}[/]: {Markup.Escape(ex.Message)}");
            }
        }

        private static void SafeDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { /* ignore */ }
        }


    }

}
