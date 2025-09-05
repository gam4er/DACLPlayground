using Spectre.Console;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ParseJsonWithSDDLs
{
    public static class ParseSDDL
    {
        static string LookupAccountSidFallback(SecurityIdentifier sid)
        {
            byte [] sidBytes = new byte [sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            // Первичный вызов для размеров буферов
            var nameLen = 0;
            var domainLen = 0;
            SID_NAME_USE use;
            LookupAccountSid(null, sidBytes, null, ref nameLen, null, ref domainLen, out use);

            var name = new StringBuilder(nameLen);
            var domain = new StringBuilder(domainLen);

            if (!LookupAccountSid(null, sidBytes, name, ref nameLen, domain, ref domainLen, out use))
                return null;

            // Собираем DOMAIN\Name (если домена нет — просто Name)
            return domain.Length > 0 ? $"{domain}\\{name}" : name.ToString();
        }

        // P/Invoke
        public enum SID_NAME_USE
        {
            User = 1, Group, Domain, Alias, WellKnownGroup, DeletedAccount,
            Invalid, Unknown, Computer, Label
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupAccountSid(
            string lpSystemName,        // null = локальная машина / система сама решит
            byte [] Sid,
            StringBuilder Name,
            ref int cchName,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse
        );


        static void AppendCsv(
            string path,
            string DistinguishedName,
            string Identity,
            string AccessControlType,
            string ActiveDirectoryRight,
            string ObjectType)
        {
            // Экранируем кавычки и запятые
            string Escape(string v) => $"\"{v.Replace("\"", "\"\"")}\"";

            var line = string.Join("|",
                Escape(DistinguishedName),
                Escape(Identity),
                Escape(AccessControlType),
                Escape(ActiveDirectoryRight),
                Escape(ObjectType)
            );

            File.AppendAllText(path, line + Environment.NewLine);
        }

        public static void CheckSDDL(string SDDL, string DN)
        {
            if (ParseJsonWithSDDLs.Exclusions.Count > 0)
            {
                foreach (var needle in ParseJsonWithSDDLs.Exclusions)
                {
                    if (DN?.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                        return; // пропускаем объект
                }
            }

            string pattern_all = @"^
            (?:
              O:(?<OwnerSID>S-\d+(-\d+)+|[A-Z]{2})
            )?
            (?:
              G:(?<GroupSID>S-\d+(-\d+)+|[A-Z]{2})
            )?
            (?:
              D:
              (?<DACLFlags>[PARI]{0,5})
              (?<DACLACEs>(?:\([^\)]+\))+)
            )?
            (?:
              S:
              (?<SACLFlags>[PARI]{0,5})
              (?<SACLACEs>(?:\([^\)]+\))+)
            )?
            $";

            RegexOptions options = RegexOptions.IgnorePatternWhitespace | RegexOptions.Singleline | RegexOptions.IgnoreCase;
            Regex regex_all = new Regex(pattern_all, options);
            Match match_all = regex_all.Match(SDDL);

            Dictionary<string, Dictionary<string, string>> ACEs = new Dictionary<string, Dictionary<string, string>>();

            if (match_all.Success)
            {
                //if (opts.Verbose)
                {
                    //Console.WriteLine("SDDL строка валидна.");
                    //Console.WriteLine($"SID владельца:\t\t{match_all.Groups ["OwnerSID"].Value}");
                    //Console.WriteLine($"SID группы:\t\t{match_all.Groups ["GroupSID"].Value}");
                    //Console.WriteLine($"Флаги DACL:\t\t{match_all.Groups ["DACLFlags"].Value}");
                    //Console.WriteLine($"ACE DACL: {match_all.Groups ["DACLACEs"].Value}");
                    //Console.WriteLine($"Флаги SACL:\t\t{match_all.Groups ["SACLFlags"].Value}");
                    //Console.WriteLine($"ACE SACL: {match_all.Groups ["SACLACEs"].Value}");
                    //Console.WriteLine("====================================");
                }
                string pattern_acl = @"\(([A-Z]{1,2});([A-Z]{0,18});([^;]*?);([a-f0-9\-]{36})?;([a-f0-9\-]{36})?;(S-\d+(-\d+)+|[A-Z]{2})\)";
                Regex regex_acl = new Regex(pattern_acl, options);
                Match match_acls = regex_acl.Match(match_all.Groups ["DACLACEs"].Value);

                while (match_acls.Success)
                {
                    string ace_type = match_acls.Groups [1].Value;
                    if (ace_type.ToUpper() == "OD" ||
                        ace_type.ToUpper() == "D"
                        )
                    {
                        match_acls = match_acls.NextMatch();
                        continue;
                    }
                    string ace_flags = match_acls.Groups [2].Value;
                    string ace_rights = match_acls.Groups [3].Value;
                    string ace_object_guid = match_acls.Groups [4].Value.ToUpper();
                    string ace_inherit_object_guid = match_acls.Groups [5].Value.ToUpper();
                    string ace_account_sid = match_acls.Groups [6].Value.ToUpper();
                    string current_ACE = match_acls.Value.ToUpper();

                    #region HardcodedExclusions

                    if (current_ACE.Contains("OA;;CR;AB721A53-1E2F-11D0-9819-00AA0040529B;;WD") ||
                        current_ACE.Contains("OA;;CR;AB721A55-1E2F-11D0-9819-00AA0040529B;;AU") ||
                        (
                            (
                                current_ACE.Contains("A;;SWWPRC;;;AU") ||
                                current_ACE.Contains("A;;CC;;;AU") ||
                                current_ACE.Contains("A;;CCSWWPRC;;;AU")
                            )
                            && 
                            DN.Contains("CN=MicrosoftDNS,CN=System")
                        ) ||
                        (
                            (
                                current_ACE.Contains(";CR;EDACFD8F-FFB3-11D1-B41D-00A0C968F939;") 
                            ) &&
                            DN.Contains("CN=Policies,CN=System")
                        ) 
                    )
                    {
                        match_acls = match_acls.NextMatch();
                        continue;
                    }
                    #endregion

                    bool user_result = false;
                    bool rights_result = false;

                    if (ace_account_sid == "DG" ||              // DOMAIN_GUESTS
                        ace_account_sid == "DU" ||              // DOMAIN_USERS
                        ace_account_sid == "DC" ||              // DOMAIN_COMPUTERS
                        ace_account_sid == "BG" ||              // BUILTIN_GUESTS
                        ace_account_sid == "LG" ||              // GUEST
                        ace_account_sid == "AU" ||              // AUTHENTICATED_USERS
                        ace_account_sid == "WD" ||              // EVERYONE
                        ace_account_sid == "AN" ||              // ANONYMOUS
                        ace_account_sid == "S-1-1-0" ||
                        ace_account_sid == "S-1-5-7" ||
                        ace_account_sid == "S-1-5-11" ||
                        ace_account_sid == "S-1-5-32-545" ||
                        ace_account_sid == "S-1-5-32-546" ||
                        ace_account_sid == "S-1-5-32-560" ||
                        ace_account_sid == "S-1-5-32-562" ||
                        ace_account_sid == "S-1-5-32-571" ||
                        ace_account_sid == "S-1-5-32-581" ||
                        ace_account_sid.EndsWith("-501") ||
                        ace_account_sid.EndsWith("-513") ||
                        ace_account_sid.EndsWith("-514") ||
                        ace_account_sid.EndsWith("-515")
                       )
                    {
                        user_result = true;
                    }

                    var chunks = Enumerable.Range(0, ace_rights.Length / 2).Select(i => ace_rights.Substring(i * 2, 2));

                    rights_result = chunks.Any(x => x == "GW" || // Generic Write  0x40000000
                                                    x == "GA" || // Generic All    0x10000000
                                                    x == "WO" || // Write Owner    0x00080000
                                                    x == "WD" || // Write DAC      0x00040000
                                                    x == "CR" || // Control Access 0x00000100
                                                    x == "WP" || // Write Property 0x00000020
                                                    x == "CC"    // Create Child   0x00000001
                                                   );

                    if (user_result && rights_result)
                    {
                        string converted_ace_rights = Rights.DecodeAccessRights(ace_rights);
                        string converted_object_guid = "";
                        if (ace_object_guid != "")
                            converted_object_guid = ParseJsonWithSDDLs.rights.ContainsKey(ace_object_guid) 
                                ? ParseJsonWithSDDLs.rights[ace_object_guid].name 
                                : ParseJsonWithSDDLs.attrs.ContainsKey(ace_object_guid)
                                    ? ParseJsonWithSDDLs.attrs [ace_object_guid].name
                                    : ace_object_guid;
                        else
                            converted_object_guid = "whole object";

                        if (!ACEs.ContainsKey(ace_account_sid))
                            ACEs.Add(ace_account_sid, new Dictionary<string, string>());
                        ACEs [ace_account_sid].Add(current_ACE, converted_ace_rights + " on " + converted_object_guid);


                        #region 2CSV

                        if (ParseJsonWithSDDLs.GenerateCsv)   // ← ДОБАВИТЬ ЭТУ СТРОКУ
                        {
                            string username;
                            if (!SddlSidStrings.SIDs.TryGetValue(ace_account_sid, out username))
                            {
                                username = LookupAccountSidFallback(new SecurityIdentifier(ace_account_sid));
                                if (username == null)
                                    username = ace_account_sid;
                                /*
                                username = new SecurityIdentifier(ace_account_sid)
                                    .Translate(typeof(NTAccount))
                                    .ToString();
                                */
                            }

                            foreach (var r in converted_ace_rights.Split(',').Select(tmp => tmp.Trim()))
                            {
                                string escaped_DN = DN.Replace("/", "\\/");
                                string [] objectClasses = new string [] { "" };
                                try
                                {
                                    var DirObj = new System.DirectoryServices.DirectoryEntry($"LDAP://{escaped_DN}");
                                    if (DirObj.Properties.Contains("objectClass"))
                                        objectClasses = (new System.DirectoryServices.DirectoryEntry($"LDAP://{escaped_DN}")
                                            .Properties ["objectClass"])
                                            .Cast<string>()
                                            .ToArray();
                                }
                                catch (COMException ex) when ((uint)ex.ErrorCode == 0x8007200a) // E_ADS_PROPERTY_NOT_FOUND
                                {
                                    //Console.WriteLine("Свойство 'objectClass' отсутствует у объекта.");
                                }
                                catch
                                {
                                }

                                foreach (string s in objectClasses)
                                    AppendCsv(ParseJsonWithSDDLs.reportPath, DN, username, r, converted_object_guid, s);

                            }
                        }
                        #endregion
                    }

                    match_acls = match_acls.NextMatch();
                }

                if(ACEs.Count == 0)
                    return;

                var t = new Table()
                    .Border(TableBorder.DoubleEdge)
                    .Title(string.Format("[red]{0}[/]",DN))
                    .AddColumn(new TableColumn("[u]User[/]"))
                    .AddColumn(new TableColumn("[u]ACE[/]"))
                    ;
                t.Expand();
                t.ShowRowSeparators = true;

                // Добавление данных в основную таблицу
                foreach (var user in ACEs)
                {
                    string username;
                    if (!SddlSidStrings.SIDs.TryGetValue(user.Key, out username))
                    {
                        username = LookupAccountSidFallback(new SecurityIdentifier(user.Key));
                        if (username == null)
                            username = user.Key;
                    }

                    // Создаем вложенную таблицу для пары "ключ-значение"
                    var Explain = new Table()
                        .AddColumn(new TableColumn("[u]ACE[/]"))
                        .AddColumn(new TableColumn("[u]Explain[/]"));

                    Explain.ShowRowSeparators = true;

                    // Добавляем строки в вложенную таблицу
                    foreach (var kvp in user.Value)
                    {
                        Explain.AddRow($"[green]{kvp.Key}[/]", $"[blue]{kvp.Value}[/]");
                    }

                    Explain.Expand()/*.HideHeaders()*/.NoBorder();
                    //Explain.Border = TableBorder.Minimal;
                    //Explain.ShowRowSeparators = true;

                    // Добавляем пользователя и его вложенную таблицу в основную таблицу
                    t.AddRow(new Markup($"[Cyan]{username}[/]"), Explain);
                    /*
                    if (SddlSidStrings.SIDs.TryGetValue(user.Key, out string username))
                        t.AddRow(new Markup($"[Cyan]{username}[/]"), Explain);
                    else
                        t.AddRow(new Markup($"[Cyan]{user.Key}[/]"), Explain);
                    */
                }

                t.Expand();
                AnsiConsole.Write(t);
            }
            else
            {
                AnsiConsole.WriteLine("SDDL строка невалидна.");
            }            
        }        
    }
}
