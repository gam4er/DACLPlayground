using Newtonsoft.Json;

using Spectre.Console;
using Spectre.Console.Cli;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;


namespace ParseJsonWithSDDLs
{
    sealed class AppSettings : CommandSettings
    {
        [Description("Папка с входными *.json файлами (экспорт объектов AD). Если не указана — экспорт будет сгенерирован автоматически.")]
        [CommandOption("-i|--input <FOLDER>")]
        public string InputFolder { get; set; }

        [Description("Файл с исключениями DN (подстроки, по одной в строке).")]
        [CommandOption("-e|--exclude-file <PATH>")]
        public string ExcludeFile { get; set; }

        [Description("Генерировать CSV-вывод.")]
        [CommandOption("--csv")]
        public bool Csv { get; set; }

        [Description("Обновить/пересоздать кэш прав и GUID.")]
        [CommandOption("-u|--update-cache")]
        public bool UpdateCache { get; set; }

        [Description("Папка для автогенерации экспортов, если --input не указан. По умолчанию: ./exports")]
        [CommandOption("--export-output <FOLDER>")]
        public string ExportOutput { get; set; } = "exports";

        [Description("Перезаписывать уже существующие JSON при автогенерации.")]
        [CommandOption("--export-overwrite")]
        public bool ExportOverwrite { get; set; }

        public override ValidationResult Validate()
        {
            if (!string.IsNullOrEmpty(InputFolder) && !Directory.Exists(InputFolder))
                return ValidationResult.Error($"Input folder not found: {InputFolder}");

            if (!string.IsNullOrEmpty(ExcludeFile) && !File.Exists(ExcludeFile))
                return ValidationResult.Error($"Exclude file not found: {ExcludeFile}");

            // Экспортная папка создастся позже при необходимости
            return ValidationResult.Success();
        }
    }


    internal sealed class Record
    {
        public Record(string distinguishedName, string name, string sAMAccountName, string sid, string guid, string sddl)
        {
            Sid = sid; Guid = guid; Sddl = sddl;
            DistinguishedName = distinguishedName; Name = name; SamAccountName = sAMAccountName;
        }

        public string DistinguishedName { get; }
        public string Name { get; }
        public string SamAccountName { get; }
        public string Sid { get; }
        public string Guid { get; }
        public string Sddl { get; }
    }

    internal static class RecordLoader
    {
        public static List<Record> Load(string jsonPath)
        {
            var json = File.ReadAllText(jsonPath);

            // Newtonsoft умеет мапить параметры конструктора ↔ поля JSON
            return JsonConvert.DeserializeObject<List<Record>>(json)
                   ?? new List<Record>();
        }
    }

    
    internal static class RecordStreamLoader
    {
        public static IEnumerable<Record> Stream(string path)
        {
            var sr = new StreamReader(path);
            var jr = new JsonTextReader(sr)
            {
                // подстраховка: читаем длинные строки без ограничения
                MaxDepth = null
            };

            var ser = new JsonSerializer();

            if (!jr.Read() || jr.TokenType != JsonToken.StartArray)
                throw new JsonException("Ожидался JSON-массив.");

            while (jr.Read())
            {
                if (jr.TokenType == JsonToken.EndArray)
                    yield break;

                // jr сейчас стоит на StartObject → десериализуем один элемент
                yield return ser.Deserialize<Record>(jr);
            }
        }
    }

    

    public class ParseJsonWithSDDLs
    {
        public static Dictionary<string,ExtendedRight> rights = new Dictionary<string, ExtendedRight>();

        public static Dictionary<string, SchemaAttribute> attrs = new Dictionary<string, SchemaAttribute>();
        
        public static string reportPath = "Interesting.csv";

        public static bool GenerateCsv = false;
        public static HashSet<string> Exclusions = new(StringComparer.OrdinalIgnoreCase);


        static void LoadDomainCacheFromFiles(string server)
        {
            rights.Clear();
            attrs.Clear();

            var js = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };

            var rightsPath = $"{server}_rights.json";
            var attrsPath = $"{server}_attributes.json";

            if (File.Exists(rightsPath))
            {
                var json = File.ReadAllText(rightsPath);
                var data = js.Deserialize<Dictionary<string, ExtendedRight>>(json);
                if (data != null) rights = data;
            }

            if (File.Exists(attrsPath))
            {
                var json = File.ReadAllText(attrsPath);
                var data = js.Deserialize<Dictionary<string, SchemaAttribute>>(json);
                if (data != null) attrs = data;
            }
        }

        static void LoadExclusions(string path)
        {
            Exclusions.Clear();
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return;

            foreach (var line in File.ReadAllLines(path))
            {
                var rule = line.Trim();
                if (!string.IsNullOrEmpty(rule))
                    Exclusions.Add(rule);
            }

            AnsiConsole.WriteLine($"Loaded {Exclusions.Count} DN-exclude patterns.");
        }


        static void EnsureDomainData(string server, bool updateCache)
        {
            var rightsPath = $"{server}_rights.json";
            var attrsPath = $"{server}_attributes.json";

            bool haveCache = File.Exists(rightsPath) && File.Exists(attrsPath);

            if (updateCache || !haveCache)
            {
                try
                {
                    FillDomainData(server); // как и прежде: по итогу она пишет оба json
                }
                catch (COMException cex) when ((uint)cex.ErrorCode == 0x8007203A)
                {
                    // сервер недоступен — используем имеющийся кэш, либо пропускаем
                    if (haveCache)
                    {
                        LoadDomainCacheFromFiles(server);
                        AnsiConsole.MarkupLine($"[yellow]Use cached rights/attrs for unreachable DC[/]: {Markup.Escape(server)}");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[yellow]No rights/attrs for unreachable DC[/]: {Markup.Escape(server)}");
                        rights.Clear(); attrs.Clear();
                    }
                    return;
                }
            }
            else
            {
                LoadDomainCacheFromFiles(server);
                Console.WriteLine($"Loaded cached rights/attrs for {server}: {rights.Count}/{attrs.Count}.");
            }
        }


        public static void FillDomainData (string Server)
        {
            rights.Clear();
            attrs.Clear();

            var rootDse = new DirectoryEntry(string.Format("LDAP://{0}/RootDSE", Server));
            var configNC = rootDse.Properties ["configurationNamingContext"].Value.ToString();
            var schemaNC = rootDse.Properties ["schemaNamingContext"].Value.ToString();

            // ---------- Extended & Valid rights ----------            

            string extRightsPath = $"LDAP://CN=Extended-Rights,{configNC}";
            foreach (var p in DirectoryHelper.Query(
                         extRightsPath,
                         "(objectClass=controlAccessRight)",
                         "name", "rightsGuid", "objectGUID"))
            {
                string rightsGuid = DirectoryHelper.GetSingleString(p, "rightsGuid").ToUpper();
                string name = DirectoryHelper.GetSingleString(p, "name");
                string objectGUID = DirectoryHelper.GetSingleString(p, "objectGUID").ToUpper();
                if (rights.ContainsKey(rightsGuid))
                    rights [rightsGuid].name += " | " + name;
                else
                    rights.Add(rightsGuid, new ExtendedRight
                    {
                        name = name,
                        rightsGuid = rightsGuid,
                        objectGUID = objectGUID
                    });
            }

            // ------------------ attributeSecurityGUID ------------------
            string schemaPath = $"LDAP://{schemaNC}";
            foreach (var p in DirectoryHelper.Query(
                         schemaPath,
                         "(attributeSecurityGUID=*)",
                         "name", "attributeSecurityGUID", "objectGUID",
                         "attributeID", "attributeSyntax", "schemaIDGUID"))
            {
                string schemaIDGUID = DirectoryHelper.GetSingleString(p, "schemaIDGUID").ToUpper();
                string name = DirectoryHelper.GetSingleString(p, "name");
                string objectGUID = DirectoryHelper.GetSingleString(p, "objectGUID").ToUpper();
                if (!String.IsNullOrEmpty(schemaIDGUID))
                {
                    if (rights.ContainsKey(schemaIDGUID))
                        rights [schemaIDGUID].name += " | " + name;
                    else
                        rights.Add(schemaIDGUID, new ExtendedRight
                        {
                            name = name,
                            rightsGuid = schemaIDGUID,
                            objectGUID = objectGUID
                        });
                }
            }

            // ---------- 3) Attribute schema ----------

            foreach (var p in DirectoryHelper.Query(
                         schemaPath,
                         "(|(objectClass=attributeSchema)(objectClass=classSchema))",
                         "cn", "attributeID", "attributeSyntax", "schemaIDGUID", "objectGUID"))
            {
                string name = DirectoryHelper.GetSingleString(p, "cn");
                string attributeID = DirectoryHelper.GetSingleString(p, "attributeID");
                string attributeSyntax = DirectoryHelper.GetSingleString(p, "attributeSyntax");
                string objectGUID = DirectoryHelper.GetSingleString(p, "objectGUID").ToUpper();
                string schemaIDGUID = DirectoryHelper.GetSingleString(p, "schemaIDGUID").ToUpper();

                if (attrs.ContainsKey(schemaIDGUID))
                    attrs [schemaIDGUID].name += " | " + name;
                else
                    attrs.Add(schemaIDGUID, new SchemaAttribute
                    {
                        name = name,
                        attributeID = attributeID,
                        attributeSyntax = attributeSyntax,
                        objectGUID = objectGUID,
                        schemaIDGUID = schemaIDGUID
                    });
            }

            // ---------- 4) сериализовать ----------
            var js = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };

            File.WriteAllText(string.Format("{0}_rights.json", Server), js.Serialize(rights));
            File.WriteAllText(string.Format("{0}_attributes.json", Server), js.Serialize(attrs));

            AnsiConsole.WriteLine($"Saved {rights.Count} extended rights and {attrs.Count} schema attributes.");

        }

        sealed class ProcessCommand : Command<AppSettings>
        {
            public override int Execute(CommandContext context, AppSettings settings)
            {
                ParseJsonWithSDDLs.GenerateCsv = settings.Csv;
                LoadExclusions(settings.ExcludeFile);

                string inputFolder = settings.InputFolder;

                // ❶ Если --input НЕ указан → автогенерация экспортов
                if (string.IsNullOrWhiteSpace(inputFolder))
                {
                    inputFolder = settings.ExportOutput;
                    AnsiConsole.MarkupLine($"[yellow]--input не задан.[/] Автогенерация экспортов в: [bold]{Markup.Escape(inputFolder)}[/]");
                    ForestExport.ExportAll(inputFolder, settings.ExportOverwrite);
                }

                // ❷ CSV-шапка при необходимости
                if (ParseJsonWithSDDLs.GenerateCsv && !File.Exists(ParseJsonWithSDDLs.reportPath))
                {
                    File.WriteAllText(ParseJsonWithSDDLs.reportPath,
                        "DistinguishedName,Identity,AccessControlType,ActiveDirectoryRight,ObjectType\n", Encoding.UTF8);
                }

                AnsiConsole.Record();

                // ❸ Права/атрибуты: используем/пересобираем кэш на каждый server.json
                foreach (var filePath in Directory.EnumerateFiles(inputFolder, "*.json", System.IO.SearchOption.TopDirectoryOnly))
                {
                    // быстрый фильтр пустышек
                    var fi = new FileInfo(filePath);
                    if (fi.Length < 3) // "[]" — 2 байта, плюс возможен CR/LF
                    {
                        AnsiConsole.MarkupLine($"[yellow]Skip empty file[/]: {Markup.Escape(filePath)}");
                        continue;
                    }

                    // дополнительно: элементарная валидация, что это JSON-массив
                    using (var fs = File.OpenRead(filePath))
                    using (var sr = new StreamReader(fs, Encoding.UTF8, true, 4096, leaveOpen: false))
                    {
                        int first = sr.Peek();
                        if (first != '[') // наш экспортер пишет массив
                        {
                            AnsiConsole.MarkupLine($"[yellow]Skip non-array JSON[/]: {Markup.Escape(filePath)}");
                            continue;
                        }
                    }

                    string server = Path.GetFileNameWithoutExtension(filePath);

                    // если домен недоступен сейчас — FillDomainData может упасть → обернём и пропустим
                    try
                    {
                        EnsureDomainData(server, settings.UpdateCache);
                    }
                    catch (COMException cex) when ((uint)cex.ErrorCode == 0x8007203A)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Skip rights/attrs for unreachable DC[/]: {Markup.Escape(server)}");
                        continue;
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Skip rights/attrs for {Markup.Escape(server)}[/]: {Markup.Escape(ex.Message)}");
                        continue;
                    }

                    // стримим записи
                    foreach (var rec in RecordStreamLoader.Stream(filePath))
                        ParseSDDL.CheckSDDL(rec.Sddl, rec.DistinguishedName);
                }


                File.WriteAllText("Interesting.htm", AnsiConsole.ExportHtml(), Encoding.UTF8);
                AnsiConsole.Clear();
                return 0;
            }
        }


        static int Main(string [] args)
        {
            var app = new CommandApp<ProcessCommand>();
            app.Configure(cfg =>
            {
                cfg.SetApplicationName("ParseJsonWithSDDLs");
                cfg.ValidateExamples(); // необязательно, просто полезно
            });

            try
            {
                return app.Run(args);
            }
            catch (CommandParseException ex)
            {
                AnsiConsole.MarkupLine($"[red]Ошибка парсинга аргументов:[/] {ex.Message}");
                return -1;
            }
        }

    }
}
