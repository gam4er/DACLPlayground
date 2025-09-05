# ParseJsonWithSDDLs

## 🇷🇺 Описание

**ParseJsonWithSDDLs** — это утилита командной строки под .NET Framework 4.8 для массового анализа строк SDDL из атрибута **nTSecurityDescriptor** объектов Active Directory. Программа выявляет «широкие» разрешения (например, для *Everyone/Authenticated Users/Domain Users/Domain Computers/Anonymous* и т. п.), формирует человекочитаемый HTML-отчёт и (по желанию) *pipe-delimited* CSV для последующей обработки. При отсутствии входной папки с экспортами утилита **сама выгружает** объекты AD (включая домены леса и целевые стороны трастов) в JSON с постраничным LDAP и корректной загрузкой DACL через **SecurityDescriptorFlagControl**. Для параметров командной строки используется **Spectre.Console.Cli**. ([learn.microsoft.com][1], [Microsoft for Developers][2], [spectreconsole.net][3])

### Ключевая функциональность

* Парсинг SDDL из `nTSecurityDescriptor` и выделение ACE, представляющих риск «широких» прав (GA/GW/CR/WP/WD/WO/CC и др.).
* Авто-экспорт в `exports/*.json`, если `--input` не указан: все домены леса + целевые стороны трастов. Экспорт потоковый, с LDAP-пейджингом (**PageResultRequestControl**), и чтением SDDL/DACL (**SecurityDescriptorFlagControl**). ([learn.microsoft.com][4])
* Переиспользуемый кэш прав/атрибутов схемы: `<domain>_rights.json` и `<domain>_attributes.json`, обновляемый по `--update-cache`.
* Фильтрация объектов по DN по подстроке из текстового файла исключений (одна строка — одно правило).
* Отчёты:

  * **HTML** (`Interesting.htm`) с таблицами (Spectre.Console),
  * **CSV** (`Interesting.csv`) — опционально, разделитель `|` (упрощает пост-обработку).
* Устойчивость к недоступным КД: пустые/битые JSON не сохраняются (запись через `*.tmp` + атомарный `Move/Replace`), такие домены пропускаются без падений.
* Корректная CLI-валидация через `CommandSettings.Validate()` (Spectre). ([spectreconsole.net][5])

---

## 🇷🇺 Установка и требования

* **.NET Framework 4.8** (целевой фреймворк проекта).
* Сборочные ссылки/пакеты:

  * `System.DirectoryServices`, `System.DirectoryServices.Protocols`, `System.DirectoryServices.ActiveDirectory`.
  * `Newtonsoft.Json` (NuGet).
  * `Spectre.Console` + `Spectre.Console.Cli` (NuGet).
    Роль пространств имён и классов:
    – **LdapConnection**, **PageResultRequestControl** — постраничное чтение LDAP. ([learn.microsoft.com][6])
    – **SecurityDescriptorFlagControl** — запрос DACL/Owner/Group вместе с результатами поиска. ([learn.microsoft.com][7])
    – **Domain.GetAllTrustRelationships** / **TrustRelationshipInformation** — получение целевых доменов трастов. ([learn.microsoft.com][8])
    – **Spectre.Console.Cli** — команды/настройки/валидация. ([spectreconsole.net][3])
* Доступ к LDAP с правами, достаточными для чтения `nTSecurityDescriptor` (без SACL).

---

## 🇷🇺 Параметры командной строки

| Параметр                    | Описание                                                                                                        | Пример                       |
| --------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| `-i, --input <FOLDER>`      | Папка с исходными `*.json` экспортами. Если **не указана** — экспорты будут сгенерированы автоматически.        | `--input D:\AD\Exports`      |
| `--csv`                     | Включить генерацию `Interesting.csv` (pipe-delimited).                                                          | `--csv`                      |
| `-u, --update-cache`        | Обновить/пересоздать кэш `<domain>_rights.json` и `<domain>_attributes.json`. Если отсутствуют — будут созданы. | `--update-cache`             |
| `-e, --exclude-file <PATH>` | Текстовый файл с подстроками для исключения объектов по DN (по строке на правило).                              | `--exclude-file D:\ex.txt`   |
| `--export-output <FOLDER>`  | Куда сохранять автогенерацию экспортов, если `--input` не задан. По умолчанию `./exports`.                      | `--export-output D:\AD\Auto` |
| `--export-overwrite`        | При автогенерации перезаписывать существующие JSON. По умолчанию не перезаписывает.                             | `--export-overwrite`         |

### Примеры

1. Прогон по готовым экспортам, с CSV, обновить кэш прав/атрибутов:

```
ParseJsonWithSDDLs.exe --input D:\AD\Exports --csv --update-cache
```

2. Без `--input`: автогенерация экспортов в `./exports`, затем анализ, HTML-отчёт:

```
ParseJsonWithSDDLs.exe
```

3. Автогенерация в свою папку с перезаписью + CSV + исключения по DN:

```
ParseJsonWithSDDLs.exe --export-output D:\AD\Auto --export-overwrite --csv --exclude-file D:\exclude.txt
```

---

## 🇷🇺 Входные и выходные файлы

### Вход (экспорты объектов AD, JSON-массив)

* Расположение: `--input <FOLDER>` или автогенерация в `--export-output` (по умолчанию `exports\`).
* Формат элемента (один объект AD), поля соответствуют классу `Record`:

```json
{
  "distinguishedName": "CN=User1,OU=People,DC=example,DC=com",
  "name": "User1",
  "sAMAccountName": "user1",
  "sid": "S-1-5-21-...-1105",
  "guid": "2f2c1f3e-dc5f-4d2a-9b43-9a7c2f6e0aab",
  "sddl": "O:...G:...D:(A;;RPWP;;;AU)..."
}
```

* Экспорт создаётся потоково (JSON-массив) постраничными LDAP-поисками (**PageResultRequestControl**); для получения DACL используется **SecurityDescriptorFlagControl** (Dacl|Owner|Group). ([learn.microsoft.com][4])
* При недоступности домена файл **не создаётся** (пишется во временный `*.tmp`, сохраняется только непустой массив).

### Выход

* **HTML**: `Interesting.htm` — таблицы объектов/пользователей/ACE (рендер на базе Spectre.Console).

* **CSV**: `Interesting.csv` — опциональный, включается `--csv`. Разделитель: `|` (pipe). Поля:

  ```
  DistinguishedName|Identity|AccessControlType|ActiveDirectoryRight|ObjectType
  ```

  `Identity` — дружественное имя SID (попытка Resolve через well-known SID’ы и `LookupAccountSid`).
  `ActiveDirectoryRight` — декодированные коды прав (GA/GW/CR/WP/WD/WO/CC/… → человекочитаемые).

* **Кэш**:

  * `<domain>_rights.json` — карта `{ rightsGuid => { name, rightsGuid, objectGUID } }` из `CN=Extended-Rights` и `attributeSecurityGUID=*`.
  * `<domain>_attributes.json` — карта `{ schemaIDGUID => { name, attributeID, attributeSyntax, objectGUID, schemaIDGUID } }`.
    Поведение: использовать кэш если есть, иначе создать; форс-обновление — `--update-cache`.

* **Файл исключений** (вход): произвольный `*.txt`, каждая строка — подстрока для поиска в DN; совпадение → объект пропускается.

---

## 🇷🇺 Логика анализа и критерии «широких» разрешений

* «Широкие» субъекты: `DG, DU, DC, BG, LG, AU, WD, AN` и соответствующие well-known SID’ы/числовые SID-группы (включая S-1-1-0, S-1-5-7, S-1-5-11, и т. п.).
* «Опасные» права (наличие любого): `GA, GW, WO, WD, CR, WP, CC` → декодируются в человекочитаемые значения (см. `Rights.DecodeAccessRights`).
* ACE типа `D`/`OD` (deny) игнорируются.
* Ряд ложноположительных кейсов отфильтрован жёсткими исключениями (DNS-зона, GPO-контейнер и др.).

Синтаксис SDDL и смысл DACL/ACE см. официальные материалы Microsoft и статьи по SDDL. ([learn.microsoft.com][1], [TECHCOMMUNITY.MICROSOFT.COM][9])

---

## 🇷🇺 Архитектура и внутренности

* **Парсер SDDL** — регулярные выражения по общему шаблону SD и ACE с пост-обработкой (разбор прав, целевых GUID прав/атрибутов из кэша).
* **Экспорт LDAP** — `LdapConnection` (Negotiate, v3, Sealing, no referrals), `SearchRequest` со списком атрибутов (`name`, `sAMAccountName`, `nTSecurityDescriptor`, `objectGUID`, `objectSid`, `distinguishedName`), `PageResultRequestControl` для постраничного чтения, `SecurityDescriptorFlagControl` для выдачи SD полей. ([learn.microsoft.com][6])
* **Охват доменов** — `Forest.GetCurrentForest().Domains` + `Domain.GetAllTrustRelationships()` + `CN=System, trustedDomain` → получаем универсальный пул DNS-имён. ([learn.microsoft.com][8])
* **CLI** — `Command<AppSettings>` с валидацией через `AppSettings.Validate()` (Spectre). ([spectreconsole.net][3])
* **Устойчивость** — для экспорта используется временный файл `*.tmp` и атомарный `Move/Replace`; пустые/битые JSON пропускаются при чтении.

---

## 🇷🇺 Рекомендации и ограничения

* **Привилегии**: для чтения `nTSecurityDescriptor` достаточно обычных прав чтения AD-объектов (SACL не запрашивается).
* **Производительность**: на больших лесах используйте отдельный сервер ближе к КД, держите `PageSize` разумным (≤ server-side limit), запускайте под учёткой с TGT/Kerberos и доступом к DC. ([learn.microsoft.com][4])
* **Точность кэша**: при изменении схемы/расширенных прав — запускайте с `--update-cache`.

---

## 🇷🇺 Благодарности и ссылки

* **SDDL (официально)** — Microsoft Learn: определение и синтаксис. ([learn.microsoft.com][1])
* **SDDL (обзор)** — Raymond Chen, Old New Thing. ([Microsoft for Developers][2])
* **LDAP пейджинг** — Microsoft: Paged Results control. ([learn.microsoft.com][4])
* **SecurityDescriptorFlagControl** — Microsoft API. ([learn.microsoft.com][7])
* **LdapConnection** — Microsoft API. ([learn.microsoft.com][6])
* **TrustRelationshipInformation** — Microsoft API. ([learn.microsoft.com][8])
* **Spectre.Console.Cli** — создание команд и валидация. ([spectreconsole.net][3])

---

## 🇬🇧 English

### Description

**ParseJsonWithSDDLs** is a .NET Framework 4.8 command-line utility for bulk analysis of **nTSecurityDescriptor** SDDL strings from Active Directory objects. It detects “overly broad” permissions (e.g., granted to *Everyone/Authenticated Users/Domain Users/Domain Computers/Anonymous*), and produces a human-readable **HTML** report plus an optional *pipe-delimited* **CSV**. When no input folder is provided, the tool **self-exports** AD objects (covering all forest domains and trust targets) into JSON using LDAP paging and **SecurityDescriptorFlagControl** to retrieve DACLs. Command-line parsing & validation is done with **Spectre.Console.Cli**. ([learn.microsoft.com][1], [spectreconsole.net][3])

### Features

* SDDL parsing from `nTSecurityDescriptor`, extraction of risky ACEs (GA/GW/CR/WP/WD/WO/CC…).
* Auto-export to `exports/*.json` if `--input` is missing: all forest domains + trust targets. Streaming JSON array with LDAP paging (**PageResultRequestControl**) and SD retrieval (**SecurityDescriptorFlagControl**). ([learn.microsoft.com][4])
* Reusable rights/schema caches: `<domain>_rights.json`, `<domain>_attributes.json` (force refresh via `--update-cache`).
* DN-based object exclusion from a plain text file (one substring per line).
* Reports: **HTML** (`Interesting.htm`) and optional **CSV** (`Interesting.csv`, `|` delimiter).
* Robustness: temporary `*.tmp` + atomic `Move/Replace`; empty/invalid JSON files are skipped; unreachable DCs are tolerated.
* Proper CLI validation via `CommandSettings.Validate()`. ([spectreconsole.net][5])

### Command-line options

| Option                      | Description                                                                                     | Example                      |
| --------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------- |
| `-i, --input <FOLDER>`      | Folder with input `*.json` exports. If **omitted**, exports are auto-generated.                 | `--input D:\AD\Exports`      |
| `--csv`                     | Enable CSV output (`Interesting.csv`, pipe-delimited).                                          | `--csv`                      |
| `-u, --update-cache`        | Refresh/recreate `<domain>_rights.json` & `<domain>_attributes.json`. Creates them if missing.  | `--update-cache`             |
| `-e, --exclude-file <PATH>` | Text file with DN substrings to skip (one per line).                                            | `--exclude-file D:\ex.txt`   |
| `--export-output <FOLDER>`  | Output folder for auto-generated exports when `--input` is not specified. Default: `./exports`. | `--export-output D:\AD\Auto` |
| `--export-overwrite`        | Overwrite existing JSON during auto-generation. Off by default.                                 | `--export-overwrite`         |

**Examples**

* Run over existing exports, produce CSV, refresh caches:

  ```
  ParseJsonWithSDDLs.exe --input D:\AD\Exports --csv --update-cache
  ```
* No `--input`: auto-generate exports into `./exports`, then analyze & emit HTML report:

  ```
  ParseJsonWithSDDLs.exe
  ```
* Auto-generate into a custom folder with overwrite + CSV + DN exclusions:

  ```
  ParseJsonWithSDDLs.exe --export-output D:\AD\Auto --export-overwrite --csv --exclude-file D:\exclude.txt
  ```

### Input & output

**Input (JSON exports, array)**
Generated into `--export-output` (default `exports\`) or provided via `--input`. Each element contains:

```json
{ "distinguishedName": "...", "name": "...", "sAMAccountName": "...",
  "sid": "S-1-5-...", "guid": "....", "sddl": "O:...G:...D:(A;;RPWP;;;AU)..." }
```

Export relies on **LdapConnection** with **PageResultRequestControl** and **SecurityDescriptorFlagControl** to obtain DACLs. Empty/broken JSON files are never committed (temporary file is deleted). ([learn.microsoft.com][6])

**Output**

* **HTML**: `Interesting.htm` (tables rendered via Spectre.Console).
* **CSV**: `Interesting.csv` (optional, pipe-delimited) with columns:

  ```
  DistinguishedName|Identity|AccessControlType|ActiveDirectoryRight|ObjectType
  ```
* **Caches**: `<domain>_rights.json` and `<domain>_attributes.json` as described above.

### How it works

* **SDDL parsing**: regex-based split of SD and ACEs, decode rights, resolve target GUIDs against caches.
* **Forest & trusts coverage**: `Forest.GetCurrentForest().Domains` + `Domain.GetAllTrustRelationships()` + `CN=System` (`trustedDomain`) to collect DNS names for export. ([learn.microsoft.com][8])
* **CLI**: `Command<AppSettings>` with `Validate()` for argument checks. ([spectreconsole.net][3])

### Recommendations / limitations

* **Privileges**: standard directory read access is sufficient for DACL (SACL is not requested).
* **Performance**: keep page size within server-side limits; run close to DCs; prefer Kerberos. ([learn.microsoft.com][4])
* **Cache freshness**: run with `--update-cache` after schema/rights changes.

### References

* **SDDL (official)** — Microsoft Learn. ([learn.microsoft.com][1])
* **SDDL (overview)** — Old New Thing. ([Microsoft for Developers][2])
* **LDAP paging** — Microsoft Docs (Paged Results control). ([learn.microsoft.com][4])
* **SecurityDescriptorFlagControl** — Microsoft API. ([learn.microsoft.com][7])
* **LdapConnection** — Microsoft API. ([learn.microsoft.com][6])
* **Trust relationships** — Microsoft API. ([learn.microsoft.com][8])
* **Spectre.Console.Cli** — Commands & validation. ([spectreconsole.net][3])

---

### Примечания к проектному коду

* **Экспорт** реализован в `ForestExport.cs` (параллельная обработка, атомарная запись).&#x20;
* **Разбор SDDL и генерация отчётов** — `ParseSDDL.cs` (фильтры по DN, CSV-output, HTML на Spectre).&#x20;
* **Загрузка/стриминг JSON** — `ParseJsonWithSDDLs.cs` (Record/RecordStreamLoader, обработка пустых/не-array JSON, кэш прав/атрибутов, CLI).&#x20;
* **Расшифровка прав** — `Rights.cs`.&#x20;
* **Well-known SIDs** — `SddlSidStrings.cs`.&#x20;
* **Поиск Extended Rights и Schema Attributes** — `AllLookup.cs` + `FillDomainData`.&#x20;

Если захочешь, добавлю раздел «Threat model / detection mapping» (MITRE, сценарии злоупотребления широкими правами) и JSON-схему в `docs/`.

[1]: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language?utm_source=chatgpt.com "Security Descriptor Definition Language - Win32 apps"
[2]: https://devblogs.microsoft.com/oldnewthing/20220510-00/?p=106640&utm_source=chatgpt.com "A brief summary of the various versions of the Security ..."
[3]: https://spectreconsole.net/cli/commands?utm_source=chatgpt.com "Creating Commands"
[4]: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/paging-search-results?utm_source=chatgpt.com "Paging Search Results | Microsoft Learn"
[5]: https://spectreconsole.net/api/spectre.console.cli/commandsettings/5ddb132e?utm_source=chatgpt.com "Spectre.Console - Validate()"
[6]: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection?view=net-9.0-pp&utm_source=chatgpt.com "LdapConnection Class (System.DirectoryServices.Protocols)"
[7]: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.securitydescriptorflagcontrol?view=netframework-4.8.1&utm_source=chatgpt.com "SecurityDescriptorFlagControl Class (System.DirectoryServices ..."
[8]: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?view=windowsdesktop-9.0&utm_source=chatgpt.com "Domain.GetAllTrustRelationships Method"
[9]: https://techcommunity.microsoft.com/blog/askds/the-security-descriptor-definition-language-of-love-part-1/395202?utm_source=chatgpt.com "The Security Descriptor Definition Language of Love (Part 1)"
