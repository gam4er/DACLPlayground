using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ParseJsonWithSDDLs
{
    public static class SddlSidStrings
    {
        // Dictionary mapping SDDL SID strings to constants from Sddl.h
        public static Dictionary<string, string> SIDs = new Dictionary<string, string>
        {
            // Well-known SIDs
            { "AA", "ACCESS_CONTROL_ASSISTANCE_OPS" },
            { "AC", "ALL_APP_PACKAGES" },
            { "AN", "ANONYMOUS" },
            { "AO", "ACCOUNT_OPERATORS" },
            { "AU", "AUTHENTICATED_USERS" },
            { "BA", "BUILTIN_ADMINISTRATORS" },
            { "BG", "BUILTIN_GUESTS" },
            { "BU", "BUILTIN_USERS" },
            { "CA", "CERT_SERV_ADMINISTRATORS" },
            { "CD", "CERTSVC_DCOM_ACCESS_GROUP" },
            { "CG", "CREATOR_GROUP" },
            { "CO", "CREATOR_OWNER" },
            { "CY", "CRYPTO_OPERATORS" },
            { "DA", "DOMAIN_ADMINISTRATORS" },
            { "DC", "DOMAIN_COMPUTERS" },
            { "DD", "DOMAIN_DOMAIN_CONTROLLERS" },
            { "DG", "DOMAIN_GUESTS" },
            { "DU", "DOMAIN_USERS" },
            { "EA", "ENTERPRISE_ADMINS" },
            { "ED", "ENTERPRISE_DOMAIN_CONTROLLERS" },
            { "ER", "EVENT_LOG_READERS" },
            { "ES", "RDS_ENDPOINT_SERVERS" },
            { "HA", "HYPER_V_ADMINS" },
            { "IS", "IIS_USERS" },
            { "IU", "INTERACTIVE" },
            { "LA", "LOCAL_ADMIN" },
            { "LG", "LOCAL_GUEST" },
            { "LS", "LOCAL_SERVICE" },
            { "LU", "PERFLOG_USERS" },
            { "LW", "WINRM_REMOTE_WMI_USERS" },
            { "MS", "RDS_MANAGEMENT_SERVERS" },
            { "MU", "PERFMON_USERS" },
            { "NO", "NETWORK_CONFIGURATION_OPS" },
            { "NS", "NETWORK_SERVICE" },
            { "NU", "NETWORK" },
            { "OW", "OWNER_RIGHTS" },
            { "PA", "GROUP_POLICY_ADMINS" },
            { "PO", "PRINTER_OPERATORS" },
            { "PS", "PERSONAL_SELF" },
            { "PU", "POWER_USERS" },
            { "RA", "RDS_REMOTE_ACCESS_SERVERS" },
            { "RC", "RESTRICTED_CODE" },
            { "RD", "REMOTE_DESKTOP" },
            { "RE", "REPLICATOR" },
            { "RM", "REMOTE_MANAGEMENT_USERS" },
            { "RO", "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS" },
            { "RS", "RAS_SERVERS" },
            { "RU", "ALIAS_PREW2KCOMPACC" },// Alias to allow previous Windows 2000
            { "SA", "SCHEMA_ADMINISTRATORS" },
            { "SO", "SERVER_OPERATORS" },
            { "SU", "SERVICE" },
            { "SY", "LOCAL_SYSTEM" },
            { "WD", "EVERYONE" },
            { "WR", "WRITE_RESTRICTED_CODE" },
        };
    }
}
