using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ParseJsonWithSDDLs
{

    // ---------------- model ----------------
    public class ExtendedRight
    {
        public string name { get; set; }
        public string rightsGuid { get; set; }
        public string objectGUID { get; set; }
    }

    public class SchemaAttribute
    {
        public string name { get; set; }
        public string attributeID { get; set; }
        public string attributeSyntax { get; set; }
        public string objectGUID { get; set; }
        public string schemaIDGUID { get; set; }
    }

    // ---------------- helper ----------------
    internal static class DirectoryHelper
    {
        public static IEnumerable<ResultPropertyCollection> Query(string ldapPath,
                                                                  string ldapFilter,
                                                                  params string [] attribs)
        {
            using (var root = new DirectoryEntry(ldapPath))
            {
                using (var searcher = new DirectorySearcher(root, ldapFilter, attribs, SearchScope.Subtree))
                {
                    searcher.PageSize = 1000;           // fast-paged
                    foreach (SearchResult sr in searcher.FindAll())
                        yield return sr.Properties;
                }
            }
        }

        public static string GetSingleString(ResultPropertyCollection p, string attr)
        {
            if (!p.Contains(attr) || p [attr].Count == 0) return String.Empty;

            object v = p [attr] [0];
            return v is byte [] bytes ? new Guid(bytes).ToString().ToUpper() : v.ToString();
        }
    }
}
