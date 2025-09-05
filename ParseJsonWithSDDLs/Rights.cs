using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ParseJsonWithSDDLs
{
    public static class Rights
    {
        static Dictionary<string, string> accessRights = new Dictionary<string, string>
        {
            // Standard Rights
            { "RC", "READ_CONTROL" },           // Read the security descriptor
            { "SD", "DELETE" },                 // Delete the object
            { "WD", "WRITE_DAC" },              // Modify the DACL in the object's security descriptor
            { "WO", "WRITE_OWNER" },            // Change the owner in the object's security descriptor
            { "AS", "ACCESS_SYSTEM_SECURITY" }, // Access the SACL

            // Generic Rights
            { "GA", "GENERIC_ALL" },
            { "GR", "GENERIC_READ" },
            { "GW", "GENERIC_WRITE" },
            { "GX", "GENERIC_EXECUTE" },

            // Directory Service Object Access Rights
            { "CC", "CREATE_CHILD" },   // Create a child object
            { "DC", "DELETE_CHILD" },   // Delete a child object
            { "LC", "LIST_CHILDREN" },     // List the contents of a container
            { "SW", "SELF_WRITE" },           // Perform a validated write to the object
            { "RP", "READ_PROPERTY" },      // Read properties of the object
            { "WP", "WRITE_PROPERTY" },     // Write properties of the object
            { "DT", "DELETE_TREE" },       // Delete all child objects
            { "LO", "LIST_OBJECT" },    // List a particular object
            { "CR", "CONTROL_ACCESS" }, // Control access right

            // File Access Rights
            { "FA", "ALL_ACCESS" },
            { "FR", "GENERIC_READ" },
            { "FW", "GENERIC_WRITE" },
            { "FX", "GENERIC_EXECUTE" },

            // Registry Key Access Rights
            { "KA", "KEY_ALL_ACCESS" },
            { "KR", "KEY_READ" },
            { "KW", "KEY_WRITE" },
            { "KX", "KEY_EXECUTE" }
        };

        public static string DecodeAccessRights(string rightsString)
        {
            // Check if the rights string length is even
            if (rightsString.Length % 2 != 0)
            {
                throw new ArgumentException("Access rights string length must be even.");
            }

            List<string> decodedRights = new List<string>();

            // Split the rights string into chunks of 2 characters
            for (int i = 0; i < rightsString.Length; i += 2)
            {
                string code = rightsString.Substring(i, 2);

                if (accessRights.TryGetValue(code, out string right))
                {
                    decodedRights.Add(right);
                }
                else
                {
                    decodedRights.Add($"Unknown Right ({code})");
                }
            }

            // Concatenate the decoded rights with commas
            return string.Join(", ", decodedRights);
        }

    }
}
