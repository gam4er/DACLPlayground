using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace SetNullDaclFramework
{
    internal class SetNullDaclFramework
    {
        static int Main(string [] args)
        {
            // --- 1. Получаем DN -------------------------------------------------
            if (args.Length == 0 || string.IsNullOrWhiteSpace(args [0]))
            {
                Console.Error.WriteLine("Usage: SetNullDacl.exe <DistinguishedName>");
                return 1;
            }
            string dn = args [0];

            try
            {
                // --- 2. ADSI-объект и считывание SD ----------------------------
                var de = new DirectoryEntry("LDAP://" + dn);
                byte [] raw = de.ObjectSecurity.GetSecurityDescriptorBinaryForm();

                if (raw == null || raw.Length == 0)
                    throw new InvalidOperationException("Cannot read nTSecurityDescriptor (no READ_CONTROL?).");

                // 3) Разбираем SD
                var sd = new RawSecurityDescriptor(raw, 0);      // или CommonSecurityDescriptor

                // Уже NULL-DACL?
                if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
                {
                    Console.WriteLine("Object already has NULL-DACL.");
                    return 0;
                }

                // 4) Обнуляем DACL и правим флаги
                sd.DiscretionaryAcl = null;
                //sd.ControlFlags &= ~ControlFlags.DiscretionaryAclPresent;   // снять DACL_PRESENT
                //sd.ControlFlags |= ControlFlags.DiscretionaryAclDefaulted; // добавить DACL_DEFAULTED

                // 5) Сериализуем и пишем обратно
                var buf = new byte [sd.BinaryLength];
                sd.GetBinaryForm(buf, 0);

                de.ObjectSecurity.SetSecurityDescriptorBinaryForm(buf);
                de.CommitChanges();

                Console.WriteLine("NULL-DACL successfully applied to:\n  " + dn);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: " + ex.Message);
                return 2;
            }
        }
    }
}
