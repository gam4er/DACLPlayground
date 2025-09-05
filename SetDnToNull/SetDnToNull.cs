using System.Security.AccessControl;
using System.DirectoryServices;                 // ADSI

namespace SetDnToNull
{
    internal class SetDnToNull
    {
        static int Main(string [] args)
        {
            string dn = args.Length > 0 ? args [0] : Console.ReadLine();
            if (string.IsNullOrWhiteSpace(dn))
            {
                Console.Error.WriteLine("Usage: SetDnToNull.exe <DistinguishedName>");
                return 1;
            }

            try
            {
                // 1) ADSI-объект
                using var de = new DirectoryEntry("LDAP://" + dn);
                de.Options.SecurityMasks = SecurityMasks.Dacl;          // только DACL
                de.RefreshCache(new [] { "nTSecurityDescriptor" });

                var raw = de.Properties ["nTSecurityDescriptor"].Value as byte [];
                if (raw == null)
                    throw new InvalidOperationException("Cannot read nTSecurityDescriptor (no READ_CONTROL?).");

                // 2) Разбираем SD
                var sd = new RawSecurityDescriptor(raw, 0);

                // Уже NULL-DACL?
                if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
                {
                    Console.WriteLine("Object already has NULL-DACL.");
                    return 0;
                }

                // 3) Снимаем DACL и корректируем флаги
                sd.DiscretionaryAcl = null;
                //sd.ControlFlags &= ~ControlFlags.DiscretionaryAclPresent;
                //sd.ControlFlags |= ControlFlags.DiscretionaryAclDefaulted;

                // 4) Сериализуем и пишем обратно
                var buf = new byte [sd.BinaryLength];
                sd.GetBinaryForm(buf, 0);

                de.Properties ["nTSecurityDescriptor"].Value = buf;
                de.CommitChanges();

                Console.WriteLine($"NULL-DACL applied to: {dn}");
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
