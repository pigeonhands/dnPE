using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using dnPE;
using System.Diagnostics;

namespace dnPE_Example
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Example RunPE checker using dnPE.");
            Console.Write("Process name: ");
            string pNameString = Console.ReadLine();

            Process[] processbyName = Process.GetProcessesByName(pNameString);
            if(processbyName.Length < 1)
            {
                Console.WriteLine("Invalid process.");
                Console.ReadLine();
                return;
            }

            PEInfomation PE = PEInfomation.Load(processbyName.FirstOrDefault());

            Dictionary<string, object> values = PEInfomation.ReadStructValues(PE.Overview);
            foreach (var i in values)
                Console.WriteLine("{0}: {1}", i.Key, i.Value);

            int unmachedValues = 0;
            unmachedValues += PEInfomation.CountDiffrences(PE.FileHeader, PE.FileHeader);
            unmachedValues += PEInfomation.CountDiffrences(PE.OptionalHeader32, PE.OptionalHeader32, "ImageBase");
            int sectionAmmount = Math.Min(Convert.ToInt32(PE.Overview.NumberOfSections), Convert.ToInt32(PE.Overview.NumberOfSections));

            for (int i = 0; i < sectionAmmount; i++)
            {
                unmachedValues += PEInfomation.CountDiffrences(PE.Sections[i], PE.Sections[i]);
            }

            Console.WriteLine("Number of PE discrepancies: {0}", unmachedValues);
            Console.ReadLine();
        }
    }
}
