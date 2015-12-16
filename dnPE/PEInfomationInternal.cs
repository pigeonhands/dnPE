using dnPE.Structures;
using dnPE.Structures.MetaData;
using System;
using System.Text;

namespace dnPE
{
    internal class PEInfomationInternal : PEInfomation
    {
        internal void WriteOverview()
        {
            _Overview.AddressOfEntrypoint = OptionalHeader32.AddressOfEntrypoint;
            _Overview.FileHeaderPointer = DosHeader.e_lfanew;
            _Overview.ImageBase = OptionalHeader32.ImageBase;
            _Overview.NumberOfSections = FileHeader.NumberOfSections;
            _Overview.SizeOfHeaders = OptionalHeader32.SizeOfHeaders;
            _Overview.SizeOfImage = OptionalHeader32.SizeOfImage;
        }

        public PEInfomationInternal(byte[] b)
        {
            DataBytes = b;
            FilePath = string.Empty;
            IsProcess = false;
        }

        public PEInfomationInternal(int pId, IntPtr _module)
        {
            ProcessID = pId;
            ModuleBaseAddress = _module;
            LoadModuleInfo();
        }

        public PEInfomationInternal(IntPtr procHandle, IntPtr _module)
        {
            Handle = procHandle;
            ProcessID = 0;
            ModuleBaseAddress = _module;
            LoadModuleInfo();
        }

        void LoadModuleInfo()
        {
            StringBuilder sb = new StringBuilder(255);
            NativeMethods.GetModuleFileNameEx(GetProcessHandle(), ModuleBaseAddress, sb, 255);
            CloseProcessHandle();
            FilePath = sb.ToString();
            IsProcess = true;
        }

       

       
        
    }
}
