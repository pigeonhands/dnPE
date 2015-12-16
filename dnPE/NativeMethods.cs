using dnPE.Structures;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace dnPE
{
    internal delegate bool EnumResourceNameCallback(IntPtr module, string type, string name, IntPtr z);
    internal delegate bool EnumResourceTypeCallback(IntPtr module, string type, IntPtr z);
    internal class NativeMethods
    {
        

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string path);

        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr handle);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int bufferSize, int bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr process, IntPtr baseAddress, int size, uint newProtection, out uint oldProtection);
    }
}
