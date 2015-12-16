using dnPE.Structures.MetaData;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dnPE
{
    public abstract partial class PEInfomation
    {
        public IntPtr LoadModule()
        {
            if (loadedModuleHandle != IntPtr.Zero)
                return loadedModuleHandle;

            loadedModuleHandle = NativeMethods.LoadLibrary(FilePath);


            return loadedModuleHandle;
        }

        public void UnloadModule()
        {
            if (loadedModuleHandle == IntPtr.Zero)
                return;

            if (NativeMethods.FreeLibrary(loadedModuleHandle))
                loadedModuleHandle = IntPtr.Zero;
        }

        public byte[] ReadStorageStream(STORAGE_STREAM_HEADER storageStream)
        {
            if (!IsNet)
                return null;
            try
            {
                byte[] stream = new byte[storageStream.iSize];

                if (IsProcess)
                {
                    uint protection = 0;

                    IntPtr handle = GetProcessHandle();
                    IntPtr address = new IntPtr(ModuleBaseAddress.ToInt32() + NetStructures.COR20Header.MetaDataRva + storageStream.iOffset);

                    NativeMethods.VirtualProtectEx(handle, address, stream.Length, 0x10, out protection);
                    bool success = NativeMethods.ReadProcessMemory(handle, address, stream, stream.Length, 0);
                    NativeMethods.VirtualProtectEx(handle, address, stream.Length, protection, out protection);

                    CloseProcessHandle();
                    if (!success)
                        throw new Exception("Failed to read.");
                }
                else
                {
                    Buffer.BlockCopy(DataBytes, NetStructures.NetOffsets.MetaDataRawAddress + (int)storageStream.iOffset, stream, 0, stream.Length);
                }
                return stream;
            }
            catch
            {
                return null;
            }
        }

        public IntPtr GetProcessHandle()
        {
            if (Handle != IntPtr.Zero)
                return Handle;
            if (IsProcess)
                Handle = NativeMethods.OpenProcess(0x1F0FFF, false, ProcessID);
            return Handle;
        }

        public void CloseProcessHandle()
        {
            if (Handle == IntPtr.Zero)
                return;

            if (IsProcess)
            {
                if (NativeMethods.CloseHandle(Handle))
                    Handle = IntPtr.Zero;
            }
        }

    }
}
