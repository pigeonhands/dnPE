using dnPE.Structures;
using dnPE.Structures.MetaData;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace dnPE
{
    /// <summary>
    /// .Net libaray for viewing PE infomation
    /// Made by BahNahNah
    /// uid=2388291
    /// </summary>
    public abstract partial class PEInfomation
    {
        /// <summary>
        /// Load PE infomation from file on disk
        /// </summary>
        /// <param name="file">Path to file</param>
        /// <returns>PE Infomation of target</returns>
        public static PEInfomation Load(string file)
        {
            if (!File.Exists(file)) throw new ArgumentException("File does not exist", "file");
            return Load(File.ReadAllBytes(file), file);
        }

        /// <summary>
        /// Load PE infomation from byte array
        /// </summary>
        /// <param name="data"></param>
        /// <param name="path"></param>
        /// <returns>PE Infomation of target</returns>
        public static PEInfomation Load(byte[] data, string path)
        {
            if (data == null) throw new ArgumentNullException("data");

            PEInfomationInternal info = new PEInfomationInternal(data);

            info._DosHeader = StructFromBytes<IMAGE_DOS_HEADER>(data, 0);
            info._FileHeader = StructFromBytes<IMAGE_FILE_HEADER>(data, Convert.ToInt32(info._DosHeader.e_lfanew));
            info._OptionalHeader32 = StructFromBytes<IMAGE_OPTIONAL_HEADER32>(data, Convert.ToInt32(info._DosHeader.e_lfanew) + Marshal.SizeOf(info._FileHeader));
            info._DataDirectories = StructFromBytes<IMAGE_DATA_DIRECTORIES>(data, Convert.ToInt32(info._DosHeader.e_lfanew) + Marshal.SizeOf(info._FileHeader) + Marshal.SizeOf(info._OptionalHeader32));

            info._Sections = new IMAGE_SECTION_HEADER[info._FileHeader.NumberOfSections];
            int sectionsBase = Convert.ToInt32(info._DosHeader.e_lfanew) + Marshal.SizeOf(info._FileHeader) + Marshal.SizeOf(info._OptionalHeader32) + Marshal.SizeOf(info._DataDirectories);
            int sizeOfSection = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            for (int i = 0; i < info._Sections.Length; i++)
            {
                int sectionLocation = sectionsBase + (sizeOfSection * i);
                info._Sections[i] = StructFromBytes<IMAGE_SECTION_HEADER>(data, sectionLocation);
            }

            if (info.IsNet)
            { 
                //is .net
                info._NetStructures.NetOffsets.COR20RawAddress = Convert.ToInt32(info._DataDirectories.CLRRuntimeHeaderRva - info._Sections[0].VirtualAddress + info._Sections[0].PointerToRawData);
                info._NetStructures.COR20Header = StructFromBytes<COR20_HEADER>(data, info._NetStructures.NetOffsets.COR20RawAddress);

                info._NetStructures.NetOffsets.MetaDataRawAddress = Convert.ToInt32(info._NetStructures.COR20Header.MetaDataRva - info._Sections[0].VirtualAddress + info._Sections[0].PointerToRawData);

                LoadNetMetaData(info, data);
            }

            info.WriteOverview();
            return info;

        }

        /// <summary>
        /// Load PE infomation from process using default module.
        /// </summary>
        /// <param name="p">Process to load</param>
        /// <returns>PE Infomation of target</returns>
        public static PEInfomation Load(Process p)
        {
            ProcessModule module = p.Modules[0];
            return Load(p.Id, module);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="p">Process containing target module</param>
        /// <param name="module">Target module</param>
        /// <returns>PE Infomation of target</returns>
        public static PEInfomation Load(Process p, ProcessModule module)
        {
            return Load(p.Id, module);
        }

        /// <summary>
        /// Load PE infomation from process.
        /// </summary>
        /// <param name="ProcessID">PID of process containing target module</param>
        /// <param name="module">Target module</param>
        /// <returns>PE Infomation of target</returns>
        public static PEInfomation Load(int ProcessID, ProcessModule module)
        {
            return Load(ProcessID, module.BaseAddress);
        }

        /// <summary>
        /// Load PE infomation from process.
        /// </summary>
        /// <param name="ProcessID">PID of process containing target module</param>
        /// <param name="moduleAddress">Base address of target module</param>
        /// <returns></returns>
        public static PEInfomation Load(int ProcessID, IntPtr moduleAddress)
        {
            PEInfomationInternal info = new PEInfomationInternal(ProcessID, moduleAddress);
            return vLoad(info, moduleAddress);
        }

        /// <summary>
        /// Load PE infomation from process.
        /// </summary>
        /// <param name="procHandle">handle of process containing target module</param>
        /// <param name="moduleAddress">Base address of target module</param>
        /// <returns></returns>
        public static PEInfomation Load(IntPtr procHandle, IntPtr moduleAddress)
        {
            PEInfomationInternal info = new PEInfomationInternal(procHandle, moduleAddress);
            return vLoad(info, moduleAddress);
        }

        private static PEInfomation vLoad(PEInfomationInternal info, IntPtr baseAddress)
        {
            IntPtr handle = info.GetProcessHandle();
            if (handle == IntPtr.Zero)
                throw new ArgumentException("Invalid process", "ProcessID");

            info._DosHeader = StructFromMemory<IMAGE_DOS_HEADER>(handle, baseAddress);
            IntPtr imageBase = new IntPtr(info._DosHeader.e_lfanew + (uint)baseAddress);

            info._FileHeader = StructFromMemory<IMAGE_FILE_HEADER>(handle, imageBase);
            info._OptionalHeader32 = StructFromMemory<IMAGE_OPTIONAL_HEADER32>(handle, imageBase + Marshal.SizeOf(info._FileHeader));
            info._DataDirectories = StructFromMemory<IMAGE_DATA_DIRECTORIES>(handle, imageBase + Marshal.SizeOf(info._FileHeader) + Marshal.SizeOf(info._OptionalHeader32));

            info._Sections = new IMAGE_SECTION_HEADER[info._FileHeader.NumberOfSections];
            IntPtr sectionsBase = imageBase + Marshal.SizeOf(info._FileHeader) + Marshal.SizeOf(info._OptionalHeader32) + Marshal.SizeOf(info._DataDirectories);
            int sizeOfSection = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            for (int i = 0; i < info._Sections.Length; i++)
            {
                IntPtr sectionLocation = sectionsBase + (sizeOfSection * i);
                info._Sections[i] = StructFromMemory<IMAGE_SECTION_HEADER>(handle, sectionLocation);
            }

            if (info.IsNet)
            {
                //is .net
                info._NetStructures.COR20Header = StructFromMemory<COR20_HEADER>(handle, new IntPtr((uint)baseAddress + info._DataDirectories.CLRRuntimeHeaderRva));

                byte[] data = new byte[info._NetStructures.COR20Header.MetaDataSize];
                NativeMethods.ReadProcessMemory(handle, new IntPtr((uint)baseAddress + info._NetStructures.COR20Header.MetaDataRva), data, data.Length, 0);

                LoadNetMetaData(info, data);

            }

            info.CloseProcessHandle();

            info.WriteOverview();
            return info;
        }

        private static void LoadNetMetaData(PEInfomationInternal info, byte[] MetaDataHeaderBytes)
        {
            info._NetStructures.MetaDataHeader.Signature = BitConverter.ToUInt32(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress);
            info._NetStructures.MetaDataHeader.MajorVersion = BitConverter.ToUInt16(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 4);
            info._NetStructures.MetaDataHeader.MinorVersion = BitConverter.ToUInt16(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 6);
            info._NetStructures.MetaDataHeader.Reserved = BitConverter.ToUInt32(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 8);
            info._NetStructures.MetaDataHeader.VersionLength = BitConverter.ToUInt32(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 12);

            info._NetStructures.MetaDataHeader.VersionString = new char[info._NetStructures.MetaDataHeader.VersionLength];
            info._NetStructures.MetaDataHeader.VersionString = Encoding.ASCII.GetString(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 16, info._NetStructures.MetaDataHeader.VersionString.Length).ToCharArray();

            info._NetStructures.MetaDataHeader.Flags = BitConverter.ToUInt16(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 16 + Convert.ToInt32(info._NetStructures.MetaDataHeader.VersionLength));
            info._NetStructures.MetaDataHeader.NumberOfStreams = BitConverter.ToUInt16(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + 18 + Convert.ToInt32(info._NetStructures.MetaDataHeader.VersionLength));


            int metaDataHeaderSize = 20 + Convert.ToInt32(info._NetStructures.MetaDataHeader.VersionLength);
            int offset = 0;

            info._NetStructures.StorageStreamHeaders = new STORAGE_STREAM_HEADER[5];

            int[] nameLengths = new int[] { 4, 12, 4, 8, 8 };

            for (int i = 0; i < nameLengths.Length; i++)
            {
                info._NetStructures.StorageStreamHeaders[i].iOffset = BitConverter.ToUInt32(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + metaDataHeaderSize + offset);
                info._NetStructures.StorageStreamHeaders[i].iSize = BitConverter.ToUInt32(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + metaDataHeaderSize + 4 + offset);

                info._NetStructures.StorageStreamHeaders[i].rcName = new char[nameLengths[i]];
                info._NetStructures.StorageStreamHeaders[i].rcName = Encoding.ASCII.GetString(MetaDataHeaderBytes, info._NetStructures.NetOffsets.MetaDataRawAddress + metaDataHeaderSize + 8 + offset, info._NetStructures.StorageStreamHeaders[i].rcName.Length).ToCharArray();
                offset += 8 + nameLengths[i];
            }
            info._NetStructures.SizeOfSotrageStreamHeaders = offset;

            info._NetStructures.NetOffsets.RawAddressOfTableStreams = info._NetStructures.NetOffsets.MetaDataRawAddress + Convert.ToInt32(info._NetStructures.StorageStreamHeaders[0].iOffset);
            info._NetStructures.TableStreamHeader = StructFromBytes<TABLE_STREAM_HEADER>(MetaDataHeaderBytes, info._NetStructures.NetOffsets.RawAddressOfTableStreams);
        }

        public static PEInfomation DisectSelf()
        {
            Process p = Process.GetCurrentProcess();
            return Load(p.Id, p.Modules[0]);
        }

        public static IntPtr OpenProcessHandle(int pid)
        {
            return NativeMethods.OpenProcess(0x1F0FFF, false, pid);
        }

        public static void CloseProcessHandle(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
        }

        internal static T StructFromMemory<T>(IntPtr handle, IntPtr address)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[structSize];
            NativeMethods.ReadProcessMemory(handle, address, buffer, buffer.Length, 0);
            return StructFromBytes<T>(buffer, 0);
        }

        internal static T StructFromBytes<T>(byte[] data, int offset)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            IntPtr gAlloc = Marshal.AllocHGlobal(structSize);
            Marshal.Copy(data, offset, gAlloc, structSize);
            T retStruct = (T)Marshal.PtrToStructure(gAlloc, typeof(T));
            Marshal.FreeHGlobal(gAlloc);
            return retStruct;
        }

        /// <summary>
        /// Scans two instances of the same object/scruct and returns the ammount of diffrent field values
        /// </summary>
        /// <typeparam name="T">Struct type to scan</typeparam>
        /// <param name="sruct1">First struct</param>
        /// <param name="sruct2">Second struct</param>
        /// <param name="excludeFields">Name of fields to exclude</param>
        /// <returns>Number of non-matching fields</returns>
        public static int CountDiffrences<T>(T sruct1, T sruct2, params string[] excludeFields)
        {
            Type scanType = typeof(T);

            int tUnmachedValues = 0;

            foreach (FieldInfo f in scanType.GetFields())
            {
                if (excludeFields.Contains(f.Name))
                    continue;
                object oProc = f.GetValue(sruct1);
                object oFile = f.GetValue(sruct2);

                if (oProc.ToString() != oFile.ToString())
                    tUnmachedValues++;
            }
            return tUnmachedValues;
        }

        public static Dictionary<string, object> ReadStructValues<T>(T tStruct, params string[] excludeFields)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();
            Type scanType = typeof(T);

            foreach (FieldInfo f in scanType.GetFields())
            {
                if (excludeFields.Contains(f.Name))
                    continue;
                ret.Add(f.Name, f.GetValue(tStruct));
            }
            return ret;
        }
    }
}
