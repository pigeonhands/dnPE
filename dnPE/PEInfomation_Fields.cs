using dnPE.Structures;
using System;

namespace dnPE
{
    public abstract partial class PEInfomation
    {
        /// <summary>
        /// Returns true if the PE was loaded through a process
        /// </summary>
        public bool IsProcess { get; protected set; }

        /// <summary>
        /// Only for Processes, PID of loaded process
        /// </summary>
        public int ProcessID { get; protected set; }

        /// <summary>
        /// Only for Processes, base address of loaded module
        /// </summary>
        public IntPtr ModuleBaseAddress { get; protected set; }

        /// <summary>
        /// Only for Files, returns the filebytes of the loaded file
        /// </summary>
        public byte[] DataBytes { get; protected set; }

        /// <summary>
        /// Only for Files
        /// </summary>
        public string FilePath { get; protected set; }

       

        

        protected IntPtr Handle = IntPtr.Zero;
        protected IntPtr loadedModuleHandle = IntPtr.Zero;

        protected IMAGE_DOS_HEADER _DosHeader;
        protected IMAGE_FILE_HEADER _FileHeader;
        protected IMAGE_OPTIONAL_HEADER32 _OptionalHeader32;
        protected IMAGE_DATA_DIRECTORIES _DataDirectories;
        protected IMAGE_SECTION_HEADER[] _Sections;
        protected IMAGE_OVERVIEW _Overview;
        protected NET_STRUCTURES _NetStructures;

        public IMAGE_DOS_HEADER DosHeader
        {
            get { return _DosHeader; }
        }

        public IMAGE_FILE_HEADER FileHeader
        {
            get { return _FileHeader; }
        }

        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get { return _OptionalHeader32; }
        }

        public IMAGE_DATA_DIRECTORIES DataDirectories
        {
            get { return _DataDirectories; }
        }

        public IMAGE_SECTION_HEADER[] Sections
        {
            get { return _Sections; }
        }

        public IMAGE_OVERVIEW Overview
        {
            get { return _Overview; }
        }

        public NET_STRUCTURES NetStructures
        {
            get { return _NetStructures; }
        }
        public bool IsNet { get { return (FileHeader.NumberOfSections > 0 && DataDirectories.CLRRuntimeHeaderRva != 0x0 && DataDirectories.SizeOfCLRRumtimeHeader != 0x0); } }

        public const int SizeOfDosHeader = 0x40;
        public const int SizeOfFileHeader = 0x18;
        public const int SizeOfOptionalHeader = 0x60;
        public const int SizeOfDataDirectories = 0x80;
        public const int SizeOfSectionHeader = 0x28;
    }
}
