using dnPE.Structures.MetaData;

namespace dnPE.Structures
{
    public struct NET_STRUCTURES
    {
        public COR20_HEADER COR20Header;
        public METADATA_HEADER MetaDataHeader;
        public NET_OFFSETS NetOffsets;
        public STORAGE_STREAM_HEADER[] StorageStreamHeaders;
        public TABLE_STREAM_HEADER TableStreamHeader;

        public const int StorageStreamHeaderSize = 14;
        public int SizeOfSotrageStreamHeaders;

        
    }
}
