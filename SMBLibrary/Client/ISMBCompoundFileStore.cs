using System.Collections.Generic;

namespace SMBLibrary.Client
{
    public class BatchOperationResult
    {
        public string Path { get; set; }
        public NTStatus Status { get; set; }
    }
    
    public interface ISMBCompoundFileStore : ISMBFileStore
    {
        NTStatus BatchDeleteFiles(IList<string> filePaths, out IList<BatchOperationResult> results);
    }
}
