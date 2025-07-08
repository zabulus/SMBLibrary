using System;
using System.Collections.Generic;

namespace SMBLibrary.SMB2.Commands
{
    public class CompoundSmb2Command : SMB2Command
    {
        public List<SMB2Command> Commands { get; }
        public bool RelatedOperations { get; set; }

        public CompoundSmb2Command(IList<SMB2Command> commands, bool relatedOperations = false)
            : base(commands[0].CommandName)
        {
            if (commands == null || commands.Count == 0)
                throw new ArgumentException("At least one command is required");
            Commands = new List<SMB2Command>(commands);
            RelatedOperations = relatedOperations;
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            if (Commands.Count == 1)
            {
                Commands[0].WriteBytes(buffer, offset);
                return;
            }

            // Set NextCommand and RelatedOperations flags
            for (int i = 0; i < Commands.Count; i++)
            {
                var command = Commands[i];
                if (RelatedOperations && i > 0)
                {
                    command.Header.Flags |= SMB2PacketHeaderFlags.RelatedOperations;
                    if (command is IHasFileId currCommand)
                    {
                        currCommand.FileId = new FileID(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
                    }
                }
                if (i < Commands.Count - 1)
                {
                    int pad = (8 - (command.Length % 8)) % 8;
                    command.Header.NextCommand = (uint)(command.Length + pad);
                }
                else
                {
                    command.Header.NextCommand = 0;
                }
            }

            int currentOffset = offset;
            foreach (var command in Commands)
            {
                command.WriteBytes(buffer, currentOffset);
                int pad = (8 - (command.Length % 8)) % 8;
                currentOffset += command.Length + pad;
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            // would not be called for CompoundSmb2Command
            throw new NotImplementedException();
        }

        public int CompoundLength
        {
            get
            {
                int total = 0;
                foreach (var command in Commands)
                {
                    int len = command is CompoundSmb2Command ccc ? ccc.CompoundLength : command.Length;
                    // 8-byte alignment
                    total += ((len + 7) / 8) * 8;
                }
                return total;
            }
        }

        public override int CommandLength => CompoundLength;
    }
}
