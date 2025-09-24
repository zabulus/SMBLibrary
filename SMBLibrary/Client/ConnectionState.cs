/* Copyright (C) 2017-2023 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Net.Sockets;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public sealed class ConnectionState : IDisposable
    {
        private readonly EventHandler<SocketAsyncEventArgs> m_completed;
        private NBTConnectionReceiveBuffer m_receiveBuffer;
        private readonly SocketAsyncEventArgs m_receiveArgs;

        public ConnectionState(EventHandler<SocketAsyncEventArgs> mCompleted)
        {
            m_completed = mCompleted;
            m_receiveBuffer = new NBTConnectionReceiveBuffer();
            m_receiveArgs = new SocketAsyncEventArgs();
            m_receiveArgs.SetBuffer(m_receiveBuffer.Buffer, m_receiveBuffer.WriteOffset, m_receiveBuffer.AvailableLength);
            m_receiveArgs.UserToken = this;
            m_receiveArgs.Completed += mCompleted;
        }

        public NBTConnectionReceiveBuffer ReceiveBuffer
        {
            get
            {
                return m_receiveBuffer;
            }
        }

        public SocketAsyncEventArgs Args => m_receiveArgs;

        public void IncreaseBufferSize(int maxPacketSize)
        {
            m_receiveBuffer.IncreaseBufferSize(maxPacketSize);
            m_receiveArgs.SetBuffer(m_receiveBuffer.Buffer, m_receiveBuffer.WriteOffset, m_receiveBuffer.AvailableLength);
        }

        public void Dispose()
        {
            m_receiveArgs.Completed -= m_completed;
            m_receiveArgs.Dispose();
            m_receiveBuffer.Dispose();
        }
    }
}
