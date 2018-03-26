using System;
using System.Collections.Generic;
using System.Text;

namespace Sodium
{
    public interface IBufferPool
    {
      byte[] Rent(int minLength);
      void Return(byte[] buf);
    }
}
