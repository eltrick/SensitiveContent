using System;
using System.Collections.Generic;
using System.Text;

namespace SensitiveContent.Interfaces
{
    internal interface IPublicKeyInfrastructure
    {
        public void ExportPrivateKey();
        public string PrintPublicKey();
        public byte[] DeriveKey();
    }
}
