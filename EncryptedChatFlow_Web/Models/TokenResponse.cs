using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EncryptedChatFlow_Web.Models
{
    public class TokenResponse
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expiration { get; set; }
    }

}
