using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EncryptedChatFlow.Models.Dtos
{
    public class UserTokenRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

}
