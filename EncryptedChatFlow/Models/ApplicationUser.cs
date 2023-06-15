using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace EncryptedChatFlow.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ICollection<Message> Messages { get; set; }
    }
}
