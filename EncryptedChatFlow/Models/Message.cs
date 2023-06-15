using System;

namespace EncryptedChatFlow.Models
{
    public class Message
    {
        public int Id { get; set; }
        public string Content { get; set; }
        public DateTime Timestamp { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
    }
}
