using System.Threading.Tasks;

namespace EncryptedChatFlow_Web.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string htmlMessage);
    }

}
