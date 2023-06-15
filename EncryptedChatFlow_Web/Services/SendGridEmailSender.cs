using SendGrid;
using SendGrid.Helpers.Mail;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace EncryptedChatFlow_Web.Services
{
    public class SendGridEmailSender : IEmailSender
    {
        private readonly ISendGridClient _client;
        private readonly ILogger<SendGridEmailSender> _logger;

        public SendGridEmailSender(ISendGridClient client, ILogger<SendGridEmailSender> logger)
        {
            _client = client;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("ken@backendinsight.com", "Kenneth Okalang"),
                Subject = subject,
                PlainTextContent = htmlMessage,
                HtmlContent = htmlMessage
            };
            msg.AddTo(new EmailAddress(email));

            // Disable click tracking.
            msg.SetClickTracking(false, false);

            try
            {
                var response = await _client.SendEmailAsync(msg);
                _logger.LogInformation($"Email sent with status {response.StatusCode}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while sending email.");
            }
        }
    }
}
