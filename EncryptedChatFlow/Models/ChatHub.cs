using EncryptedChatFlow.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;
using System;
using System.Threading.Tasks;

namespace EncryptedChatFlow.Models
{
    public class ChatHub : Hub
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public ChatHub(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task SendMessage(string userName, string message)
        {
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null)
            {
                // Handle user not found, throw an error or return
                throw new Exception("User not found");
            }

            var newMessage = new Message
            {
                Content = message,
                Timestamp = DateTime.Now,
                UserId = user.Id
            };

            _context.Messages.Add(newMessage);
            await _context.SaveChangesAsync();

            await Clients.All.SendAsync("ReceiveMessage", newMessage.Timestamp.ToString(), userName, message);
        }



        public override async Task OnConnectedAsync()
        {
            // When a user connects, send a user-friendly message to all clients
            await Clients.All.SendAsync("ReceiveMessage", DateTime.Now.ToString(), "Chat server", "A new participant has joined the chat!");
            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception exception)
        {
            // When a user disconnects, send a user-friendly message to all clients
            await Clients.All.SendAsync("ReceiveMessage", DateTime.Now.ToString(), "Chat server", "A participant has left the chat.");
            await base.OnDisconnectedAsync(exception);
        }
    }
}

