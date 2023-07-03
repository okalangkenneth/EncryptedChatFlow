using EncryptedChatFlow.Data;
using EncryptedChatFlow.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace EncryptedChatFlow.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MessagesController : ControllerBase
    {
        private readonly IHubContext<ChatHub> _hubContext;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<MessagesController> _logger;
        private readonly IDistributedCache _cache;

        public MessagesController(IHubContext<ChatHub> hubContext, ApplicationDbContext context, ILogger<MessagesController> logger, IDistributedCache cache)
        {
            _hubContext = hubContext;
            _context = context;
            _logger = logger;
            _cache = cache;
        }

        // GET api/messages
        [HttpGet]
        [Authorize(Roles = "Admin, User")] // Both Admin and User can view all messages
       

        public async Task<IActionResult> Get()
        {
            _logger.LogInformation("This is an information log");

            try
            {
                var cacheKey = "allMessages";
                string serializedMessages;
                var encodedMessages = await _cache.GetAsync(cacheKey);

                if (encodedMessages != null)
                {
                    serializedMessages = Encoding.UTF8.GetString(encodedMessages);
                    var messages = JsonSerializer.Deserialize<List<Message>>(serializedMessages);
                    return Ok(messages);
                }
                else
                {
                    var messages = await _context.Messages.ToListAsync();
                    serializedMessages = JsonSerializer.Serialize(messages);

                    encodedMessages = Encoding.UTF8.GetBytes(serializedMessages);
                    var options = new DistributedCacheEntryOptions()
                        .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                        .SetAbsoluteExpiration(DateTime.Now.AddHours(1));

                    await _cache.SetAsync(cacheKey, encodedMessages, options);
                    return Ok(messages);
                }
            }
            catch (Exception e)
            {
                // Log the error message to Serilog
                _logger.LogError(e, "An error occurred while fetching messages");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        // GET api/messages/{id}
        [HttpGet("{id}")]
        [Authorize(Roles = "Admin, User")] // Both Admin and User can view specific message
        public async Task<IActionResult> Get(int id)
        {
            try
            {
                var message = await _context.Messages.FindAsync(id);

                if (message == null)
                {
                    return NotFound();
                }

                return Ok(message);
            }
            catch (Exception e)
            {
                // Log the error message to Serilog
                return BadRequest(e.Message);
            }
        }

        // POST api/messages
        [HttpPost]
        [Authorize(Roles = "Admin, User")] // Both Admin and User can create a new message
        public async Task<IActionResult> Create(Message message)
        {
            try
            {
                // Save the message to your database.
                _context.Messages.Add(message);
                await _context.SaveChangesAsync();

                // After the message is saved, use the hub context to send the message to all connected clients.
                await _hubContext.Clients.All.SendAsync("ReceiveMessage", message.Timestamp, message.User, message.Content);

                return Ok(message);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error occurred while creating a message");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        // PUT api/messages/{id}
        [HttpPut("{id}")]
        [Authorize] // Only the user who created the message can update it
        public async Task<IActionResult> Update(int id, Message updatedMessage)
        {
            try
            {
                // Compare UserId of message to current user
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier); // Get UserId of the currently authenticated user
                var message = await _context.Messages.FindAsync(id);

                if (message.UserId != userId) // If the message was not created by the current user
                {
                    return Unauthorized(); // Return 401
                }

                message.Content = updatedMessage.Content;
                message.Timestamp = updatedMessage.Timestamp;

                // validate the new UserId if necessary
                // message.UserId = updatedMessage.UserId;
                // message.User is likely not necessary if you've updated UserId, 
                // since EF Core will handle the relation based on the UserId
                // message.User = updatedMessage.User;


                await _context.SaveChangesAsync();

                return NoContent();
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"An error occurred while updating the message with id {id}");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        // DELETE api/messages/{id}
        [HttpDelete("{id}")]
        [Authorize] // Only the user who created the message or an Admin can delete it
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                // Compare UserId of message to current user
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier); // Get UserId of the currently authenticated user
                var message = await _context.Messages.FindAsync(id);

                if (message == null)
                {
                    return NotFound();
                }

                // If the message was not created by the current user and the user is not an Admin
                if (message.UserId != userId && !User.IsInRole("Admin"))
                {
                    return Unauthorized(); // Return 401
                }

                _context.Messages.Remove(message);
                await _context.SaveChangesAsync();

                return NoContent();
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"An error occurred while deleting the message with id {id}");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

    }
}



