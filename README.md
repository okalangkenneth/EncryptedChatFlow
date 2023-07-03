# Leveraging .NET Core, SignalR, Ocelot and Audit Logs for Secure Real-Time Messaging

## **Introduction**:
    
"The objective of this project was to develop a secure, real-time chat application by harnessing an array of technologies including 
.NET Core, ASP.NET Core Identity, SignalR, JSON Web Tokens (JWTs), SendGrid, Google login, and Redis. 
The application integrates Ocelot as a reverse proxy, directing the client's requests to appropriate microservices, and incorporates an audit logging mechanism for maintaining a comprehensive history of user actions.
To further fortify security, a CORS policy has been implemented for secure handling of cross-origin requests and responses. 
We've adopted Google login for robust authentication and SendGrid for reliable email delivery services. 
Redis, a versatile in-memory data structure store, has been employed as a database and cache, thereby augmenting our application's performance and scalability.
Moreover, our API incorporates a rate limiting protocol, effectively safeguarding against potential denial-of-service attacks.
These diverse technologies interweave across three interconnected projects - the API, client, and Ocelot project - each serving a 
crucial role in ensuring a seamless, user-friendly application experience."

## **Technical Details**:
    
 "The chat application is built on a .NET Core backend, handling user authentication, message transmission, and various other functionalities. ASP.NET Core Identity is used for secure user data management, while real-time communication between the server and clients is facilitated by SignalR.
Here are some code snippets related to user authentication and data management using ASP.NET Core Identity:

### ApplicationUser Model (EncryptedChatFlow/Models/ApplicationUser.cs)
This model extends the IdentityUser class provided by ASP.NET Core Identity, which represents the registered user in the application.

````using Microsoft.AspNetCore.Identity;
namespace EncryptedChatFlow.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ICollection<Message> Messages { get; set; }
    }
}
````
### TokenController (EncryptedChatFlow/Controllers/TokenController.cs)
This controller is responsible for generating JWT tokens for authenticated users.
````using EncryptedChatFlow.Models;
namespace EncryptedChatFlow.Controllers
{
    [Route("api/token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public TokenController(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> GetToken([FromBody] UserTokenRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid user data");
            }
            //... (JWT token generation code)
        }
    }
}
````
### AccountsController (EncryptedChatFlow_Web/Controllers/AccountsController.cs)
This controller handles user registration, login, and logout operations.

````
using EncryptedChatFlow.Models;
namespace EncryptedChatFlow_Web.Controllers
{
    [Authorize]
    public class AccountsController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountsController> _logger;
        private readonly IEmailSender _emailSender;

        public AccountsController(ILogger<AccountsController> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        //... (Login, Logout, Register methods)
    }
}
````
### Startup Configuration (EncryptedChatFlow/Startup.cs)
This class configures services and the app's request pipeline. It includes the configuration of the Identity service.
````
namespace EncryptedChatFlow
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            //... (Other service configurations)
        }

        //... (Configure method)
    }
}
````
### Real-time communication with SignalR: 
The ChatHub class is a SignalR hub that manages real-time communication. It has methods for sending messages and handling user connections and disconnections.

````
using EncryptedChatFlow.Data;
namespace EncryptedChatFlow.Models{
    public class ChatHub : Hub {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        public ChatHub(ApplicationDbContext context, UserManager<ApplicationUser> userManager) {
            _context = context;
            _userManager = userManager;
        }
        public async Task SendMessage(string userName, string message) {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null) {
                throw new Exception("User not found");
            }
            var newMessage = new Message { Content = message, Timestamp = DateTime.Now, UserId = user.Id };
            _context.Messages.Add(newMessage);
            await _context.SaveChangesAsync();
            await Clients.All.SendAsync("ReceiveMessage", newMessage.Timestamp.ToString(), userName, message);
        }
        public override async Task OnConnectedAsync() {
            await Clients.All.SendAsync("ReceiveMessage", DateTime.Now.ToString(), "Chat server", "A new participant has joined the chat!");
            await base.OnConnectedAsync();
        }
        public override async Task OnDisconnectedAsync(Exception exception) {
            await Clients.All.SendAsync("ReceiveMessage", DateTime.Now.ToString(), "Chat server", "A participant has left the chat.");
            await base.OnDisconnectedAsync(exception);
        }
        public async Task AccessTokenExpired() {
            await Clients.Caller.SendAsync("AccessTokenExpired");
        }
    }
}

````

These snippets show how the application uses ASP.NET Core Identity for user management and authentication. The ApplicationUser model is used to represent users, and the TokenController and AccountsController handle user authentication operations. The Startup class configures the Identity service and other necessary services for the application.

    
For stateless and secure authentication, JSON Web Tokens (JWTs) are employed and stored in HttpOnly cookies to prevent Cross-Site Scripting (XSS) attacks. The application also integrates Google Login for a smoother and faster authentication experience.


Email notifications are handled using SendGrid, a reliable cloud-based email delivery service. To enhance performance and scalability, Redis and in-memory caching techniques are implemented.
The application is designed with a strong emphasis on security, using a comprehensive Cross-Origin Resource Sharing (CORS) policy for safe handling of cross-origin requests. Additionally, API rate limiting is implemented to protect against potential denial-of-service attacks.
On the client-side, JavaScript is employed for token management and chat interactions. Ocelot is implemented as a reverse proxy to handle incoming requests efficiently and route them to the appropriate services.
Moreover, audit logs are used to keep a record of user activities, strengthening the application's security by providing traceability and accountability. The overall architecture of the application is segmented into three interconnected projects: the API, the Client, and the Ocelot project, each playing a vital role in ensuring a seamless, secure chat environment."

    
3. **Challenges & Solutions**:
    
"The integration of multiple components—real-time chat, secure authentication, reverse proxy, and audit logging—posed significant challenges. Ensuring secure and seamless real-time communication involved carefully managing JWTs, while setting up Ocelot required precise configuration to correctly route requests. Implementing audit logging necessitated strategic planning to capture meaningful user activity without hampering performance. Solutions involved rigorous testing, careful debugging, and thoughtful design—giving attention to both security and user experience."

4. **Testing**:
    
"Unit tests and integration tests were used extensively throughout the project to ensure the reliable functionality of each component. These tests helped verify user authentication, message transmission, JWT management, correct request routing through Ocelot, and accurate recording of user actions in the audit logs. They were instrumental in maintaining high code quality and catching potential issues early in the development process."

5. **Demonstration**:
    
"Here's a demo of the chat application in action. Notice how messages are exchanged in real time, how the application handles user authentication, and how each user action is recorded in the audit logs. Additionally, observe the role of Ocelot in managing requests."

6. **Conclusion**:
    
"This project demonstrates the effective combination of .NET Core, SignalR, Ocelot, and audit logs to create a secure, real-time messaging platform. The inclusion of extensive testing ensures the application is robust and reliable. This application could serve a variety of real-world use cases, such as live customer support, real-time collaboration tools, or secure inter-office communication—any scenario that requires real-time, secure messaging with traceability of user actions."

