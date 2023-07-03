# Leveraging .NET Core, SignalR, Ocelot and Audit Logs for Secure Real-Time Messaging

## Table of Contents:
1. [Introduction](#introduction)
2. [Technical Details](#technical-details)
3. [Challenges & Solutions](#challenges-solutions)
4. [Testing](#testing)
5. [Demonstration](#demonstration)
6. [Conclusion](#conclusion)


## Introduction:
    
"The objective of this project was to develop a secure, real-time chat application by harnessing an array of technologies including 
.NET Core, ASP.NET Core Identity, SignalR, JSON Web Tokens (JWTs), SendGrid, Google login, and Redis. 
The application integrates Ocelot as a reverse proxy, directing the client's requests to appropriate microservices, and incorporates an audit logging mechanism for maintaining a comprehensive history of user actions.
To further fortify security, a CORS policy has been implemented for secure handling of cross-origin requests and responses. 
We've adopted Google login for robust authentication and SendGrid for reliable email delivery services. 
Redis, a versatile in-memory data structure store, has been employed as a database and cache, thereby augmenting our application's performance and scalability.
Moreover, our API incorporates a rate limiting protocol, effectively safeguarding against potential denial-of-service attacks.
These diverse technologies interweave across three interconnected projects - the API, client, and Ocelot project - each serving a 
crucial role in ensuring a seamless, user-friendly application experience."

## Technical Details:
    
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
Here are the code snippets related to JSON Web Tokens (JWTs):
### JWT Authentication: 
The TokenController.cs file in the EncryptedChatFlow project handles the generation of JWTs. Here's a snippet of the GetToken method:

````
[HttpPost]
public async Task<IActionResult> GetToken([FromBody] UserTokenRequest model)
{
    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
        return BadRequest("Invalid user data");
    }
    var userRoles = await _userManager.GetRolesAsync(user);
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    };
    foreach (var userRole in userRoles)
    {
        claims.Add(new Claim(ClaimTypes.Role, userRole));
    }
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:MySuperSecretKey"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var expires = DateTime.Now.AddDays(Convert.ToDouble(_configuration["JwtSettings:ExpirationInDays"]));
    var token = new JwtSecurityToken(
        issuer: _configuration["JwtSettings:Issuer"],
        audience: _configuration["JwtSettings:Audience"],
        claims: claims,
        notBefore: DateTime.UtcNow,
        expires: expires,
        signingCredentials: creds
    );
    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
}
````
### JWT Storage in HttpOnly Cookies: 
The AccountsController.cs file in the EncryptedChatFlow_Web project handles the storage of JWTs in HttpOnly cookies. Here's a snippet of the Login method:

````
[HttpPost]
public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
{
    //... (User authentication code)
    if (result.Succeeded)
    {
        var user = await _userManager.FindByNameAsync(model.Email);
        if (user == null)
        {
            return View(model);
        }
        var requestBody = new UserTokenRequest { Email = model.Email };
        var requestBodyJson = JsonConvert.SerializeObject(requestBody);
        //... (HTTP request to API code)
        if (response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            var responseBodyObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseBody);
            if (responseBodyObject.ContainsKey("token"))
            {
                var token = responseBodyObject["token"];
                _logger.LogInformation($"Got token: {token}");
                Response.Cookies.Append(
                    "jwt_cookie",
                    token,
                    new CookieOptions { Secure = true, SameSite = SameSiteMode.Lax }
                );
            }
        }
        return RedirectToAction("Chat", "Home");
    }
    //... (Other code)
}
````

Email notifications are handled using SendGrid, a reliable cloud-based email delivery service. To enhance performance and scalability, Redis and in-memory caching techniques are implemented.
Here are the code snippets related to SendGrid email notifications and Redis caching:
### SendGrid Email Notifications: 
The SendGridEmailSender.cs file in the EncryptedChatFlow_Web project handles the sending of emails using SendGrid. Here's a snippet of the SendEmailAsync method:

````
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
````
### Redis Caching: 
The Startup.cs file in the EncryptedChatFlow project configures Redis caching. Here's a snippet of the ConfigureServices method:
````
public void ConfigureServices(IServiceCollection services)
{
    //... (Other service configurations)
    services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = Configuration.GetConnectionString("Redis");
    });
    //... (Other service configurations)
}
````
These snippets show how the application uses SendGrid for email notifications and Redis for caching to enhance performance and scalability.

The application is designed with a strong emphasis on security, using a comprehensive Cross-Origin Resource Sharing (CORS) policy for safe handling of cross-origin requests. Additionally, API rate limiting is implemented to protect against potential denial-of-service attacks.

Here are the code snippets related to Cross-Origin Resource Sharing (CORS) policy and API rate limiting:
### CORS Policy:
The Startup.cs file in the EncryptedChatFlow project configures the CORS policy. Here's a snippet of the ConfigureServices method:

````
public void ConfigureServices(IServiceCollection services)
{
    //... (Other service configurations)
    services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigin",
            builder =>
            {
                builder.WithOrigins("https://www.example.com")
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
    });
    //... (Other service configurations)
}
````
And here's a snippet of the Configure method where the CORS policy is applied:

````
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    //... (Other middleware configurations)
    app.UseCors("AllowSpecificOrigin");
    //... (Other middleware configurations)
}
````
### API Rate Limiting: 
The Startup.cs file in the EncryptedChatFlow project also configures API rate limiting. Here's a snippet of the ConfigureServices method:
````
public void ConfigureServices(IServiceCollection services)
{
    //... (Other service configurations)
    services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
    services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
    services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
    services.AddInMemoryRateLimiting();
    services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
    //... (Other service configurations)
}
````
And here's a snippet of the Configure method where the rate limiting middleware is applied:
````
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    //... (Other middleware configurations)
    app.UseIpRateLimiting();
    //... (Other middleware configurations)
}
````

On the client-side, JavaScript is employed for token management and chat interactions. Ocelot is implemented as a reverse proxy to handle incoming requests efficiently and route them to the appropriate services.
Moreover, audit logs are used to keep a record of user activities, strengthening the application's security by providing traceability and accountability. 
Here are the relevant code snippets for the audit logs:
### Logging in the MessagesController.cs file:
The application uses the ILogger interface for logging. Here is an example of how it's used in the MessagesController.cs file:

````
private readonly ILogger<MessagesController> _logger;

public MessagesController(IHubContext<ChatHub> hubContext, ApplicationDbContext context, ILogger<MessagesController> logger, IDistributedCache cache)
{
    _hubContext = hubContext;
    _context = context;
    _logger = logger;
    _cache = cache;
}

[HttpGet]
[Authorize(Roles = "Admin, User")]
public async Task<IActionResult> Get()
{
    _logger.LogInformation("This is an information log");
    ...
}
````
In the above code, the logger is injected into the MessagesController and used to log an informational message when the Get() method is called.
### Logging in the Startup.cs file (in the EncryptedChatFlow_Web project):
The application uses Serilog for logging. Here is how it's configured in the Startup.cs file:

````
public Startup(IConfiguration configuration)
{
    Configuration = configuration;
    Log.Logger = new LoggerConfiguration()
        .ReadFrom.Configuration(configuration)
        .CreateLogger();
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
{
    ...
    app.UseSerilogRequestLogging();
    ...
}
````
In the above code, the logger is configured in the Startup constructor and then used in the Configure method to log requests.

### Logging in the AccountsController.cs file (in the EncryptedChatFlow_Web project):
The application uses the ILogger interface for logging. Here is an example of how it's used in the AccountsController.cs file:
````
private readonly ILogger<AccountsController> _logger;

public AccountsController(ILogger<AccountsController> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender)
{
    _logger = logger;
    _userManager = userManager;
    _signInManager = signInManager;
    _emailSender = emailSender;
}

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    await _signInManager.SignOutAsync();
    Response.Cookies.Delete("jwt_cookie");
    _logger.LogInformation("User logged out.");
    return RedirectToAction(nameof(HomeController.Index), "Home");
}

````
In the above code, the logger is injected into the AccountsController and used to log an informational message when the Logout() method is called.These logs can be used to keep a record of user activities, strengthening the application's security by providing traceability and accountability.

The overall architecture of the application is segmented into three interconnected projects: the API, the Client, and the Ocelot project, each playing a vital role in ensuring a seamless, secure chat environment."

    
## Challenges & Solutions:
    
The integration of multiple components—real-time chat, secure authentication, reverse proxy, and audit logging—posed significant challenges. Ensuring secure and seamless real-time communication involved carefully managing JWTs, while setting up Ocelot required precise configuration to correctly route requests. Implementing audit logging necessitated strategic planning to capture meaningful user activity without hampering performance. Solutions involved rigorous testing, careful debugging, and thoughtful design—giving attention to both security and user experience.

## Testing:
    
Unit tests and integration tests were used extensively throughout the project to ensure the reliable functionality of each component. These tests helped verify user authentication, message transmission, JWT management, correct request routing through Ocelot, and accurate recording of user actions in the audit logs. They were instrumental in maintaining high code quality and catching potential issues early in the development process.
Here is a a screen shot of unit test done on the 'Get' method of the 'MessagesController' which is supposed to return a list of messages and an integration test for user authentication.
![EncryptedChatFlow](https://github.com/okalangkenneth/EncryptedChatFlow/assets/68539411/50c65f93-388f-40e1-ae69-258f9948a876)

## Demonstration:
    
Here's a demo of the chat application in action. Notice how messages are exchanged in real time, how the application handles user authentication, and how each user action is recorded in the audit logs. Additionally, observe the role of Ocelot in managing requests.

## Conclusion:
    
This project demonstrates the effective combination of .NET Core, SignalR, Ocelot, and audit logs to create a secure, real-time messaging platform. The inclusion of extensive testing ensures the application is robust and reliable. This application could serve a variety of real-world use cases, such as live customer support, real-time collaboration tools, or secure inter-office communication—any scenario that requires real-time, secure messaging with traceability of user actions.

