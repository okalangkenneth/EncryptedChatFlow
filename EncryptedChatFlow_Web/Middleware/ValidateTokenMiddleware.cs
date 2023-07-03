using EncryptedChatFlow.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;

public class ValidateTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private readonly IHubContext<ChatHub> _hubContext;
    private readonly ILogger<ValidateTokenMiddleware> _logger;

    public ValidateTokenMiddleware(RequestDelegate next, IConfiguration configuration, IHubContext<ChatHub> hubContext, ILogger<ValidateTokenMiddleware> logger)
    {
        _next = next;
        _configuration = configuration;
        _hubContext = hubContext;
        _logger = logger;

        _logger.LogInformation("ValidateTokenMiddleware initialized.");  
    }

    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogInformation("InvokeAsync started.");  

        string authHeader = context.Request.Headers["Authorization"];

        _logger.LogInformation($"Authorization header: {authHeader}");  
        if (authHeader != null && authHeader.StartsWith("Bearer "))
        {
            var token = authHeader.Substring("Bearer ".Length).Trim();

            _logger.LogInformation($"Got the token in middleware: {token}");  // Log the token

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["JwtSettings:MySuperSecretKey"]);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;

                if (jwtToken.ValidTo < DateTime.UtcNow)
                {
                    _logger.LogInformation("Token has expired.");  // Log token expiration

                    // Token has expired - disconnect the client
                    await _hubContext.Clients.All.SendAsync("AccessTokenExpired");
                    return;
                }
            }
            catch (Exception ex)
            {
                // Token validation failed - disconnect the client
                _logger.LogError(ex, "Token validation failed.");  

                // Token validation failed - disconnect the client
                await _hubContext.Clients.All.SendAsync("AccessTokenExpired");
                return;
            }
        }

        // Call the next middleware in the pipeline
        await _next(context);
    }
}


