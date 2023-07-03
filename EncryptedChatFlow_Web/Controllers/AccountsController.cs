using EncryptedChatFlow.Models;
using EncryptedChatFlow.Models.Dtos;
using EncryptedChatFlow_Web.Models;
using EncryptedChatFlow_Web.Services;
using EncryptedChatFlow_Web.Views.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace EncryptedChatFlow_Web.Controllers
{
    [Authorize]
    public class AccountsController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountsController> _logger;
        private readonly IEmailSender _emailSender;

        public AccountsController(
            ILogger<AccountsController> logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Email);
                if (user == null)
                {
                    // You might want to handle this case differently
                    return View(model);
                }

                // Prepare the request body data
                var requestBody = new UserTokenRequest { Email = model.Email };
                var requestBodyJson = JsonConvert.SerializeObject(requestBody);

                // Send a request to your API to get a JWT token
                using (var httpClient = new HttpClient())
                {
                    var content = new StringContent(requestBodyJson, Encoding.UTF8, "application/json");
                    var response = await httpClient.PostAsync("https://localhost:44305/api/token", content);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseBody = await response.Content.ReadAsStringAsync();
                        var responseBodyObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseBody);

                        if (responseBodyObject.ContainsKey("token"))
                        {
                            var token = responseBodyObject["token"];

                            _logger.LogInformation($"Got token: {token}");  // Add this line

                            Response.Cookies.Append(
                                "jwt_cookie",
                                token,
                                new CookieOptions
                                {
                                     //HttpOnly = true,  // Temporarily comment this line
                                    Secure = true, // in production, set this to true to enforce transmission over HTTPS
                            SameSite = SameSiteMode.Lax // set according to your requirements
                                }
                            );
                        }
                    }
                }

                return RedirectToAction("Chat", "Home");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return View("Lockout");
            }
            else
            {
                ViewBag.LoginFailed = true;
                return View(model);
            }
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            Response.Cookies.Delete("jwt_cookie"); // delete the jwt cookie
            _logger.LogInformation("User logged out.");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }


        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }


        [AllowAnonymous]
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    // Generate the email confirmation token
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    // Generate the confirmation link
                    var confirmationLink = Url.Action("ConfirmEmail", "Accounts",
                        new { userId = user.Id, token = token }, Request.Scheme);

                    // Send the confirmation email
                    await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
                        $"Please confirm your account by clicking this link: <a href='{confirmationLink}'>link</a>");

                    // Sign in the user and redirect them to the home page
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (userId == null || token == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return View("ConfirmEmail");
            }

            return View("Error");
        }

        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View("Login");
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                // Set JWT as a HttpOnly, Secure, and SameSite cookie here
                string jwtToken = await GetJwtFromApiAsync(info);  // You will need to implement this

                Response.Cookies.Append(
                    "jwt",
                    jwtToken,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true, // Ensure the cookie is sent over HTTPS
                SameSite = SameSiteMode.Strict // Prevents the cookie from being sent in cross-site requests
            }
                );

                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var user = new ApplicationUser { UserName = email, Email = email };
                var createResult = await _userManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    createResult = await _userManager.AddLoginAsync(user, info);
                    if (createResult.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }
                foreach (var error in createResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
            }
        }

        private async Task<string> GetJwtFromApiAsync(ExternalLoginInfo info)
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var client = new HttpClient();

            var content = new StringContent(
                JsonConvert.SerializeObject(new { Email = email }),
                Encoding.UTF8,
                "application/json");

            var response = await client.PostAsync("https://localhost:44305/auth", content);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(jsonResponse);

                return tokenResponse.Token;
            }
            else
            {
                throw new Exception("Failed to retrieve JWT token from API");
            }
        }

        public async Task<string> GetJwtOrRefresh()
        {
            var jwt = Request.Cookies["jwt"];
            var jwtHandler = new JwtSecurityTokenHandler();
            var token = jwtHandler.ReadJwtToken(jwt);

            // Check if token is close to expiring
            if (token.ValidTo > DateTime.UtcNow.AddMinutes(5))
            {
                return jwt;
            }

            // Refresh token
            var client = new HttpClient();
            var content = new StringContent(
                JsonConvert.SerializeObject(new { Token = jwt }),
                Encoding.UTF8,
                "application/json");
            var response = await client.PostAsync("https://localhost:44305/auth/refresh", content);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(jsonResponse);

                // Set new JWT as a cookie
                Response.Cookies.Append(
                    "jwt",
                    tokenResponse.Token,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    }
                );

                return tokenResponse.Token;
            }
            else
            {
                throw new Exception("Failed to refresh JWT token");
            }
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Action(
                    "ResetPassword",
                    "Accounts",
                    new { userId = user.Id, code = code },
                    Request.Scheme);

                await _emailSender.SendEmailAsync(
                    model.Email,
                    "Reset Password",
                    $"Please reset your password by clicking <a href='{callbackUrl}'>here</a>");

                return View("ForgotPasswordConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null, string userId = null)
        {
            // Check if both userId and code are not null
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(userId))
            {
                return View("Error");
            }
            else
            {
                var model = new ResetPasswordViewModel { Code = code, UserId = userId };
                return View(model);
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(AccountsController.ResetPasswordConfirmation), "Accounts");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(AccountsController.ResetPasswordConfirmation), "Accounts");
            }
            AddErrors(result);
            return View();
        }

        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }



    }
}

