using EncryptedChatFlow.Data;
using EncryptedChatFlow.Models;
using EncryptedChatFlow_Web.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SendGrid;
using Serilog;
using System;

namespace EncryptedChatFlow_Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .CreateLogger();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddSingleton(Log.Logger);

            services.AddSignalR();

            services.AddTransient<IEmailSender, SendGridEmailSender>();
            services.AddSingleton<ISendGridClient>(x => new SendGridClient(Configuration["SendGrid:ApiKey"]));

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    IConfigurationSection googleAuthNSection =
                        Configuration.GetSection("Authentication:Google");

                    options.ClientId = googleAuthNSection["ClientId"];
                    options.ClientSecret = googleAuthNSection["ClientSecret"];
                })
                .AddFacebook(options =>
                {
                    IConfigurationSection fbAuthNSection =
                        Configuration.GetSection("Authentication:Facebook");

                    options.AppId = fbAuthNSection["AppId"];
                    options.AppSecret = fbAuthNSection["AppSecret"];
                });

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly("EncryptedChatFlow")));

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(options =>
            {
                // Cookie settings
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);

                options.LoginPath = "/Accounts/Login"; // your login path
                options.AccessDeniedPath = "/Accounts/AccessDenied"; // you can set this path as per your design
                options.SlidingExpiration = true;
            });

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            // Middleware for error handling. 
            app.UseExceptionHandler(errorApp =>
            {
                errorApp.Run(async context =>
                {
                    context.Response.StatusCode = 500; // or another status code of your choice
                    context.Response.ContentType = "text/html";

                    var errorFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                    if (errorFeature != null)
                    {
                        var exception = errorFeature.Error;

                        // log the exception, e.g.
                        logger.LogError(exception, "An error occurred while processing your request.");

                        await context.Response.WriteAsync("<h1>An error occurred while processing your request.</h1>");
                        await context.Response.WriteAsync(new string(' ', 512)); // Padding for IE
                    }
                });
            });



            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseMiddleware<ValidateTokenMiddleware>();
            app.UseAuthentication();
            app.UseAuthorization();

            

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");

                endpoints.MapHub<ChatHub>("/chathub");
            });

            app.UseSerilogRequestLogging();

        }

    }
}
