using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Blog.TokenAuthGettingStarted
{
    using System.Text;
    using CustomTokenProvider;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;

    public partial class Startup
    {

        private void ConfigureAuth(IServiceCollection services)
        {

            signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("TokenAuthentication:SecretKey").Value));


            var tokenValidationParameters = new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = Configuration.GetSection("TokenAuthentication:Issuer").Value,
                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = Configuration.GetSection("TokenAuthentication:Audience").Value,
                // Validate the token expiry
                ValidateLifetime = true,
                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero
            };

            /*
             services.AddAuthentication(options =>
        {
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })

        .AddJwtBearer(options =>
        {
            options.Authority = "http://localhost:30940/";
            options.Audience = "resource-server";
            options.RequireHttpsMetadata = false;
        }); 
             * */
            services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                }
                )
                .AddCookie(o =>
                {
                    o.Cookie.Domain = "http://localhost:50000/";
                    o.Cookie.Expiration = DateTime.UtcNow.AddMinutes(10).TimeOfDay;
                    o.Cookie.Name = Configuration.GetSection("TokenAuthentication:CookieName").Value;
                    o.TicketDataFormat = new CustomJwtDataFormat( SecurityAlgorithms.HmacSha256, tokenValidationParameters);
                    o.LoginPath = new PathString(Configuration.GetSection("TokenAuthentication:TokenPath").Value);
                })
                .AddJwtBearer(options =>
                {
                    //options.Authority = "http://localhost:50000/";
                    //options.Audience = "resource-server";
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = tokenValidationParameters;
                    //options.SaveToken = true;


                })


            ;

            //services.UseJwtBearerAuthentication(new JwtBearerOptions
            //{
            //    //AutomaticAuthenticate = true,
            //    //AutomaticChallenge = true,

            //});



            //services.UseCookieAuthentication(new CookieAuthenticationOptions
            //{
            //    //AutomaticAuthenticate = true,
            //    //AutomaticChallenge = true,
            //    //AuthenticationScheme = "Cookie",
            //    //  CookieName = Configuration.GetSection("TokenAuthentication:CookieName").Value,
            //    TicketDataFormat = new CustomJwtDataFormat(
            //        SecurityAlgorithms.HmacSha256,
            //        tokenValidationParameters)
            //});

            //var tokenProviderOptions = new TokenProviderOptions
            //{
            //    Path = Configuration.GetSection("TokenAuthentication:TokenPath").Value,
            //    Audience = Configuration.GetSection("TokenAuthentication:Audience").Value,
            //    Issuer = Configuration.GetSection("TokenAuthentication:Issuer").Value,
            //    SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
            //    IdentityResolver = GetIdentity
            //};

            //services.UseMiddleware<TokenProviderMiddleware>(Options.Create(tokenProviderOptions));


        }

        private Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            // Don't do this in production, obviously!
            if (username == "TEST" && password == "TEST123")
            {
                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(username, "Token"), new Claim[] { }));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

    }
}