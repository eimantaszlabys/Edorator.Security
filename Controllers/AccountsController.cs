using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Edorator.Security.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.MongoDB;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Edorator.Security.Controllers
{
    [Route("api/[controller]")]
    public class AccountsController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;


        public AccountsController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            if (userManager == null) throw new ArgumentNullException(nameof(userManager));
            if (signInManager == null) throw new ArgumentNullException(nameof(signInManager));
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Register")]
        public async Task<ActionResult> Register([FromBody]RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var identityUser = new IdentityUser
                {
                    Email = model.Email,
                    UserName = model.Email,
                    Roles = new List<string> { "user" }
                };

                IdentityResult result = await _userManager.CreateAsync(identityUser, model.Password);
                if (result.Succeeded)
                {
                    return Ok(result);
                }
                else
                {
                    return BadRequest(result);
                }
            }

            return BadRequest(ModelState);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Login")]
        public async Task<ActionResult> Login([FromBody] LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, true, true);
                if (result.Succeeded)
                {
                    IdentityUser user = await _userManager.FindByNameAsync(model.Email);
                    var requestAt = DateTime.Now;
                    var expiresIn = requestAt + TokenAuthOption.ExpiresSpan;
                    var token = GenerateToken(user, expiresIn);

                    return Ok(new
                    {
                        requertAt = requestAt,
                        expiresIn = TokenAuthOption.ExpiresSpan.TotalSeconds,
                        tokeyType = TokenAuthOption.TokenType,
                        accessToken = token
                    });
                }
                else
                {
                    return BadRequest(new {
                        errorMessage = "Bad 'username' or 'password'."
                    });
                }
            }

            return BadRequest(ModelState);
        }

        [HttpPost]
        //[Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("logout")]
        public async Task<ActionResult> LogOut()
        {
            ClaimsPrincipal principal = User;
            

            if(principal.Identity.IsAuthenticated)
            {
                await _signInManager.SignOutAsync();
            }

            return Ok();
        }

        private static string GenerateToken(IdentityUser user, DateTime expires)
        {
            var handler = new JwtSecurityTokenHandler();

            var claims = user.Claims.Select(x => x.ToSecurityClaim()).ToList();

            foreach (string userRole in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = TokenAuthOption.Issuer,
                Audience = TokenAuthOption.Audience,
                SigningCredentials = TokenAuthOption.SigningCredentials,
                Subject = new ClaimsIdentity(claims),
                Expires = expires,
                
            });
            return handler.WriteToken(securityToken);
        }

        [HttpGet]
        [Route("ValidateToken/{accessToken}")]
        public ActionResult ValidateAccessToken(string accessToken)
        {
            SecurityToken securityToken;
            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = TokenAuthOption.Issuer,
                ValidAudience = TokenAuthOption.Audience,
                 IssuerSigningKey = TokenAuthOption.Key,

            };

            var recipientTokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal claimsPrincipal = recipientTokenHandler.ValidateToken(accessToken, validationParameters, out securityToken);
            return Ok(claimsPrincipal.Claims.Select(x => new
            {
                x.Value
            }));
        }
    }
}
