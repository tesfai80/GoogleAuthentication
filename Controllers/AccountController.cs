﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;

namespace GoogleAuth.Controllers
{
    [AllowAnonymous,Route("account")]
    public class AccountController : Controller
    {
        [Route("google-login")]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse")
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }
        [Route("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var results = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var claims = results.Principal.Identities.FirstOrDefault()
                .Claims.Select(claim => new
                {
                    claim.Issuer,
                    claim.OriginalIssuer,
                    claim.Type,
                    claim.Value
                });
            return Json(claims);
        }
    }
}
