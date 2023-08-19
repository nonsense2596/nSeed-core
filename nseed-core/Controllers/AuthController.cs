using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using nseed_core.Authentication;
using nseed_core.Services;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace nseed_core.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {

        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly TokenService _tokenService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, ApplicationDbContext context, TokenService tokenService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _tokenService = tokenService;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegistrationRequest request)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new User { UserName = request.Username, Email = request.Email };

            var result = await _userManager.CreateAsync(
                user,
                request.Password
            );

            if (result.Succeeded)
            {
                request.Password = "";
                var adminRoleExists = await _roleManager.RoleExistsAsync("User");
                if (adminRoleExists)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                }

                return CreatedAtAction(nameof(Register), new { email = request.Email }, request);
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }
            return BadRequest(ModelState);
        }

        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<AuthResponse>> Authenticate([FromBody] AuthRequest request)
        {
            // validation of credentials
            if (!ModelState.IsValid) { return BadRequest("Bad credentials"); }
            Debug.WriteLine("asd");
            Debug.WriteLine(request.Email);

            var managedUser = await _userManager.FindByEmailAsync(request.Email);
            if (managedUser == null) { return BadRequest("Bad credentials"); }

            var isPasswordValid = await _userManager.CheckPasswordAsync(managedUser, request.Password);
            if (!isPasswordValid) { return BadRequest("Bad credentials"); }

            var userInDb = _context.Users.FirstOrDefault(u => u.Email == request.Email);
            if (userInDb is null) return Unauthorized();

            var userRoles = await _userManager.GetRolesAsync(userInDb);

            var authClaims = new List<Claim> { };

            if (userRoles.Count == 0) authClaims.Add(new Claim("userRole", ""));
            else authClaims.Add(new Claim("userRole", userRoles[0]));
            authClaims.Add(new Claim("userName", userInDb.UserName));
            authClaims.Add(new Claim("userEmail", userInDb.Email));

            var accessToken = _tokenService.CreateToken(userInDb, authClaims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            userInDb.RefreshToken = refreshToken;
            userInDb.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);


            await _context.SaveChangesAsync();

            return Ok(new AuthResponse
            {
                Username = userInDb.UserName, 
                Email = userInDb.Email, 
                Token = new JwtSecurityTokenHandler().WriteToken(accessToken),
                RefreshToken = refreshToken,
                Expiration = accessToken.ValidTo    
            });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(Token tokenModel)
        {
            if (tokenModel is null) return BadRequest("Invalid access token or refresh token");

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
            if (principal == null) { return BadRequest("Invalid access token or refresh token"); }
            string username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now) { return BadRequest("Invalid access token or refresh token"); }


            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim> { };

            if (userRoles.Count == 0) authClaims.Add(new Claim("userRole", ""));
            else authClaims.Add(new Claim("userRole", userRoles[0]));
            authClaims.Add(new Claim("userName", user.UserName));
            authClaims.Add(new Claim("userEmail", user.Email));

            var newAccessToken = _tokenService.CreateToken(user, authClaims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);

            await _userManager.UpdateAsync(user);

            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken,
                Expiration = newAccessToken.ValidTo
            });

        }






    }
}
