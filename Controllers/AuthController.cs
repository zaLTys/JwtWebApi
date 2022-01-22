using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public partial class AuthController : ControllerBase
    {
        public static User _user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet("GetUserDetails"), Authorize]
        public ActionResult<UserDetailsModel> GetUserDetails() //just a POC, I know this is already a fat controller
        {
            var userName = User?.Identity?.Name;
            var alternativeUserName = User.FindFirstValue(ClaimTypes.Name);
            var role = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new UserDetailsModel
            {
                Role = role,
                Username = userName,
                Username2 = alternativeUserName
            });
        }

        [HttpGet("GetUserDetailsViaService"), Authorize]
        public ActionResult<UserDetailsModel> GetUserDetailsViaService() //just a POC, I know this is already a fat controller
        {
            return _userService.GetUserDetails();
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);


            _user.Username = request.Username;
            _user.PasswordHash = passwordHash;
            _user.PasswordSalt = passwordSalt;

            return Ok(_user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (_user.Username != request.Username)
            {
                return BadRequest("userNotFound");
            }

            if (!VerifyPasswordHash(request.Password, _user.PasswordHash, _user.PasswordSalt))
            {
                return BadRequest("wrongPasss");
            }

            string token = CreateToken(_user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:JwtSecretKey").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }


        [HttpPost("validateToken")]
        public async Task<ActionResult<UserDetailsModel>> ValidateToken(string token)
        {
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8
                .GetBytes(_configuration.GetSection("AppSettings:JwtSecretKey").Value));
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // expire exactly  (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                //Initial testing:
                var values = jwtToken.Claims.Select(x => x.Value).ToList();
                var types = jwtToken.Claims.Select(x => x.Type).ToList();

                //Better alternative:
                var claims = JwtParser.ParseClaimsFromJwt(token);
                var identity = new ClaimsIdentity(claims, "jwt");
                var user = new ClaimsPrincipal(identity);


                return Ok($"Token valid for username {user.FindFirstValue(ClaimTypes.Name)}");
            }
            catch
            {
                //failed
                return BadRequest("Token invalid");
            }
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }
    }
}
