using BCrypt.Net;
using JwtWebApi.DTOs;
using JwtWebApi.Models;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User User = new User();
        public readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("register")]
        public ActionResult<User> Register(UserDto data)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(data.Password);
            User.PasswordHash = passwordHash;
            User.UserName = data.UserName;
            return Ok(User);

        }
        [HttpPost("login")]
        public ActionResult<User> Login(UserDto data)
        {
            if (User.UserName != data.UserName)
            {
                return BadRequest("User Not Found");
            }
            if (!BCrypt.Net.BCrypt.Verify(data.Password, User.PasswordHash))
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(User);
            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {

            new Claim(ClaimTypes.UserData, user.UserName),

            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
       
    }
}
