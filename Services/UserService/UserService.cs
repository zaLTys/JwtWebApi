using System.Security.Claims;

namespace JwtWebApi.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public UserDetailsModel GetUserDetails()
        {
            var result = new UserDetailsModel();
            if(_httpContextAccessor.HttpContext != null)
            {
                result.Role = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);
                result.Username = _httpContextAccessor.HttpContext.User.Identity?.Name;
                result.Username2 = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return result;
           
        }
    }
}
