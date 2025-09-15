using Microsoft.EntityFrameworkCore;
using SecureAuth.Api.Data;
using SecureAuth.Api.Models;
using SecureAuth.Api.Utils;
using Sustainsys.Saml2;
using System.Security.Claims;

namespace SecureAuth.Api.Services;

public class SamlService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly IConfiguration _configuration;

    public SamlService(ApplicationDbContext context, JwtService jwtService, IConfiguration configuration)
    {
        _context = context;
        _jwtService = jwtService;
        _configuration = configuration;
    }

    public async Task<User> HandleSamlLoginAsync(ClaimsPrincipal principal, HttpRequest request)
    {
        var email = GetEmailFromSamlClaims(principal);
        var name = GetNameFromSamlClaims(principal);
        var userId = GetUserIdFromSamlClaims(principal) ?? Guid.NewGuid().ToString();
        
        var deviceInfo = DeviceUtil.GetDeviceInfo(request);
        var ip = DeviceUtil.GetClientIp(request);

        var existingUser = await _context.Users
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u => u.Email == email);

        User user;
        if (existingUser != null)
        {
            // Update existing user
            existingUser.UserId = userId;
            existingUser.Name = name;
            existingUser.Source = "saml";
            existingUser.UpdatedTime = DateTime.UtcNow;
            user = existingUser;
        }
        else
        {
            // Create new user
            user = new User
            {
                UserId = userId,
                Email = email,
                Name = name,
                Source = "saml",
                RoleId = await GetRoleIdByEmailAsync(email),
                CreatedBy = "system",
                UpdatedBy = "system"
            };
            
            _context.Users.Add(user);
        }

        // Save user changes
        await _context.SaveChangesAsync();

        // Log login history
        var logHistory = new UserLogHistory
        {
            UserId = user.UserId,
            Ip = ip,
            DeviceInfo = deviceInfo,
            CreatedBy = "system",
            UpdatedBy = "system"
        };

        _context.UserLogHistories.Add(logHistory);
        await _context.SaveChangesAsync();

        return user;
    }

    public string CreateAdminJwtCookie(User user, HttpResponse response)
    {
        var userClaims = new Dictionary<string, object>
        {
            ["userId"] = user.UserId,
            ["email"] = user.Email,
            ["name"] = user.Name,
            ["source"] = "saml",
            ["roleId"] = user.RoleId.ToString()
        };

        var jwtToken = _jwtService.GenerateToken(userClaims);
        var expireTimeMinutes = int.Parse(_configuration["Token:ExpireTime"] ?? "8") * 60;

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !IsDevelopment(),
            MaxAge = TimeSpan.FromMinutes(expireTimeMinutes),
            Path = "/"
        };

        response.Cookies.Append(Constants.ADMIN_TOKEN, jwtToken, cookieOptions);
        return jwtToken;
    }

    private string GetEmailFromSamlClaims(ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.Email)?.Value ??
               principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value ??
               principal.FindFirst("email")?.Value ?? "";
    }

    private string GetNameFromSamlClaims(ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.Name)?.Value ??
               principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value ??
               principal.FindFirst("name")?.Value ??
               principal.FindFirst(ClaimTypes.GivenName)?.Value ?? "";
    }

    private string? GetUserIdFromSamlClaims(ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
               principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value ??
               principal.FindFirst("sub")?.Value;
    }

    private async Task<int> GetRoleIdByEmailAsync(string email)
    {
        // Check if user has specific role assigned based on email
        // For AWS SSO, you might want to map certain domains to admin roles
        if (email.EndsWith("@company.com") || email.EndsWith("@admin.com"))
        {
            return 2; // Admin role
        }
        
        await Task.CompletedTask;
        return 1; // Default user role
    }

    private bool IsDevelopment()
    {
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        return "Development".Equals(environment, StringComparison.OrdinalIgnoreCase);
    }
}