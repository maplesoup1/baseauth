using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Api.Data;
using SecureAuth.Api.Models;
using SecureAuth.Api.Utils;
using System.Security.Claims;

namespace SecureAuth.Api.Services;

public class OAuthService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;

    public OAuthService(
        ApplicationDbContext context, 
        JwtService jwtService, 
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory)
    {
        _context = context;
        _jwtService = jwtService;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<User> HandleOAuthLoginAsync(ClaimsPrincipal principal, string source, HttpRequest request)
    {
        var userId = GetUserId(principal, source);
        var email = GetEmail(principal);
        var name = GetName(principal);
        
        var deviceInfo = DeviceUtil.GetDeviceInfo(request);
        var ip = DeviceUtil.GetClientIp(request);
        var countryCode = await GetCountryByIpAsync(ip);

        var existingUser = await _context.Users
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u => u.Email == email);

        User user;
        if (existingUser != null)
        {
            // Update existing user
            existingUser.UserId = userId;
            existingUser.Name = name;
            existingUser.Source = source;
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
                Source = source,
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
            IpCountryCode = countryCode,
            DeviceInfo = deviceInfo,
            CreatedBy = "system",
            UpdatedBy = "system"
        };

        _context.UserLogHistories.Add(logHistory);
        await _context.SaveChangesAsync();

        return user;
    }

    public string CreateJwtCookie(User user, HttpResponse response)
    {
        var userClaims = new Dictionary<string, object>
        {
            ["userId"] = user.UserId,
            ["email"] = user.Email,
            ["name"] = user.Name,
            ["source"] = user.Source ?? "",
            ["roleId"] = user.RoleId.ToString()
        };

        var jwtToken = _jwtService.GenerateToken(userClaims);
        var expireTime = DateTime.UtcNow.AddHours(8);

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !IsDevelopment(),
            SameSite = SameSiteMode.None,
            MaxAge = TimeSpan.FromHours(8),
            Path = "/"
        };

        if (!IsDevelopment())
        {
            var baseUrl = _configuration["ExternalApis:AppUiUrl"] ?? "http://localhost:3000";
            if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
            {
                cookieOptions.Domain = uri.Host;
            }
        }

        response.Cookies.Append(Constants.TOKEN, jwtToken, cookieOptions);
        return jwtToken;
    }

    private string GetUserId(ClaimsPrincipal principal, string source)
    {
        return source.ToLower() switch
        {
            "google" => principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                       principal.FindFirst("sub")?.Value ?? "",
            "facebook" => principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                         principal.FindFirst("id")?.Value ?? "",
            "microsoft" => principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                          principal.FindFirst("oid")?.Value ?? 
                          principal.FindFirst("sub")?.Value ?? "",
            _ => principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? ""
        };
    }

    private string GetEmail(ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.Email)?.Value ?? 
               principal.FindFirst("email")?.Value ?? 
               principal.FindFirst("preferred_username")?.Value ?? "";
    }

    private string GetName(ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.Name)?.Value ?? 
               principal.FindFirst("name")?.Value ?? 
               principal.FindFirst("preferred_username")?.Value ?? "";
    }

    private async Task<int> GetRoleIdByEmailAsync(string email)
    {
        // Check if user has specific role assigned
        // For now, return default role ID = 1
        // You can implement role assignment logic based on email domains or other criteria
        await Task.CompletedTask;
        return 1;
    }

    private async Task<string> GetCountryByIpAsync(string ip)
    {
        try
        {
            var optimusApiUrl = _configuration["ExternalApis:OptimusApiUrlInternal"];
            var optimusApiToken = _configuration["ExternalApis:OptimusApiToken"];
            
            if (string.IsNullOrEmpty(optimusApiUrl) || string.IsNullOrEmpty(optimusApiToken))
            {
                return "NA";
            }

            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {optimusApiToken}");
            
            var url = $"{optimusApiUrl}{Constants.IPGEOLOCATION}{ip}";
            var response = await httpClient.GetStringAsync(url);
            
            var countryCode = response.Trim().Trim('"');
            return string.IsNullOrEmpty(countryCode) ? "NA" : countryCode;
        }
        catch
        {
            return "NA";
        }
    }

    private bool IsDevelopment()
    {
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        return "Development".Equals(environment, StringComparison.OrdinalIgnoreCase);
    }
}