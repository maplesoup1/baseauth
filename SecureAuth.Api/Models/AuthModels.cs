using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace SecureAuth.Api.Models;

public class LoginRequest
{
    [Required]
    [EmailAddress]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    public string Password { get; set; } = string.Empty;
    
    public string? Code { get; set; }
    
    public string? Uuid { get; set; }
}

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string Name { get; set; } = string.Empty;
    
    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;
    
    public string? Code { get; set; }
    
    public string? Uuid { get; set; }
}

public class LoginUser : ClaimsPrincipal
{
    public string UserId { get; set; } = string.Empty;
    public string Username => Email;
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Source { get; set; }
    public int RoleId { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime LoginTime { get; set; } = DateTime.UtcNow;
    public DateTime ExpireTime { get; set; }
    public string? IpAddress { get; set; }
    public string? DeviceInfo { get; set; }
    public List<string> Permissions { get; set; } = new();

    public User User { get; set; } = new();

    public LoginUser() : base() { }

    public LoginUser(ClaimsIdentity identity) : base(identity) 
    {
        var claims = identity.Claims.ToList();
        UserId = claims.FirstOrDefault(x => x.Type == "userId")?.Value ?? string.Empty;
        Email = claims.FirstOrDefault(x => x.Type == "email")?.Value ?? string.Empty;
        Name = claims.FirstOrDefault(x => x.Type == "name")?.Value ?? string.Empty;
        Source = claims.FirstOrDefault(x => x.Type == "source")?.Value;
        RoleId = int.Parse(claims.FirstOrDefault(x => x.Type == "roleId")?.Value ?? "1");
        Token = claims.FirstOrDefault(x => x.Type == "token")?.Value ?? string.Empty;
        
        if (DateTime.TryParse(claims.FirstOrDefault(x => x.Type == "exp")?.Value, out DateTime exp))
        {
            ExpireTime = exp;
        }
    }

    public static LoginUser FromUser(User user, string token, DateTime expireTime)
    {
        var loginUser = new LoginUser
        {
            UserId = user.UserId,
            Email = user.Email,
            Name = user.Name,
            Source = user.Source,
            RoleId = user.RoleId,
            Token = token,
            ExpireTime = expireTime,
            User = user
        };

        var claims = new List<Claim>
        {
            new("userId", user.UserId),
            new("email", user.Email),
            new("name", user.Name),
            new("roleId", user.RoleId.ToString()),
            new("token", token),
            new("exp", expireTime.ToString())
        };

        if (!string.IsNullOrEmpty(user.Source))
        {
            claims.Add(new Claim("source", user.Source));
        }

        var identity = new ClaimsIdentity(claims, "jwt");
        loginUser.AddIdentity(identity);

        return loginUser;
    }
}

public class AjaxResult
{
    public int Code { get; set; } = 200;
    public string Message { get; set; } = "操作成功";
    public object? Data { get; set; }
    
    public static AjaxResult Success() => new() { Code = 200 };
    public static AjaxResult Success(object data) => new() { Code = 200, Data = data };
    public static AjaxResult Success(string message) => new() { Code = 200, Message = message };
    public static AjaxResult Success(string message, object data) => new() { Code = 200, Message = message, Data = data };
    
    public static AjaxResult Error() => new() { Code = 500, Message = "操作失败" };
    public static AjaxResult Error(string message) => new() { Code = 500, Message = message };
    public static AjaxResult Error(int code, string message) => new() { Code = code, Message = message };
    
    public AjaxResult Put(string key, object value)
    {
        if (Data == null)
        {
            Data = new Dictionary<string, object>();
        }
        
        if (Data is Dictionary<string, object> dict)
        {
            dict[key] = value;
        }
        
        return this;
    }
}