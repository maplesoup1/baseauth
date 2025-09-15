using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Api.Data;
using SecureAuth.Api.Models;
using SecureAuth.Api.Services;
using SecureAuth.Api.Utils;
using System.Security.Claims;

namespace SecureAuth.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly OAuthService _oauthService;
    private readonly IConfiguration _configuration;

    public AuthController(
        ApplicationDbContext context, 
        JwtService jwtService, 
        OAuthService oauthService,
        IConfiguration configuration)
    {
        _context = context;
        _jwtService = jwtService;
        _oauthService = oauthService;
        _configuration = configuration;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var user = await _context.Users
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email == request.Username);

            if (user == null)
            {
                return Ok(AjaxResult.Error("用户不存在"));
            }

            // For demo purposes, we'll accept any password
            // In production, you should verify the password hash
            // if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            // {
            //     return Ok(AjaxResult.Error("密码错误"));
            // }

            var userClaims = new Dictionary<string, object>
            {
                ["userId"] = user.UserId,
                ["email"] = user.Email,
                ["name"] = user.Name,
                ["roleId"] = user.RoleId.ToString()
            };

            if (!string.IsNullOrEmpty(user.Source))
            {
                userClaims["source"] = user.Source;
            }

            var token = _jwtService.GenerateToken(userClaims);

            // Log login history
            var deviceInfo = DeviceUtil.GetDeviceInfo(Request);
            var ip = DeviceUtil.GetClientIp(Request);
            
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

            return Ok(AjaxResult.Success().Put(Constants.TOKEN, token));
        }
        catch (Exception ex)
        {
            return Ok(AjaxResult.Error($"登录失败: {ex.Message}"));
        }
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (existingUser != null)
            {
                return Ok(AjaxResult.Error("用户已存在"));
            }

            var user = new User
            {
                UserId = Guid.NewGuid().ToString(),
                Email = request.Email,
                Name = request.Name,
                Source = "local",
                RoleId = 1,
                CreatedBy = "system",
                UpdatedBy = "system"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(AjaxResult.Success("注册成功"));
        }
        catch (Exception ex)
        {
            return Ok(AjaxResult.Error($"注册失败: {ex.Message}"));
        }
    }

    [HttpGet("user/check")]
    [Authorize]
    public async Task<IActionResult> GetUserInfo()
    {
        try
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _context.Users
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.UserId == userId);

            if (user == null)
            {
                return NotFound();
            }

            var userInfo = new
            {
                user.UserId,
                user.Email,
                user.Name,
                user.Source,
                user.RoleId,
                RoleName = user.Role?.RoleName
            };

            return Ok(userInfo);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"获取用户信息失败: {ex.Message}");
        }
    }

    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout()
    {
        // Clear token cookie
        Response.Cookies.Delete(Constants.TOKEN);
        Response.Cookies.Delete(Constants.ADMIN_TOKEN);
        
        return Ok(AjaxResult.Success("退出成功"));
    }

    // OAuth callback endpoints
    [HttpGet("oauth/google")]
    public IActionResult GoogleLogin(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(GoogleCallback)),
            Items = { ["returnUrl"] = returnUrl ?? "/" }
        };
        
        return Challenge(properties, "Google");
    }

    [HttpGet("oauth/google/callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        return await HandleOAuthCallback("Google");
    }

    [HttpGet("oauth/facebook")]
    public IActionResult FacebookLogin(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(FacebookCallback)),
            Items = { ["returnUrl"] = returnUrl ?? "/" }
        };
        
        return Challenge(properties, "Facebook");
    }

    [HttpGet("oauth/facebook/callback")]
    public async Task<IActionResult> FacebookCallback()
    {
        return await HandleOAuthCallback("Facebook");
    }

    [HttpGet("oauth/microsoft")]
    public IActionResult MicrosoftLogin(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(MicrosoftCallback)),
            Items = { ["returnUrl"] = returnUrl ?? "/" }
        };
        
        return Challenge(properties, "Microsoft");
    }

    [HttpGet("oauth/microsoft/callback")]
    public async Task<IActionResult> MicrosoftCallback()
    {
        return await HandleOAuthCallback("Microsoft");
    }

    private async Task<IActionResult> HandleOAuthCallback(string provider)
    {
        try
        {
            var result = await HttpContext.AuthenticateAsync(provider);
            if (!result.Succeeded)
            {
                var errorUrl = _configuration["ExternalApis:AppUiUrl"] ?? "http://localhost:3000";
                return Redirect($"{errorUrl}?error=auth_failed");
            }

            var user = await _oauthService.HandleOAuthLoginAsync(result.Principal!, provider.ToLower(), Request);
            _oauthService.CreateJwtCookie(user, Response);

            var redirectUrl = _configuration["ExternalApis:AppUiUrl"] ?? "http://localhost:3000";
            return Redirect(redirectUrl);
        }
        catch (Exception ex)
        {
            var errorUrl = _configuration["ExternalApis:AppUiUrl"] ?? "http://localhost:3000";
            return Redirect($"{errorUrl}?error=callback_failed&message={Uri.EscapeDataString(ex.Message)}");
        }
    }
}