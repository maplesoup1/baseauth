using SecureAuth.Api.Services;
using SecureAuth.Api.Utils;
using System.Security.Claims;

namespace SecureAuth.Api.Middleware;

public class JwtAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JwtService _jwtService;
    private readonly ILogger<JwtAuthenticationMiddleware> _logger;

    public JwtAuthenticationMiddleware(RequestDelegate next, JwtService jwtService, ILogger<JwtAuthenticationMiddleware> logger)
    {
        _next = next;
        _jwtService = jwtService;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            var token = GetTokenFromRequest(context.Request);
            
            if (!string.IsNullOrEmpty(token))
            {
                var principal = _jwtService.ValidateToken(token);
                if (principal != null)
                {
                    context.User = principal;
                    _logger.LogDebug("JWT token validated successfully for user: {UserId}", 
                        principal.FindFirst("userId")?.Value);
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("JWT token validation failed: {Message}", ex.Message);
            // Don't set the user, let the request continue as unauthenticated
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in JWT authentication middleware");
        }

        await _next(context);
    }

    private string? GetTokenFromRequest(HttpRequest request)
    {
        // Try to get token from cookie first
        var tokenFromCookie = request.Cookies[Constants.TOKEN] ?? request.Cookies[Constants.ADMIN_TOKEN];
        if (!string.IsNullOrEmpty(tokenFromCookie))
        {
            return tokenFromCookie;
        }

        // Try to get token from Authorization header
        var authHeader = request.Headers["Authorization"].FirstOrDefault();
        if (authHeader != null && authHeader.StartsWith("Bearer "))
        {
            return authHeader.Substring("Bearer ".Length).Trim();
        }

        return null;
    }
}

public static class JwtAuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseJwtAuthentication(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<JwtAuthenticationMiddleware>();
    }
}