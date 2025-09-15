using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAuth.Api.Services;

public class JwtService
{
    private readonly IConfiguration _configuration;
    private readonly string _jwtSecret;
    private readonly int _expireTimeHours;

    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
        _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? 
                    throw new ArgumentNullException("JWT_SECRET environment variable is required");
        _expireTimeHours = int.Parse(_configuration["Token:ExpireTime"] ?? "8");
    }

    public string GenerateToken(Dictionary<string, object> userClaims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>();
        foreach (var claim in userClaims)
        {
            claims.Add(new Claim(claim.Key, claim.Value?.ToString() ?? string.Empty));
        }

        var now = DateTime.UtcNow;
        var expirationDate = now.AddHours(_expireTimeHours);

        var token = new JwtSecurityToken(
            issuer: _configuration["Token:Issuer"] ?? "ScamsReportAuth",
            audience: _configuration["Token:Audience"] ?? "ScamsReportAuth",
            claims: claims,
            notBefore: now,
            expires: expirationDate,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = _configuration["Token:Issuer"] ?? "ScamsReportAuth",
                ValidateAudience = true,
                ValidAudience = _configuration["Token:Audience"] ?? "ScamsReportAuth",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
            return principal;
        }
        catch (SecurityTokenException)
        {
            throw new UnauthorizedAccessException("Invalid JWT signature");
        }
        catch (Exception)
        {
            throw new UnauthorizedAccessException("Invalid or expired JWT token");
        }
    }

    public ClaimsIdentity? GetClaimsFromToken(string token)
    {
        var principal = ValidateToken(token);
        return principal?.Identity as ClaimsIdentity;
    }
}