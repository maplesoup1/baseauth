using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.Api.Services;

namespace SecureAuth.Api.Controllers;

[ApiController]
[Route("saml2")]
public class SamlController : ControllerBase
{
    private readonly SamlService _samlService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SamlController> _logger;

    public SamlController(SamlService samlService, IConfiguration configuration, ILogger<SamlController> logger)
    {
        _samlService = samlService;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("sso")]
    public IActionResult InitiateSingleSignOn(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(AssertionConsumerService)),
            Items = { ["returnUrl"] = returnUrl ?? "/" }
        };

        return Challenge(properties, "Saml2");
    }

    [HttpPost("acs")]
    public async Task<IActionResult> AssertionConsumerService()
    {
        try
        {
            _logger.LogInformation("SAML ACS endpoint called");

            var result = await HttpContext.AuthenticateAsync("Saml2");
            if (!result.Succeeded)
            {
                _logger.LogError("SAML authentication failed: {Error}", result.Failure?.Message);
                var errorUrl = _configuration["ExternalApis:AdminUiUrl"] ?? "http://localhost:3001";
                return Redirect($"{errorUrl}?error=saml_auth_failed");
            }

            _logger.LogInformation("SAML authentication successful for user: {User}", result.Principal?.Identity?.Name);

            var user = await _samlService.HandleSamlLoginAsync(result.Principal!, Request);
            var token = _samlService.CreateAdminJwtCookie(user, Response);

            _logger.LogInformation("JWT token created for user: {UserId}", user.UserId);

            var redirectUrl = _configuration["ExternalApis:AdminUiUrl"] ?? "http://localhost:3001";
            return Redirect(redirectUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML ACS");
            var errorUrl = _configuration["ExternalApis:AdminUiUrl"] ?? "http://localhost:3001";
            return Redirect($"{errorUrl}?error=saml_processing_failed&message={Uri.EscapeDataString(ex.Message)}");
        }
    }

    [HttpGet("sls")]
    [HttpPost("sls")]
    public async Task<IActionResult> SingleLogoutService()
    {
        try
        {
            _logger.LogInformation("SAML SLS endpoint called");

            // Clear authentication cookies
            Response.Cookies.Delete("Admin-Token");
            Response.Cookies.Delete("token");

            // Process SAML logout
            await HttpContext.SignOutAsync("Saml2");

            var redirectUrl = _configuration["ExternalApis:AdminUiUrl"] ?? "http://localhost:3001";
            return Redirect($"{redirectUrl}?message=logged_out");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML SLS");
            var redirectUrl = _configuration["ExternalApis:AdminUiUrl"] ?? "http://localhost:3001";
            return Redirect($"{redirectUrl}?error=logout_failed");
        }
    }

    [HttpGet("metadata")]
    public IActionResult Metadata()
    {
        // This endpoint would return SAML metadata for the service provider
        // The actual implementation depends on the Sustainsys.Saml2 library configuration
        return Challenge("Saml2");
    }
}