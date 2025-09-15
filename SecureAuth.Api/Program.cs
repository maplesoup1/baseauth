using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureAuth.Api.Data;
using SecureAuth.Api.Middleware;
using SecureAuth.Api.Services;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Metadata;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Database configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Redis configuration (if needed)
// builder.Services.AddStackExchangeRedisCache(options =>
// {
//     options.Configuration = builder.Configuration.GetConnectionString("Redis");
// });

// HTTP Client
builder.Services.AddHttpClient();

// Custom services
builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<OAuthService>();
builder.Services.AddScoped<SamlService>();

// CORS configuration
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? new[] { "*" };
        
        policy.WithOrigins(allowedOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Authentication configuration
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "your-super-secret-jwt-key-here-must-be-at-least-32-characters";

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Token:Issuer"] ?? "SecureAuth",
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Token:Audience"] ?? "SecureAuth",
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? "";
    options.SaveTokens = true;
})
.AddFacebook(options =>
{
    options.AppId = builder.Configuration["Authentication:Facebook:AppId"] ?? "";
    options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"] ?? "";
    options.SaveTokens = true;
})
.AddMicrosoftAccount(options =>
{
    options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"] ?? "";
    options.SaveTokens = true;
})
.AddSaml2(options =>
{
    options.SPOptions.EntityId = new EntityId(builder.Configuration["Saml2:ServiceProvider:EntityId"] ?? "secure-auth-local");
    options.SPOptions.ReturnUrl = new Uri(builder.Configuration["Saml2:ServiceProvider:AssertionConsumerServiceUrl"] ?? "https://localhost:7001/saml2/acs");
    
    // Configure Identity Provider (AWS SSO)
    var awsSsoEntityId = builder.Configuration["Saml2:IdentityProviders:AwsSso:EntityId"] ?? "aws-sso-identity-provider";
    var awsSsoSingleSignOnUrl = builder.Configuration["Saml2:IdentityProviders:AwsSso:SingleSignOnServiceUrl"];
    
    if (!string.IsNullOrEmpty(awsSsoSingleSignOnUrl))
    {
        options.IdentityProviders.Add(new IdentityProvider(new EntityId(awsSsoEntityId), options.SPOptions)
        {
            SingleSignOnServiceUrl = new Uri(awsSsoSingleSignOnUrl),
            AllowUnsolicitedAuthnResponse = true
        });
    }
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    
    if (!app.Environment.IsDevelopment())
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
    }
    
    await next();
});

app.UseHttpsRedirection();
app.UseCors();

// Authentication & Authorization
app.UseAuthentication();
app.UseJwtAuthentication(); // Custom JWT middleware
app.UseAuthorization();

app.MapControllers();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// Create database if it doesn't exist
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try
    {
        context.Database.EnsureCreated();
    }
    catch (Exception ex)
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred creating the database");
    }
}

app.Run();
