using UAParser;

namespace SecureAuth.Api.Utils;

public static class DeviceUtil
{
    public static string GetDeviceInfo(HttpRequest request)
    {
        var userAgentString = request.Headers["User-Agent"].ToString();
        if (string.IsNullOrEmpty(userAgentString))
        {
            return "Unknown";
        }

        var uaParser = Parser.GetDefault();
        var clientInfo = uaParser.Parse(userAgentString);
        
        var os = clientInfo.OS.Family ?? "Unknown OS";
        var browser = clientInfo.UA.Family ?? "Unknown Browser";

        return $"{os} - {browser}";
    }

    public static string GetClientIp(HttpRequest request)
    {
        var forwardedFor = request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor) && !forwardedFor.Equals("unknown", StringComparison.OrdinalIgnoreCase))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        var realIp = request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        return request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }
}

public static class Constants
{
    public const string TOKEN = "token";
    public const string ADMIN_TOKEN = "Admin-Token";
    public const string LOGIN_SUCCESS = "Success";
    public const string LOGIN_FAIL = "Error";
    public const string UTF8 = "UTF-8";
    public const string IPGEOLOCATION = "/api/ip-geolocation/";
    
    public static class HttpStatus
    {
        public const int SUCCESS = 200;
        public const int CREATED = 201;
        public const int UNAUTHORIZED = 401;
        public const int FORBIDDEN = 403;
        public const int NOT_FOUND = 404;
        public const int ERROR = 500;
    }

    public static class UserStatus
    {
        public const string OK = "0";
        public const string DISABLE = "1";
        public const string DELETED = "2";
    }

    public static class CacheConstants
    {
        public const string LOGIN_TOKEN_KEY = "login_tokens:";
        public const string CAPTCHA_CODE_KEY = "captcha_codes:";
    }
}