using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Api.Models;

public class User
{
    [Key]
    public string UserId { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string Name { get; set; } = string.Empty;
    
    public string? Source { get; set; }
    
    public int RoleId { get; set; } = 1;
    
    public string AccountStatus { get; set; } = "0";
    
    public int MessageCount { get; set; } = 0;
    
    public string CreatedBy { get; set; } = "system";
    
    public string UpdatedBy { get; set; } = "system";
    
    public DateTime CreatedTime { get; set; } = DateTime.UtcNow;
    
    public DateTime UpdatedTime { get; set; } = DateTime.UtcNow;

    public virtual Role? Role { get; set; }
    public virtual List<UserLogHistory> LogHistory { get; set; } = new();
}

public class Role
{
    [Key]
    public int RoleId { get; set; }
    
    [Required]
    public string RoleName { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    
    public string? Rules { get; set; }
    
    public string Status { get; set; } = "0";
    
    public string CreatedBy { get; set; } = "system";
    
    public string UpdatedBy { get; set; } = "system";
    
    public DateTime CreatedTime { get; set; } = DateTime.UtcNow;
    
    public DateTime UpdatedTime { get; set; } = DateTime.UtcNow;

    public virtual List<User> Users { get; set; } = new();
}

public class UserLogHistory
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    public string? Ip { get; set; }
    
    public string? IpCountryCode { get; set; }
    
    public string? DeviceInfo { get; set; }
    
    public string CreatedBy { get; set; } = "system";
    
    public string UpdatedBy { get; set; } = "system";
    
    public DateTime CreatedTime { get; set; } = DateTime.UtcNow;
    
    public DateTime UpdatedTime { get; set; } = DateTime.UtcNow;

    public virtual User? User { get; set; }
}