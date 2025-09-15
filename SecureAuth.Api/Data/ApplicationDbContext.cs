using Microsoft.EntityFrameworkCore;
using SecureAuth.Api.Models;

namespace SecureAuth.Api.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<UserLogHistory> UserLogHistories { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User entity configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.UserId).HasMaxLength(255);
            entity.Property(e => e.Email).HasMaxLength(255).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(255).IsRequired();
            entity.Property(e => e.Source).HasMaxLength(50);
            entity.Property(e => e.AccountStatus).HasMaxLength(1).HasDefaultValue("0");
            entity.Property(e => e.CreatedBy).HasMaxLength(255).HasDefaultValue("system");
            entity.Property(e => e.UpdatedBy).HasMaxLength(255).HasDefaultValue("system");
            entity.HasIndex(e => e.Email).IsUnique();
            
            entity.HasOne(e => e.Role)
                  .WithMany(r => r.Users)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // Role entity configuration
        modelBuilder.Entity<Role>(entity =>
        {
            entity.HasKey(e => e.RoleId);
            entity.Property(e => e.RoleName).HasMaxLength(255).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.Property(e => e.Status).HasMaxLength(1).HasDefaultValue("0");
            entity.Property(e => e.CreatedBy).HasMaxLength(255).HasDefaultValue("system");
            entity.Property(e => e.UpdatedBy).HasMaxLength(255).HasDefaultValue("system");
        });

        // UserLogHistory entity configuration
        modelBuilder.Entity<UserLogHistory>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.UserId).HasMaxLength(255).IsRequired();
            entity.Property(e => e.Ip).HasMaxLength(50);
            entity.Property(e => e.IpCountryCode).HasMaxLength(10);
            entity.Property(e => e.DeviceInfo).HasMaxLength(500);
            entity.Property(e => e.CreatedBy).HasMaxLength(255).HasDefaultValue("system");
            entity.Property(e => e.UpdatedBy).HasMaxLength(255).HasDefaultValue("system");
            
            entity.HasOne(e => e.User)
                  .WithMany(u => u.LogHistory)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Seed default roles
        modelBuilder.Entity<Role>().HasData(
            new Role
            {
                RoleId = 1,
                RoleName = "User",
                Description = "Default user role",
                Status = "0",
                CreatedBy = "system",
                UpdatedBy = "system",
                CreatedTime = DateTime.UtcNow,
                UpdatedTime = DateTime.UtcNow
            },
            new Role
            {
                RoleId = 2,
                RoleName = "Admin",
                Description = "Administrator role",
                Status = "0",
                CreatedBy = "system",
                UpdatedBy = "system",
                CreatedTime = DateTime.UtcNow,
                UpdatedTime = DateTime.UtcNow
            }
        );
    }
}