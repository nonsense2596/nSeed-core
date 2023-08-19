using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using nseed_core.Authentication;

namespace nseed_core
{
    public class ApplicationDbContext: IdentityDbContext<User>
    {

        private readonly IConfiguration _configuration;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IConfiguration configuration) : base(options)
        {
            _configuration = configuration;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            var roles = _configuration.GetSection("SeedRolesAndUsers:Roles").Get<List<Dictionary<string, string>>>();
            var users = _configuration.GetSection("SeedRolesAndUsers:Users").Get<List<Dictionary<string, string>>>();

            foreach(var role in roles)
            {
                modelBuilder.Entity<IdentityRole>().HasData(
                    new IdentityRole { 
                        Id = role["Id"], 
                        Name = role["Name"] 
                    }
                );

            };

            foreach(var user in users)
            {
                var appUser = new User { 
                    Id = user["Id"],
                    UserName = user["UserName"], 
                    NormalizedUserName = user["UserName"].ToUpper(), 
                    Email = user["Email"], 
                    NormalizedEmail = user["Email"].ToUpper(),
                };
                PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
                appUser.PasswordHash = passwordHasher.HashPassword(appUser, user["Password"]);

                modelBuilder.Entity<User>().HasData(appUser);

                modelBuilder.Entity<IdentityUserRole<string>>().HasData(
                    new IdentityUserRole<string> { 
                        RoleId = user["RoleId"], 
                        UserId = user["Id"] 
                    }
                );

            };


        }
    }
}
