// Program.cs - punto de entrada y configuración de servicios y middleware.
// Comentarios explican cada bloque y su relación con OWASP.

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SafeStoreWeb.Models;
using SafeStoreWeb.Services;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ==================== CONFIGURACIÓN DE SERVICIOS ====================

// ---------------------- Configuración DB (Postgres) ----------------------
// OWASP 3: Entity Framework Core usa parámetros preparados automáticamente
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// ---------------------- Identity (Autenticación y autorización) ----------------------
// OWASP 1: Configuración de Identity con BCrypt personalizado
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // OWASP A07: Políticas de contraseña fuertes
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12; // Aumentado para mayor seguridad
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 6;

    // OWASP A07: Protección contra fuerza bruta
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.AllowedForNewUsers = true;

    // OWASP A02: Validación de usuario
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddErrorDescriber<SpanishIdentityErrorDescriber>();

// OWASP 1: BCrypt para hashing de contraseñas
builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, BcryptPasswordHasher>();

// ---------------------- Configuración de Cookies Seguras ----------------------
// OWASP 7: Cookies seguras (HttpOnly, Secure, SameSite)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "SafeStore.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(2);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// ---------------------- Políticas de Autorización ----------------------
// OWASP 6: Control de acceso basado en roles
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User", "Admin"));
});

// ---------------------- MVC con Configuración de Seguridad ----------------------
builder.Services.AddControllersWithViews();

// ---------------------- Antiforgery / CSRF ----------------------
// OWASP 4: Configuración robusta de tokens CSRF
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.FormFieldName = "__RequestVerificationToken";
    options.Cookie.Name = "SafeStore.CSRF";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// ---------------------- Rate Limiting Mejorado ----------------------
// OWASP A07: Protección avanzada contra fuerza bruta
builder.Services.AddRateLimiter(options =>
{
    // Límite global
    options.AddFixedWindowLimiter("Global", config =>
    {
        config.PermitLimit = 200;
        config.Window = TimeSpan.FromMinutes(1);
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        config.QueueLimit = 20;
    });

    // Límite específico para login
    options.AddFixedWindowLimiter("Login", config =>
    {
        config.PermitLimit = 5;
        config.Window = TimeSpan.FromMinutes(1);
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        config.QueueLimit = 0;
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapGet("/debug-reset", async (HttpContext context) =>
    {
        var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();
        await signInManager.SignOutAsync();

        // Eliminar todas las cookies de Identity
        context.Response.Cookies.Delete("SafeStore.Auth");
        context.Response.Cookies.Delete(".AspNetCore.Identity.Application");
        context.Response.Cookies.Delete(".AspNetCore.Antiforgery.*");

        return Results.Redirect("/Account/Login");
    });

    app.MapGet("/debug-status", async (HttpContext context) =>
    {
        var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.GetUserAsync(context.User);

        return Results.Json(new
        {
            IsAuthenticated = context.User.Identity.IsAuthenticated,
            UserName = context.User.Identity.Name,
            UserExistsInDb = user != null,
            UserId = user?.Id
        });
    });
}

// ==================== CONFIGURACIÓN DEL PIPELINE ====================

// ---------------------- Middleware de Seguridad ----------------------

// OWASP: Forzar HTTPS en producción
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
app.UseHttpsRedirection();

// OWASP 5: Headers de seguridad personalizados
app.Use(async (context, next) =>
{
    // Headers básicos de seguridad
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()";

    // CSP diferenciada para desarrollo y producción
    if (app.Environment.IsDevelopment())
    {
        // CSP permisiva para desarrollo que permite Browser Link
        context.Response.Headers["Content-Security-Policy"] =
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net http://localhost:* https://localhost:*; " +
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
            "img-src 'self' data: blob: https: http:; " +
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; " +
            "connect-src 'self' ws: wss: http://localhost:* https://localhost:*; " +
            "frame-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self';";
    }
    else
    {
        // CSP estricta para producción
        context.Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self';";
    }

    await next();
});

// Aplicar rate limiting
app.UseRateLimiter();

// Servir archivos estáticos con headers de seguridad
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers["Cache-Control"] = "public, max-age=31536000";
        ctx.Context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    }
});

app.UseRouting();

// OWASP 7: Configuración de cookies
app.UseCookiePolicy(new CookiePolicyOptions
{
    Secure = CookieSecurePolicy.Always,
    HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always,
    MinimumSameSitePolicy = SameSiteMode.Strict
});

app.UseAuthentication();
app.UseAuthorization();

// ---------------------- Seed de Base de Datos ----------------------
// Solo ejecutar en desarrollo
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

            // Crear roles
            var roles = new[] { "Admin", "User" };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));
            }

            // Crear usuario admin desde configuración
            var adminEmail = builder.Configuration["AdminUser:Email"] ?? "admin@safestore.local";
            var adminPassword = builder.Configuration["AdminUser:Password"] ?? "Admin12345!";

            var admin = await userManager.FindByEmailAsync(adminEmail);
            if (admin == null)
            {
                admin = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };

                var createResult = await userManager.CreateAsync(admin, adminPassword);
                if (createResult.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, "Admin");
                    Console.WriteLine($"Usuario admin creado: {adminEmail}");
                }
                else
                {
                    Console.WriteLine($"Error creando admin: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
                }
            }
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "Error durante la inicialización de la base de datos");
        }
    }
}

// ---------------------- Mapeo de Rutas ----------------------
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Health check endpoint para monitoreo
app.MapGet("/health", () => Results.Ok(new { status = "Healthy", timestamp = DateTime.UtcNow }));

app.Run();