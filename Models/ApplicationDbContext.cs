// Models/ApplicationDbContext.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SafeStoreWeb.Models
{
    // Usuario de la aplicación (extiende IdentityUser para añadir propiedades si hace falta)
    public class ApplicationUser : IdentityUser
    {
        // Ejemplo: public string DisplayName { get; set; }
    }

    // Entidad Product con validaciones (Model validation server-side)
    public class Product
    {
        public int Id { get; set; }

        // DataAnnotations -> validación y ayuda en las vistas (protección OWASP: input validation)
        [Required]
        [StringLength(200, ErrorMessage = "El nombre no puede superar 200 caracteres.")]
        public string Name { get; set; } = string.Empty;

        [Required]
        [StringLength(2000, ErrorMessage = "La descripción no puede superar 2000 caracteres.")]
        public string Description { get; set; } = string.Empty;

        [Range(0.0, 1000000.0, ErrorMessage = "Precio inválido.")]
        public decimal Price { get; set; }

        // Si permites subir imágenes, almacenar la ruta/URL (validar al subir)
        public string? ImageUrl { get; set; }
    }

    // Contexto EF Core - controla acceso a la DB
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        // DbSet para productos: EF Core usa consultas parametrizadas por defecto -> previene SQLi.
        public DbSet<Product> Products { get; set; }
    }
}
