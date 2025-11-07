// Controllers/ProductsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeStoreWeb.Models;

namespace SafeStoreWeb.Controllers
{
    public class ProductsController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly IWebHostEnvironment _env;

        public ProductsController(ApplicationDbContext db, IWebHostEnvironment env)
        {
            _db = db;
            _env = env;
        }

        // GET: /Products -> listado público (AsNoTracking para rendimiento)
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var items = await _db.Products.AsNoTracking().ToListAsync();
            return View(items);
        }

        // GET: /Products/Details/5 -> detalle público
        [HttpGet]
        public async Task<IActionResult> Details(int id)
        {
            var p = await _db.Products.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
            if (p == null) return NotFound();
            return View(p);
        }

        // GET: /Products/Create -> formulario (solo usuarios autenticados)
        // OWASP: control de acceso (A01). Restringimos creación a usuarios autenticados.
        [Authorize]
        [HttpGet]
        public IActionResult Create() => View();

        // POST: /Products/Create -> crear producto
        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken] // Protección CSRF
        public async Task<IActionResult> Create([FromForm] Product model)
        {
            // Server-side validation -> nunca confiar en client-side solamente
            if (!ModelState.IsValid) return View(model);

            // Sanitización simple: recortar espacios
            model.Name = model.Name?.Trim() ?? string.Empty;
            model.Description = model.Description?.Trim() ?? string.Empty;

            // Validación adicional (ejemplo): evitar scripts en descripción si no sanitizas HTML
            if (model.Description.Contains("<script", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError("Description", "Descripción contiene contenido peligroso.");
                return View(model);
            }

            _db.Products.Add(model); // EF Core -> consultas parametrizadas (protección SQLi)
            await _db.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        // Nota: para Edit/Delete se recomienda [Authorize(Roles = "Admin")] y validaciones adicionales.
    }
}
