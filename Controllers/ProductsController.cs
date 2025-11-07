// Controllers/ProductsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeStoreWeb.Models;

namespace SafeStoreWeb.Controllers
{
    [Authorize] // ← AGREGAR ESTE ATRIBUTO A NIVEL DE CLASE
    public class ProductsController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly IWebHostEnvironment _env;

        public ProductsController(ApplicationDbContext db, IWebHostEnvironment env)
        {
            _db = db;
            _env = env;
        }

        // GET: /Products -> listado (solo usuarios autenticados)
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var items = await _db.Products.AsNoTracking().ToListAsync();
            return View(items);
        }

        // GET: /Products/Details/5 -> detalle (solo usuarios autenticados)
        [HttpGet]
        public async Task<IActionResult> Details(int id)
        {
            var p = await _db.Products.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
            if (p == null) return NotFound();
            return View(p);
        }

        // GET: /Products/Create -> formulario (solo usuarios autenticados)
        [HttpGet]
        public IActionResult Create() => View();

        // POST: /Products/Create -> crear producto (solo usuarios autenticados)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([FromForm] Product model)
        {
            if (!ModelState.IsValid) return View(model);

            model.Name = model.Name?.Trim() ?? string.Empty;
            model.Description = model.Description?.Trim() ?? string.Empty;

            if (model.Description.Contains("<script", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError("Description", "Descripción contiene contenido peligroso.");
                return View(model);
            }

            _db.Products.Add(model);
            await _db.SaveChangesAsync();

            TempData["SuccessMessage"] = $"Producto '{model.Name}' creado exitosamente.";
            return RedirectToAction(nameof(Index));
        }
    }
}