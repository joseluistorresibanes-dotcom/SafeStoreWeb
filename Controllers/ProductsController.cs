using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeStoreWeb.Models;

[Authorize] // Requiere autenticación para todo el controlador
public class ProductsController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ProductsController> _logger;

    public ProductsController(ApplicationDbContext db, ILogger<ProductsController> logger)
    {
        _db = db;
        _logger = logger;
    }

    // GET: /Products -> Acceso para todos los usuarios autenticados
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        _logger.LogInformation("Usuario {User} accedió al listado de productos", User.Identity.Name);
        var items = await _db.Products.AsNoTracking().ToListAsync();
        return View(items);
    }

    // GET: /Products/Details/5 -> Acceso para todos los usuarios autenticados
    [HttpGet]
    public async Task<IActionResult> Details(int id)
    {
        var product = await _db.Products.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
        if (product == null)
        {
            _logger.LogWarning("Usuario {User} intentó acceder a producto inexistente: {ProductId}",
                User.Identity.Name, id);
            return NotFound();
        }
        return View(product);
    }

    // GET: /Products/Create -> Solo Admin y Manager
    [Authorize(Policy = "CreateProducts")]
    [HttpGet]
    public IActionResult Create()
    {
        _logger.LogInformation("Usuario {User} accedió a crear producto", User.Identity.Name);
        return View();
    }

    // POST: /Products/Create -> Solo Admin y Manager
    [Authorize(Policy = "CreateProducts")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([FromForm] Product model)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Usuario {User} envió formulario inválido para crear producto",
                User.Identity.Name);
            return View(model);
        }

        try
        {
            // Sanitización
            model.Name = model.Name?.Trim() ?? string.Empty;
            model.Description = model.Description?.Trim() ?? string.Empty;

            // Validación de seguridad
            if (model.Description.Contains("<script", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError("Description", "La descripción contiene contenido peligroso.");
                return View(model);
            }

            _db.Products.Add(model);
            await _db.SaveChangesAsync();

            _logger.LogInformation("Usuario {User} creó producto: {ProductName}",
                User.Identity.Name, model.Name);

            TempData["SuccessMessage"] = $"Producto '{model.Name}' creado exitosamente.";
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al crear producto por usuario {User}", User.Identity.Name);
            ModelState.AddModelError("", "Error al crear el producto. Inténtalo de nuevo.");
            return View(model);
        }
    }

    // Futuras acciones para editar y eliminar (solo Admin)
    [Authorize(Policy = "ModifyProducts")]
    [HttpGet]
    public async Task<IActionResult> Edit(int id)
    {
        // Implementación futura - solo Admin
        return View("ComingSoon");
    }

    [Authorize(Policy = "ModifyProducts")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        // Implementación futura - solo Admin
        return View("ComingSoon");
    }
}