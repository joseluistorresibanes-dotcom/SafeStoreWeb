// Controllers/AccountController.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeStoreWeb.Models;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SafeStoreWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        // -------------------- REGISTER --------------------
        [HttpGet]
        public IActionResult Register()
        {
            // Prevenir acceso si ya está autenticado
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Products");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            // Verificar que el modelo no sea null
            if (model == null)
            {
                ModelState.AddModelError("", "Los datos del formulario están vacíos.");
                return View(new RegisterModel());
            }

            // Validación básica del modelo
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                // Verificar si el usuario ya existe
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "Ya existe un usuario con este email.");
                    return View(model);
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Asignar rol User
                    if (!await _roleManager.RoleExistsAsync("User"))
                        await _roleManager.CreateAsync(new IdentityRole("User"));

                    await _userManager.AddToRoleAsync(user, "User");

                    TempData["SuccessMessage"] = "Cuenta creada exitosamente. Ya puedes iniciar sesión.";
                    return RedirectToAction("Login");
                }

                // Manejar errores de Identity en español
                foreach (var error in result.Errors)
                {
                    // Asignar errores a los campos correspondientes
                    if (error.Code.Contains("Password"))
                    {
                        ModelState.AddModelError("Password", error.Description);
                    }
                    else if (error.Code.Contains("Email") || error.Code.Contains("UserName"))
                    {
                        ModelState.AddModelError("Email", error.Description);
                    }
                    else
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el registro del usuario {Email}", model.Email);
                ModelState.AddModelError("", "Ha ocurrido un error inesperado. Por favor, inténtalo de nuevo.");
            }

            return View(model);
        }

        // -------------------- LOGIN --------------------
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            // Prevenir acceso si ya está autenticado
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Products");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(new LoginModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [EnableRateLimiting("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (model == null)
            {
                ModelState.AddModelError("", "El modelo llegó vacío al servidor");
                return View(new LoginModel());
            }

            if (!ModelState.IsValid)
            {
                Console.WriteLine("ModelState errors:");
                foreach (var state in ModelState)
                {
                    foreach (var error in state.Value.Errors)
                    {
                        Console.WriteLine($"{state.Key}: {error.ErrorMessage}");
                    }
                }
                return View(model);
            }

            try
            {
                Console.WriteLine("Intentando autenticar usuario...");

                // Verificar si el usuario existe
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "Credenciales inválidas. Verifica tu email y contraseña.");
                    return View(model);
                }

                // Intentar login
                var result = await _signInManager.PasswordSignInAsync(
                    model.Email,
                    model.Password,
                    model.RememberMe,
                    lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    Console.WriteLine("Login exitoso");

                    // Redirección segura
                    if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    return RedirectToAction("Index", "Products");
                }

                if (result.IsLockedOut)
                {
                    Console.WriteLine("Cuenta bloqueada");
                    ModelState.AddModelError("", "Tu cuenta ha sido bloqueada temporalmente. Intenta nuevamente en 15 minutos.");
                    return View(model);
                }

                Console.WriteLine("Credenciales inválidas");
                ModelState.AddModelError("", "Credenciales inválidas. Verifica tu email y contraseña.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Excepción: {ex.Message}");
                ModelState.AddModelError("", "Ha ocurrido un error durante el login. Por favor, inténtalo de nuevo.");
            }

            return View(model);
        }

        // -------------------- LOGOUT (SOLO GET) --------------------
        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var userName = User?.Identity?.Name ?? "Usuario desconocido";

                if (User.Identity.IsAuthenticated)
                {
                    await _signInManager.SignOutAsync();
                    _logger.LogInformation("Logout exitoso para: {UserName}", userName);

                    // Limpiar la sesión completamente
                    HttpContext.Session.Clear();

                    TempData["SuccessMessage"] = "Has cerrado sesión exitosamente.";
                }
                else
                {
                    _logger.LogWarning("Intento de logout para usuario no autenticado");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el logout");
                // Continuar con la redirección incluso si hay error
            }

            return RedirectToAction("Login", "Account");
        }

        // -------------------- ACCESS DENIED --------------------
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }

    // ViewModels con validaciones mejoradas y mensajes específicos
    public class RegisterModel
    {
        [Required(ErrorMessage = "El email es obligatorio")]
        [EmailAddress(ErrorMessage = "Formato de email inválido")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [StringLength(100, ErrorMessage = "La contraseña debe tener al menos {2} caracteres", MinimumLength = 10)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirma tu contraseña")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        [Display(Name = "Confirmar contraseña")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class LoginModel
    {
        [Required(ErrorMessage = "El email es obligatorio")]
        [EmailAddress(ErrorMessage = "El formato del email no es válido")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Recordar sesión")]
        public bool RememberMe { get; set; }

        public string? ReturnUrl { get; set; }
    }
}