<?php
/**
 * AMPass - Application Router / Front Controller
 * Routes requests to appropriate controllers based on URL path.
 */

class App {
    private string $route;
    private string $method;

    public function __construct() {
        $this->route = trim($_GET['route'] ?? '', '/');
        $this->method = $_SERVER['REQUEST_METHOD'];
    }

    /**
     * Run the application - route to appropriate controller
     */
    public function run(): void {
        // Parse route segments
        $segments = $this->route ? explode('/', $this->route) : ['dashboard'];
        $page = $segments[0] ?? 'dashboard';
        $action = $segments[1] ?? 'index';
        $param = $segments[2] ?? null;

        // API routes (return JSON)
        if ($page === 'api') {
            $this->handleAPI($segments);
            return;
        }

        // Public routes (no auth required)
        $publicRoutes = ['login', 'register', 'forgot-password', 'reset-password'];
        
        if (in_array($page, $publicRoutes)) {
            if (Session::isLoggedIn() && $page !== 'reset-password') {
                $this->redirect('dashboard');
                return;
            }
            $this->loadController($page, $action, $param);
            return;
        }

        // All other routes require authentication
        if (!Session::isLoggedIn()) {
            $this->redirect('login');
            return;
        }

        // Vault unlock required for most pages
        $noUnlockRequired = ['unlock', 'logout', 'settings', 'lock'];
        if (!Session::isVaultUnlocked() && !in_array($page, $noUnlockRequired)) {
            $this->redirect('unlock');
            return;
        }

        // Admin routes
        if ($page === 'admin') {
            if (!Session::isAdmin()) {
                http_response_code(403);
                $this->loadView('errors/403');
                return;
            }
            $this->loadController('admin', $action, $param);
            return;
        }

        // Load the requested controller
        $this->loadController($page, $action, $param);
    }

    /**
     * Handle API requests
     */
    private function handleAPI(array $segments): void {
        header('Content-Type: application/json');
        
        $resource = $segments[1] ?? '';
        $action = $segments[2] ?? 'index';
        $param = $segments[3] ?? null;

        // SECURITY: Validate resource and action names (prevent path traversal / injection)
        if (!preg_match('/^[a-zA-Z]+$/', $resource) || !preg_match('/^[a-zA-Z\-]+$/', $action)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request']);
            return;
        }

        // Handle extension API namespace: /api/extension/{action} or /api/extension/vault/{subaction}
        if ($resource === 'extension') {
            $this->handleExtensionAPI($segments);
            return;
        }

        // API requires authentication (except specific endpoints)
        $publicAPI = ['auth'];
        if (!in_array($resource, $publicAPI) && !Session::isLoggedIn()) {
            http_response_code(401);
            echo json_encode(['error' => 'Authentication required']);
            return;
        }

        $controllerFile = __DIR__ . '/../controllers/api/' . ucfirst($resource) . 'ApiController.php';
        
        if (file_exists($controllerFile)) {
            require_once $controllerFile;
            $className = ucfirst($resource) . 'ApiController';
            $controller = new $className();
            
            // SECURITY: Only allow explicitly defined public methods (not magic/internal methods)
            if (method_exists($controller, $action) && !str_starts_with($action, '__') && (new ReflectionMethod($controller, $action))->isPublic()) {
                $controller->$action($param);
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint not found']);
            }
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Resource not found']);
        }
    }

    /**
     * Handle Extension API requests: /api/extension/{action} or /api/extension/vault/{subaction}
     * Maps URL paths to camelCase method names on ExtensionApiController.
     * 
     * Examples:
     *   /api/extension/status         → status()
     *   /api/extension/login          → login()
     *   /api/extension/vault/list     → vaultList()
     *   /api/extension/vault/save     → vaultSave()
     *   /api/extension/vault/match-domain → vaultMatchDomain()
     *   /api/extension/generator/policy   → generatorPolicy()
     */
    private function handleExtensionAPI(array $segments): void {
        // Handle CORS for extension requests
        $this->handleExtensionCORS();

        // Handle OPTIONS preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        $action = $segments[2] ?? 'status';
        $subAction = $segments[3] ?? null;

        // Build method name: vault/list → vaultList, vault/match-domain → vaultMatchDomain
        if ($subAction !== null) {
            // Validate sub-action
            if (!preg_match('/^[a-zA-Z\-]+$/', $subAction)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid request']);
                return;
            }
            $methodName = lcfirst($action) . ucfirst(str_replace('-', '', ucwords($subAction, '-')));
        } else {
            if (!preg_match('/^[a-zA-Z\-]+$/', $action)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid request']);
                return;
            }
            $methodName = lcfirst(str_replace('-', '', ucwords($action, '-')));
        }

        $controllerFile = __DIR__ . '/../controllers/api/ExtensionApiController.php';
        require_once $controllerFile;
        $controller = new ExtensionApiController();

        // SECURITY: Only call public, non-magic methods
        if (method_exists($controller, $methodName) && !str_starts_with($methodName, '__') && (new ReflectionMethod($controller, $methodName))->isPublic()) {
            $controller->$methodName();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found', 'code' => 'NOT_FOUND']);
        }
    }

    /**
     * Handle CORS headers for extension API requests.
     * SECURITY: Only allows configured extension origins, never wildcard in production.
     */
    private function handleExtensionCORS(): void {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        if (empty($origin)) return;

        // Get allowed origins from settings
        $allowedOrigins = [];
        try {
            $setting = Database::fetchOne(
                "SELECT setting_value FROM app_settings WHERE setting_key = 'extension_allowed_origins'"
            );
            if ($setting && !empty($setting['setting_value'])) {
                $allowedOrigins = array_map('trim', explode(',', $setting['setting_value']));
            }
        } catch (Exception $e) {
            // If DB not available, deny CORS
            return;
        }

        // Chrome extension origins look like: chrome-extension://abcdefghijklmnop
        // Always allow chrome-extension:// and moz-extension:// schemes for development
        $isExtensionOrigin = (
            str_starts_with($origin, 'chrome-extension://') ||
            str_starts_with($origin, 'moz-extension://') ||
            str_starts_with($origin, 'safari-web-extension://')
        );

        // Check if origin is in allowed list, or if it's an extension origin and list is empty (dev mode)
        $allowed = false;
        if (!empty($allowedOrigins)) {
            $allowed = in_array($origin, $allowedOrigins, true);
        } elseif ($isExtensionOrigin && Security::isLocalhost()) {
            // Allow any extension origin on localhost for development
            $allowed = true;
        }

        if ($allowed) {
            header("Access-Control-Allow-Origin: {$origin}");
            header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
            header("Access-Control-Allow-Headers: Content-Type, Authorization, X-AMPass-Version");
            header("Access-Control-Max-Age: 86400");
            header("Access-Control-Allow-Credentials: false");
        }
    }

    /**
     * Load a controller
     */
    private function loadController(string $page, string $action = 'index', ?string $param = null): void {
        // SECURITY: Validate page and action names
        if (!preg_match('/^[a-zA-Z\-]+$/', $page) || !preg_match('/^[a-zA-Z\-]+$/', $action)) {
            $this->show404();
            return;
        }

        $controllerName = str_replace('-', '', ucwords($page, '-')) . 'Controller';
        $controllerFile = __DIR__ . '/../controllers/' . $controllerName . '.php';

        if (file_exists($controllerFile)) {
            require_once $controllerFile;
            $controller = new $controllerName();
            
            $methodName = lcfirst(str_replace('-', '', ucwords($action, '-')));
            
            // SECURITY: Only call public methods, never internal/magic methods
            if (method_exists($controller, $methodName) && !str_starts_with($methodName, '__') && (new ReflectionMethod($controller, $methodName))->isPublic()) {
                $controller->$methodName($param);
            } elseif (method_exists($controller, 'index')) {
                $controller->index($param);
            } else {
                $this->show404();
            }
        } else {
            $this->show404();
        }
    }

    /**
     * Load a view file
     */
    public static function loadView(string $view, array $data = []): void {
        extract($data);
        $viewFile = __DIR__ . '/../views/' . $view . '.php';
        
        if (file_exists($viewFile)) {
            require $viewFile;
        } else {
            http_response_code(500);
            echo "View not found: " . htmlspecialchars($view);
        }
    }

    /**
     * Redirect to a route
     */
    private function redirect(string $route): void {
        $baseUrl = rtrim(APP_URL, '/');
        header("Location: {$baseUrl}/{$route}");
        exit;
    }

    /**
     * Show 404 page
     */
    private function show404(): void {
        http_response_code(404);
        self::loadView('errors/404');
    }
}
