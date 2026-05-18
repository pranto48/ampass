<?php
/**
 * AMPass - Password Generator Controller
 * The actual generation happens client-side for security.
 */

class GeneratorController {

    public function index(): void {
        $csrfToken = CSRF::generateToken();
        $data = ['csrfToken' => $csrfToken];
        require __DIR__ . '/../views/layouts/app.php';
    }
}
