document.addEventListener('DOMContentLoaded', (event) => {
    // --- HTMX Security Configuration ---
    // Ensure HTMX includes the CSRF token in its requests.
    document.body.addEventListener('htmx:configRequest', function(evt) {
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            evt.detail.headers['X-CSRF-Token'] = csrfToken.getAttribute('content');
        }
    });

    // Harden HTMX against script injection.
    if (window.htmx) {
        window.htmx.config.selfRequestsOnly = true;
        window.htmx.config.allowScriptTags = false;
        window.htmx.config.allowEval = false;
    }
});