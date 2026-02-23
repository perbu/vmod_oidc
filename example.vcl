# example.vcl
#
# Example: Protecting a site with Google OIDC using vmod-oidc.
#
# Prerequisites:
#   1. Create OAuth 2.0 credentials at https://console.cloud.google.com/apis/credentials
#   2. Set "Authorized redirect URIs" to https://www.example.com/oidc/callback
#   3. Generate a 32-byte cookie secret:
#        openssl rand -hex 32
#   4. Set environment variables before starting Varnish:
#        export OIDC_CLIENT_ID="123456789.apps.googleusercontent.com"
#        export OIDC_CLIENT_SECRET="GOCSPX-your-client-secret-here"
#        export OIDC_JWT_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

import oidc;
import std;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_init {
    new google = oidc.provider(
        discovery_url = "https://accounts.google.com/.well-known/openid-configuration",
        client_id     = std.getenv("OIDC_CLIENT_ID"),
        client_secret = std.getenv("OIDC_CLIENT_SECRET"),
        redirect_uri  = "https://www.example.com/oidc/callback",
        cookie_secret = std.getenv("OIDC_JWT_SECRET"),
        cookie_name   = "__oidc_session",
        cookie_ttl    = 3600s,
        scopes        = "openid email profile"
    );
}

sub vcl_recv {
    # --- OIDC callback ---
    # The built-in backend handles state validation, code exchange,
    # and redirects the user back with a session cookie.
    if (req.url ~ "^/oidc/callback") {
        set req.backend_hint = google.backend();
        return (pass);
    }

    # --- Protected paths ---
    # Everything under /app/ requires a valid session.
    # Unauthenticated users are redirected to Google by the built-in backend.
    if (req.url ~ "^/app/") {
        if (!google.session_valid()) {
            set req.backend_hint = google.backend();
            return (pass);
        }

        # Pass user identity to the backend as headers.
        set req.http.X-User-Email = google.claim("email");
        set req.http.X-User-Name  = google.claim("name");
        set req.http.X-User-Sub   = google.claim("sub");
    }

    # Everything else (/, /static/, /health, etc.) is public.
}
