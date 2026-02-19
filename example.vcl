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
    # This path handles the redirect back from Google after the user logs in.
    if (req.url ~ "^/oidc/callback") {
        if (!google.callback_state_valid()) {
            return (synth(403, "Invalid state"));
        }

        set req.http.X-Set-Cookie = google.exchange_code_for_session(
            google.callback_code()
        );

        if (req.http.X-Set-Cookie == "") {
            return (synth(403, "Authentication failed"));
        }

        return (synth(302, "Authenticated"));
    }

    # --- Protected paths ---
    # Everything under /app/ requires a valid session.
    if (req.url ~ "^/app/") {
        if (!google.session_valid()) {
            return (synth(302, "Login required"));
        }

        # Pass user identity to the backend as headers.
        set req.http.X-User-Email = google.claim("email");
        set req.http.X-User-Name  = google.claim("name");
        set req.http.X-User-Sub   = google.claim("sub");
    }

    # Everything else (/, /static/, /health, etc.) is public.
}

sub vcl_synth {
    # Redirect to Google login
    if (resp.status == 302 && resp.reason == "Login required") {
        set resp.http.Location = google.authorization_url();
        return (deliver);
    }

    # Post-login redirect: set the session cookie and send the user
    # back to the page they originally requested.
    if (resp.status == 302 && resp.reason == "Authenticated") {
        set resp.http.Set-Cookie = req.http.X-Set-Cookie;
        set resp.http.Location = google.callback_redirect_target();
        return (deliver);
    }
}

sub vcl_backend_response {
    # Cache public assets normally. Authenticated pages should not be cached
    # (the backend should send appropriate Cache-Control headers, or you can
    # force it here).
    if (bereq.url ~ "^/app/") {
        set beresp.uncacheable = true;
        set beresp.ttl = 0s;
    }
}
