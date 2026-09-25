<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Adds standard browser-protection headers to every response.
 *
 *  - X-Frame-Options / frame-ancestors : the site can't be embedded in another
 *    website's frame (stops "clickjacking" — tricking someone into clicking
 *    hidden buttons).
 *  - X-Content-Type-Options            : browsers must not guess file types.
 *  - Referrer-Policy                   : don't leak full page addresses to other sites.
 *  - Permissions-Policy                : camera only for this site (selfie at sign-up);
 *                                        microphone, location, payment switched off.
 *  - Strict-Transport-Security         : once the site was opened over HTTPS the
 *                                        browser refuses to use plain HTTP again.
 *  - Cache-Control: no-store           : personal data (API replies, ID photos) is not
 *                                        kept in the browser's cache — important on
 *                                        shared / public computers.
 */
class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(), payment=()');
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');
        $response->headers->set(
            'Content-Security-Policy',
            "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'"
        );

        // Railway (and most hosts) end HTTPS at a proxy and forward plain HTTP
        // to the app, so also look at the forwarded-protocol header.
        $isHttps = $request->isSecure() || strtolower((string) $request->header('X-Forwarded-Proto')) === 'https';
        if ($isHttps) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        $path = ltrim($request->path(), '/');
        if (
            str_starts_with($path, 'api/') ||
            str_starts_with($path, 'secure-image/') ||
            str_starts_with($path, 'admin/') ||
            $request->expectsJson()
        ) {
            $response->headers->set('Cache-Control', 'no-store, private');
            $response->headers->set('Pragma', 'no-cache');
        }

        return $response;
    }
}
