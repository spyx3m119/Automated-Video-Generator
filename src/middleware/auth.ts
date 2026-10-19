/**
 * auth.ts — optional shared-secret gate for publicly exposed deployments.
 *
 * The portal is built loopback-only: `local-only.ts` trusts 127.0.0.1 and treats
 * everything else as hostile. That model collapses the moment the app is
 * reachable on a public URL, where anyone who knows the hostname can start
 * renders and spend the operator's Pexels / ElevenLabs quota.
 *
 * This middleware puts a single shared secret in front of the whole app.
 *
 * Enabling: set APP_ACCESS_PASSWORD. When it is unset the gate is a no-op and
 * the original loopback-only behaviour is preserved, so local desktop use is
 * completely unchanged.
 *
 * Sessions are stateless: a signed, expiring cookie. The signing key is derived
 * from the password with scrypt, so sessions survive restarts and rotating the
 * password invalidates every outstanding session.
 */
import { createHmac, scryptSync, timingSafeEqual } from 'crypto';
import { Request, RequestHandler, Response } from 'express';
import { UnauthorizedError } from '../lib/errors';
import { logInfo, logWarn } from '../runtime';
import { loginPage } from '../views/login.view';
import { getCspNonce } from './request-context';

const COOKIE_NAME = 'avg_session';
const KEY_CONTEXT = 'avg-session-v1';
const DEFAULT_TTL_HOURS = 24 * 7;

/** Reachable without a session: the login flow plus the assets the login page needs. */
const PUBLIC_PATHS = new Set([
    '/login',
    '/logout',
    '/api/health',
    '/favicon.ico',
    '/logo.png',
    '/manifest.json',
    '/robots.txt',
]);

function accessPassword(): string {
    return (process.env.APP_ACCESS_PASSWORD || '').trim();
}

export function isAuthEnabled(): boolean {
    return accessPassword().length > 0;
}

// scrypt is deliberately slow, so derive the signing key once per password value.
let cachedKey: { password: string; key: Buffer } | null = null;
function sessionKey(): Buffer {
    const password = accessPassword();
    if (cachedKey && cachedKey.password === password) {
        return cachedKey.key;
    }
    const key = scryptSync(password, KEY_CONTEXT, 32);
    cachedKey = { password, key };
    return key;
}

function digest(value: string): Buffer {
    return createHmac('sha256', sessionKey()).update(value).digest();
}

/**
 * Constant-time password comparison. Both sides are hashed first so the buffers
 * are always the same length and `timingSafeEqual` cannot throw or leak length.
 */
export function verifyPassword(candidate: unknown): boolean {
    const expected = accessPassword();
    if (!expected) {
        return false;
    }
    return timingSafeEqual(digest(typeof candidate === 'string' ? candidate : ''), digest(expected));
}

export function sessionTtlMs(): number {
    const hours = Number.parseFloat(process.env.APP_SESSION_TTL_HOURS || '');
    const effective = Number.isFinite(hours) && hours > 0 ? hours : DEFAULT_TTL_HOURS;
    return Math.floor(effective * 60 * 60 * 1000);
}

function signSession(expiresAt: number): string {
    return `${expiresAt}.${createHmac('sha256', sessionKey()).update(`${KEY_CONTEXT}:${expiresAt}`).digest('base64url')}`;
}

function verifySessionToken(token: string | undefined): boolean {
    if (!token) {
        return false;
    }

    const separator = token.indexOf('.');
    if (separator <= 0) {
        return false;
    }

    const expiresAt = Number(token.slice(0, separator));
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
        return false;
    }

    const provided = Buffer.from(token.slice(separator + 1));
    const expected = Buffer.from(
        createHmac('sha256', sessionKey()).update(`${KEY_CONTEXT}:${expiresAt}`).digest('base64url'),
    );

    return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function readCookie(req: Request, name: string): string | undefined {
    const header = req.headers.cookie;
    if (!header) {
        return undefined;
    }

    for (const part of header.split(';')) {
        const separator = part.indexOf('=');
        if (separator === -1) {
            continue;
        }
        if (part.slice(0, separator).trim() !== name) {
            continue;
        }
        try {
            return decodeURIComponent(part.slice(separator + 1).trim());
        } catch {
            return undefined;
        }
    }

    return undefined;
}

/** True when the request carries a valid, unexpired session cookie. */
export function isAuthenticated(req: Request): boolean {
    if (!isAuthEnabled()) {
        return false;
    }
    return verifySessionToken(readCookie(req, COOKIE_NAME));
}

function isSecureRequest(req: Request): boolean {
    if (req.secure) {
        return true;
    }
    if (String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') {
        return true;
    }
    return (process.env.PUBLIC_BASE_URL || '').trim().startsWith('https://');
}

export function setSessionCookie(req: Request, res: Response, ttlMs: number): void {
    const attributes = [
        `${COOKIE_NAME}=${encodeURIComponent(signSession(Date.now() + ttlMs))}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${Math.floor(ttlMs / 1000)}`,
    ];

    if (isSecureRequest(req)) {
        attributes.push('Secure');
    }

    res.append('Set-Cookie', attributes.join('; '));
}

export function clearSessionCookie(res: Response): void {
    res.append('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

/** Only same-site absolute paths are honoured, so `?next=` cannot become an open redirect. */
export function safeNextPath(value: unknown): string {
    const raw = typeof value === 'string' ? value.trim() : '';
    if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) {
        return '/';
    }
    return raw;
}

export const requireAuth: RequestHandler = (req, res, next) => {
    if (!isAuthEnabled() || PUBLIC_PATHS.has(req.path) || isAuthenticated(req)) {
        next();
        return;
    }

    // Browser navigations get the sign-in page rendered in place — HTTP 200, not
    // a redirect — so an orchestrator health-checking any path never sees a 3xx.
    // fetch/API calls get JSON so the existing client-side error handling works.
    const accept = String(req.headers.accept || '');
    if (req.method === 'GET' && accept.includes('text/html')) {
        res.status(200)
            .set('Cache-Control', 'no-store')
            .type('html')
            .send(
                loginPage({
                    cspNonce: getCspNonce(res),
                    next: safeNextPath(req.originalUrl),
                }),
            );
        return;
    }

    next(new UnauthorizedError('Authentication required.'));
};

export function logAuthMode(): void {
    if (isAuthEnabled()) {
        logInfo(
            `[AUTH] Shared-secret gate ENABLED (APP_ACCESS_PASSWORD set, session TTL ${sessionTtlMs() / 3_600_000}h).`,
        );
        return;
    }

    logWarn(
        '[AUTH] APP_ACCESS_PASSWORD is not set — this instance is unauthenticated. Only expose it on a trusted network.',
    );
}
