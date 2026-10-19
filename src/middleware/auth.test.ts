/**
 * auth.test.ts — shared-secret gate: password verification, session signing, and
 * the request-level choice between an HTML sign-in page and a JSON 401.
 *
 * The gate is the only thing standing between a public URL and unauthenticated
 * access, so these cases are regression guards, not nice-to-haves.
 */
import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import type { NextFunction, Request, Response } from 'express';
import {
    clearSessionCookie,
    isAuthEnabled,
    isAuthenticated,
    requireAuth,
    safeNextPath,
    sessionTtlMs,
    setSessionCookie,
    verifyPassword,
} from './auth.js';

const PASSWORD = 'test-secret-123';
const originalPassword = process.env.APP_ACCESS_PASSWORD;
const originalTtl = process.env.APP_SESSION_TTL_HOURS;

function restoreEnv(): void {
    if (originalPassword === undefined) {
        delete process.env.APP_ACCESS_PASSWORD;
    } else {
        process.env.APP_ACCESS_PASSWORD = originalPassword;
    }

    if (originalTtl === undefined) {
        delete process.env.APP_SESSION_TTL_HOURS;
    } else {
        process.env.APP_SESSION_TTL_HOURS = originalTtl;
    }
}

function makeReq(overrides: Partial<Request> = {}): Request {
    return {
        method: 'GET',
        path: '/',
        originalUrl: '/',
        headers: {},
        secure: false,
        ...overrides,
    } as unknown as Request;
}

interface MockResponse extends Response {
    _headers: Record<string, string>;
    _cookies: string[];
    _body: string;
    _status?: number;
}

function makeRes(): MockResponse {
    const res: any = {
        _headers: {},
        _cookies: [],
        _body: '',
        _status: undefined,
        locals: {},
        status(code: number) {
            res._status = code;
            return res;
        },
        set(key: string, value: string) {
            res._headers[key] = value;
            return res;
        },
        type() {
            return res;
        },
        send(body: string) {
            res._body = body;
            return res;
        },
        append(key: string, value: string) {
            if (key.toLowerCase() === 'set-cookie') {
                res._cookies.push(value);
            }
            return res;
        },
        redirect(code: number) {
            res._status = code;
            return res;
        },
    };
    return res;
}

/** Reduce a Set-Cookie header to its `name=value` pair. */
function cookiePair(setCookie: string): string {
    return setCookie.split(';')[0];
}

afterEach(restoreEnv);

describe('shared-secret gate', () => {
    test('is a no-op when APP_ACCESS_PASSWORD is unset', () => {
        delete process.env.APP_ACCESS_PASSWORD;
        assert.equal(isAuthEnabled(), false);

        let passed = false;
        requireAuth(makeReq(), makeRes(), (() => {
            passed = true;
        }) as NextFunction);

        assert.equal(passed, true, 'unset password must preserve loopback-only behaviour');
    });

    test('verifyPassword accepts only the exact secret', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;

        assert.equal(verifyPassword(PASSWORD), true);
        assert.equal(verifyPassword('wrong'), false);
        assert.equal(verifyPassword(''), false);
        assert.equal(verifyPassword(undefined), false);
        assert.equal(verifyPassword(`${PASSWORD} `), false, 'candidate must not be trimmed');
    });

    test('session cookie round-trips with HttpOnly and SameSite flags', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const res = makeRes();
        setSessionCookie(makeReq(), res, sessionTtlMs());

        assert.equal(res._cookies.length, 1);
        const cookie = res._cookies[0];
        assert.match(cookie, /HttpOnly/);
        assert.match(cookie, /SameSite=Lax/);
        assert.match(cookie, /Path=\//);
        assert.match(cookie, /Max-Age=\d+/);

        assert.equal(isAuthenticated(makeReq({ headers: { cookie: cookiePair(cookie) } })), true);
    });

    test('a tampered signature is rejected', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const res = makeRes();
        setSessionCookie(makeReq(), res, sessionTtlMs());

        const pair = cookiePair(res._cookies[0]);
        const value = pair.slice(pair.indexOf('=') + 1);
        const tampered = value.slice(0, -1) + (value.endsWith('A') ? 'B' : 'A');

        assert.equal(
            isAuthenticated(makeReq({ headers: { cookie: `avg_session=${tampered}` } })),
            false,
        );
    });

    test('an unsigned future expiry is rejected', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const future = Date.now() + 10_000_000;

        assert.equal(
            isAuthenticated(makeReq({ headers: { cookie: `avg_session=${future}.deadbeef` } })),
            false,
        );
    });

    test('an expired session is rejected', async () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        process.env.APP_SESSION_TTL_HOURS = '0.0005'; // ~1.8s

        const res = makeRes();
        setSessionCookie(makeReq(), res, sessionTtlMs());
        const cookie = cookiePair(res._cookies[0]);

        assert.equal(isAuthenticated(makeReq({ headers: { cookie } })), true);
        await new Promise((resolve) => setTimeout(resolve, 2200));
        assert.equal(isAuthenticated(makeReq({ headers: { cookie } })), false);
    });

    test('rotating the password invalidates outstanding sessions', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const res = makeRes();
        setSessionCookie(makeReq(), res, sessionTtlMs());
        const cookie = cookiePair(res._cookies[0]);

        assert.equal(isAuthenticated(makeReq({ headers: { cookie } })), true);
        process.env.APP_ACCESS_PASSWORD = 'a-different-secret';
        assert.equal(isAuthenticated(makeReq({ headers: { cookie } })), false);
    });

    test('clearSessionCookie expires the cookie', () => {
        const res = makeRes();
        clearSessionCookie(res);
        assert.match(res._cookies[0], /Max-Age=0/);
    });

    test('browser navigations get the sign-in page (200, never a redirect)', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const res = makeRes();
        let nextCalled = false;

        requireAuth(
            makeReq({ method: 'GET', headers: { accept: 'text/html,application/xhtml+xml' } }),
            res,
            (() => {
                nextCalled = true;
            }) as NextFunction,
        );

        assert.equal(nextCalled, false);
        assert.equal(res._status, 200, 'a 3xx here would fail orchestrator health checks');
        assert.match(res._body, /name="password"/);
        assert.equal(res._headers['Cache-Control'], 'no-store');
    });

    test('non-navigation calls get a JSON 401', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        const res = makeRes();
        let error: any;

        requireAuth(
            makeReq({ path: '/api/fs/assets', headers: { accept: '*/*' } }),
            res,
            ((err?: unknown) => {
                error = err;
            }) as NextFunction,
        );

        assert.ok(error, 'expected an UnauthorizedError');
        assert.equal(error.statusCode, 401);
        assert.equal(error.code, 'unauthenticated');
    });

    test('public paths bypass the gate so health checks keep working', () => {
        process.env.APP_ACCESS_PASSWORD = PASSWORD;
        let passed = false;

        requireAuth(makeReq({ path: '/api/health' }), makeRes(), (() => {
            passed = true;
        }) as NextFunction);

        assert.equal(passed, true);
    });

    test('safeNextPath blocks open redirects', () => {
        assert.equal(safeNextPath('/jobs/123'), '/jobs/123');
        assert.equal(safeNextPath('https://evil.example'), '/');
        assert.equal(safeNextPath('//evil.example'), '/');
        assert.equal(safeNextPath('/\\evil'), '/');
        assert.equal(safeNextPath(undefined), '/');
        assert.equal(safeNextPath(['/a']), '/');
    });
});
