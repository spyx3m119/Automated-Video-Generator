import { Request, Response, Router } from 'express';
import { getCspNonce } from '../../middleware/request-context';
import { createMemoryRateLimiter } from '../../middleware/rate-limit';
import { loginPage } from '../../views/login.view';
import {
    clearSessionCookie,
    isAuthEnabled,
    isAuthenticated,
    safeNextPath,
    sessionTtlMs,
    setSessionCookie,
    verifyPassword,
} from '../../middleware/auth';

const router = Router();

// The password is the only factor, so cap attempts per IP to blunt brute force.
const loginLimiter = createMemoryRateLimiter({ keyPrefix: 'login', max: 10, windowMs: 15 * 60 * 1000 });

function sendLoginPage(
    req: Request,
    res: Response,
    options: { status?: number; error?: string; next?: string } = {},
): void {
    res.status(options.status ?? 200)
        .set('Cache-Control', 'no-store')
        .type('html')
        .send(
            loginPage({
                cspNonce: getCspNonce(res),
                next: safeNextPath(options.next ?? req.query.next),
                error: options.error,
            }),
        );
}

router.get('/login', (req, res) => {
    if (!isAuthEnabled() || isAuthenticated(req)) {
        res.redirect(302, safeNextPath(req.query.next));
        return;
    }

    sendLoginPage(req, res);
});

router.post('/login', loginLimiter, (req, res) => {
    const next = safeNextPath(req.body?.next);

    if (!isAuthEnabled()) {
        res.redirect(303, next);
        return;
    }

    if (!verifyPassword(req.body?.password)) {
        sendLoginPage(req, res, { status: 401, error: 'Incorrect password. Try again.', next });
        return;
    }

    setSessionCookie(req, res, sessionTtlMs());
    res.redirect(303, next);
});

router.post('/logout', (_req, res) => {
    clearSessionCookie(res);
    res.redirect(303, '/login');
});

export default router;
