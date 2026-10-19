import { layout, escapeHtml } from './layout.view';
import { PROJECT_NAME } from '../constants/config';

export interface LoginPageOptions {
    cspNonce?: string;
    next?: string;
    error?: string;
}

/**
 * Standalone sign-in page for the shared-secret gate (see middleware/auth.ts).
 *
 * Deliberately a plain HTML form POST — no client script — so it works even if
 * a browser blocks scripts, and so it cannot be broken by the inline-script
 * class of bug that has bitten the main portal.
 */
export function loginPage(options: LoginPageOptions = {}): string {
    const { cspNonce, next = '/', error } = options;

    const errorBanner = error
        ? `<div class="status" style="border-color:var(--error);color:var(--error)">${escapeHtml(error)}</div>`
        : '';

    const body = `
    <section class="layout-split">
        <div class="panel glass stack">
            <div>
                <span class="eyebrow">Restricted</span>
                <h1>${escapeHtml(PROJECT_NAME)}</h1>
                <p class="lead">This instance is protected by a shared secret. Enter the access password to continue.</p>
            </div>
            ${errorBanner}
            <p class="field-help">Changing <code>APP_ACCESS_PASSWORD</code> signs every device out.</p>
        </div>

        <div class="panel">
            <form class="form" method="post" action="/login">
                <input type="hidden" name="next" value="${escapeHtml(next)}">
                <div class="field">
                    <label for="password">Access password</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
                    <p class="field-help">Configured through the <code>APP_ACCESS_PASSWORD</code> environment variable.</p>
                </div>
                <div class="toolbar">
                    <button type="submit">Unlock</button>
                </div>
            </form>
        </div>
    </section>`;

    return layout(`Sign in | ${PROJECT_NAME}`, body, {
        cspNonce,
        description: 'Restricted access.',
        robots: 'noindex, nofollow',
    });
}
