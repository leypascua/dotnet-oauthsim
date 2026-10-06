// Run: node tests/browser-login.cjs <path-to-playwright-module>
// Requires Playwright and its Chromium browser; no frontend build is needed.
// Set OAUTHSIM_TEST_PROXY=1 to run the same flows through a prefix-stripping proxy.
const { chromium } = require(process.argv[2] || 'playwright');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');

(async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'oauthsim-login-'));
    const callback = http.createServer((request, response) => response.end('callback'));
    await new Promise(resolve => callback.listen(0, '127.0.0.1', resolve));
    const callbackUrl = `http://localhost:${callback.address().port}/callback`;
    let proxy;
    const hostingArgs = [];
    if (process.env.OAUTHSIM_TEST_PROXY === '1') {
        const reserve = http.createServer();
        await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
        const backendPort = reserve.address().port;
        await new Promise(resolve => reserve.close(resolve));
        proxy = http.createServer((request, response) => {
            if (request.url !== '/oauthsim' && !request.url.startsWith('/oauthsim/')) {
                response.writeHead(404).end('Missing application prefix');
                return;
            }
            const upstream = http.request({
                hostname: '127.0.0.1', port: backendPort, path: request.url.slice('/oauthsim'.length) || '/', method: request.method,
                headers: { ...request.headers, host: `127.0.0.1:${backendPort}`, 'x-forwarded-host': request.headers.host,
                    'x-forwarded-proto': 'http', 'x-forwarded-for': request.socket.remoteAddress }
            }, result => {
                response.writeHead(result.statusCode, result.headers);
                result.pipe(response);
            });
            upstream.on('error', error => { response.writeHead(502).end(error.message); });
            request.pipe(upstream);
        });
        await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
        hostingArgs.push('--port', String(backendPort), '--public-base-url', `http://localhost:${proxy.address().port}/oauthsim`);
    }
    const executable = process.argv[3] || path.resolve('src/OAuthSim.Web/bin/Release/net10.0/OAuthSim.Web.dll');
    const server = spawn(process.argv[3] ? executable : 'dotnet', [
        ...(process.argv[3] ? [] : [executable]), '--settings-dir', directory, '--clientId', 'email-client', '--clientSecret', 'secret', '--no-browser', ...hostingArgs
    ]);
    let output = '';
    server.stdout.on('data', data => output += data);
    server.stderr.on('data', data => output += data);
    let browser;
    try {
        let origin;
        for (let i = 0; i < 150; i++) {
            origin = output.match(/Admin:\s+(http:\/\/localhost:\d+(?:\/oauthsim)?)/)?.[1];
            if (origin) break;
            if (server.exitCode !== null) throw new Error(output);
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert.ok(origin, output);
        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ locale: 'en-US', viewport: { width: 390, height: 844 } });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const url = origin + '/authorize?' + new URLSearchParams({
            response_type: 'code', client_id: 'email-client', redirect_uri: callbackUrl,
            scope: 'openid profile email', state: 'email-test'
        });
        await page.goto(url);
        await page.waitForFunction(() => window.Alpine && document.querySelector('select[name=language]').value === 'en');
        await page.getByRole('textbox', { name: 'Email', exact: true }).fill('new.person@example.com');
        assert.equal(await page.evaluate(() => new FormData(document.querySelector('form')).get('language')), 'en', 'English selection must be included in the form');
        await page.getByRole('button', { name: 'Continue', exact: true }).click();
        await page.waitForURL(callbackUrl + '**');
        assert.ok(new URL(page.url()).searchParams.get('code'), 'No configured users should accept a valid email');
        assert.equal(new URL(page.url()).searchParams.get('state'), 'email-test');
        console.log('PASS English default submits language and accepts an ad-hoc email');
        const sessionCookie = (await context.cookies()).find(c => c.name.startsWith('OAuthSim.Login.'));
        assert.ok(sessionCookie.httpOnly && sessionCookie.sameSite === 'Lax');
        assert.equal(sessionCookie.path, proxy ? '/oauthsim' : '/');
        await page.goto(url);
        await page.getByRole('heading', { name: 'Welcome back, new.person!' }).waitFor();
        assert.equal(await page.locator('#countdown').textContent(), '5');
        await page.waitForFunction(() => document.getElementById('countdown').textContent === '4');
        await page.waitForURL(callbackUrl + '**');
        assert.ok(new URL(page.url()).searchParams.get('code'));
        assert.equal(new URL(page.url()).searchParams.get('state'), 'email-test');
        console.log('PASS welcome-back countdown completes authorization');
        await page.goto(url);
        await page.getByRole('button', { name: 'Log out', exact: true }).click();
        await page.waitForFunction(() => window.Alpine && document.querySelector('select[name=language]').value === 'en');
        await page.waitForTimeout(5100);
        assert.ok(page.url().endsWith('/oauth/v2/logout'), 'Logout must cancel the countdown');
        assert.equal(await page.getByRole('textbox', { name: 'Email', exact: true }).inputValue(), 'new.person@example.com');
        assert.equal(await page.evaluate(() => new FormData(document.querySelector('form')).get('language')), 'en');
        // The persisted language must remain valid after changing country and returning to English.
        await page.locator('select[name=country]').selectOption('JP');
        await page.locator('select[name=language]').selectOption('ja');
        await page.locator('select[name=language]').selectOption('en');
        assert.equal(await page.evaluate(() => new FormData(document.querySelector('form')).get('language')), 'en');
        await page.getByRole('button', { name: 'Continue', exact: true }).click();
        await page.waitForURL(callbackUrl + '**');
        console.log('PASS remembered English and manually selected English submit correctly');
        await page.goto(url);
        await page.getByRole('link', { name: `localhost:${callback.address().port}` }).click();
        await page.waitForURL(callbackUrl + '**');
        assert.ok(new URL(page.url()).searchParams.get('code'), 'Destination link must complete authorization');
        await page.goto(url + '&prompt=login');
        await page.getByRole('textbox', { name: 'Email', exact: true }).waitFor();
        await page.goto(url + '&max_age=0');
        await page.getByRole('textbox', { name: 'Email', exact: true }).waitFor();
        await page.goto(url + '&prompt=none');
        await page.waitForURL(callbackUrl + '**');
        assert.ok(new URL(page.url()).searchParams.get('code'));
        await page.goto(url + '&response_mode=form_post');
        await page.getByRole('button', { name: 'Continue now', exact: true }).click();
        await page.waitForURL(callbackUrl);
        console.log('PASS destination link, prompt, max_age and form_post session reuse');
        const admin = await context.newPage();
        await admin.goto(origin);
        await admin.waitForFunction(() => window.htmx && window.Alpine);
        await admin.getByRole('button', { name: 'Invalidate all sessions and tokens', exact: true }).click();
        await admin.getByRole('status').filter({ hasText: 'All login sessions and tokens invalidated' }).waitFor();
        await page.goto(url + '&prompt=none');
        await page.waitForURL(callbackUrl + '**');
        assert.equal(new URL(page.url()).searchParams.get('error'), 'login_required');
        await page.goto(url);
        await page.getByRole('textbox', { name: 'Email', exact: true }).waitFor();
        await page.getByRole('button', { name: 'Continue', exact: true }).click();
        await page.waitForURL(callbackUrl + '**');
        await page.goto(url);
        await page.getByRole('heading', { name: 'Welcome back, new.person!' }).waitFor();
        console.log('PASS HTMX global reset invalidates cookie and allows fresh login');

        // Redesigned admin: tab bar persists across HTMX swaps, forms work inside tabs, no page errors.
        admin.on('pageerror', error => errors.push('admin: ' + error.message));
        await admin.setViewportSize({ width: 1280, height: 900 });
        await admin.reload();
        await admin.waitForFunction(() => window.htmx && window.Alpine);
        const card = admin.locator('.client-card').first();
        await card.getByRole('tab', { name: /^Users/ }).click();
        await card.getByRole('tabpanel').filter({ hasText: 'Add user' }).waitFor();
        await card.locator('summary', { hasText: 'Add user' }).click();
        await card.locator('details[open] input[name=email]').fill('tab.person@example.com');
        await card.locator('details[open] input[name=name]').fill('Tab Person');
        await card.locator('details[open]').getByRole('button', { name: 'Save user', exact: true }).click();
        await admin.getByRole('status').filter({ hasText: 'User saved.' }).waitFor();
        const activeTab = admin.locator('.client-card').first().getByRole('tab', { selected: true });
        assert.match(await activeTab.textContent(), /^Users/, 'Active tab must survive the HTMX swap');
        await admin.locator('.client-card').first().locator('.row-title', { hasText: 'Tab Person' }).waitFor();
        const shots = process.env.OAUTHSIM_SHOTS;
        if (shots) {
            fs.mkdirSync(shots, { recursive: true });
            await admin.locator('.client-card').first().locator('.row-title', { hasText: 'Tab Person' }).click();
            await admin.screenshot({ path: path.join(shots, 'admin-users.png'), fullPage: true });
            await admin.locator('.client-card').first().locator('.row-title', { hasText: 'Tab Person' }).click();
            await card.getByRole('tab', { name: 'Integration' }).click();
            await admin.screenshot({ path: path.join(shots, 'admin-integration.png'), fullPage: true });
            await card.getByRole('tab', { name: /^Users/ }).click();
        }
        await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(origin).origin });
        await admin.getByRole('button', { name: 'Copy client ID' }).click();
        assert.equal(await admin.evaluate(() => navigator.clipboard.readText()), 'email-client');
        await card.getByRole('tab', { name: 'Integration' }).click();
        const inspectionSnippet = card.locator('.snippet').filter({ hasText: 'Token introspection' });
        await inspectionSnippet.getByRole('button', { name: 'Copy', exact: true }).click();
        const inspectionCommand = await admin.evaluate(() => navigator.clipboard.readText());
        assert.ok(inspectionCommand.includes(origin + '/oauth/v2/introspect') && inspectionCommand.includes('token=<access-token>') && inspectionCommand.includes('-u "email-client:<client-secret>"'));
        assert.ok(await card.getByText('Introspection', { exact: true }).isVisible());
        await card.getByRole('tab', { name: /^Users/ }).click();
        admin.once('dialog', dialog => dialog.accept());
        await admin.locator('.client-card').first().locator('.row-title', { hasText: 'Tab Person' }).click();
        await admin.locator('.client-card').first().locator('details[open]').getByRole('button', { name: 'Delete user', exact: true }).click();
        await admin.getByRole('status').filter({ hasText: 'User deleted.' }).waitFor();
        console.log('PASS admin tabs persist across HTMX swaps and nested forms save');

        // Dark mode and reduced motion render and behave.
        if (shots) {
            await admin.screenshot({ path: path.join(shots, 'admin-light.png'), fullPage: true });
            await page.screenshot({ path: path.join(shots, 'welcome-light-mobile.png') });
        }
        const dark = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 }, colorScheme: 'dark', reducedMotion: 'reduce' });
        const darkPage = await dark.newPage();
        darkPage.on('pageerror', error => errors.push('dark: ' + error.message));
        await darkPage.goto(url);
        await darkPage.waitForFunction(() => window.Alpine && document.querySelector('select[name=language]').value === 'en');
        const luminance = await darkPage.evaluate(() => {
            const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number);
            return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        });
        assert.ok(luminance < 60, `Dark scheme must render a dark canvas, got luminance ${luminance}`);
        if (shots) await darkPage.screenshot({ path: path.join(shots, 'login-dark.png') });
        await darkPage.getByRole('textbox', { name: 'Email', exact: true }).fill('dark.person@example.com');
        await darkPage.getByRole('button', { name: 'Continue', exact: true }).click();
        await darkPage.waitForURL(callbackUrl + '**');
        await darkPage.goto(url);
        await darkPage.getByRole('heading', { name: 'Welcome back, dark.person!' }).waitFor();
        if (shots) await darkPage.screenshot({ path: path.join(shots, 'welcome-dark.png') });
        await darkPage.waitForFunction(() => document.getElementById('countdown').textContent === '4');
        await darkPage.waitForURL(callbackUrl + '**');
        assert.ok(new URL(darkPage.url()).searchParams.get('code'), 'Countdown must complete under reduced motion');
        if (shots) {
            await darkPage.goto(origin);
            await darkPage.waitForFunction(() => window.htmx && window.Alpine);
            await darkPage.screenshot({ path: path.join(shots, 'admin-dark.png'), fullPage: true });
            await darkPage.setViewportSize({ width: 390, height: 844 });
            await darkPage.screenshot({ path: path.join(shots, 'admin-dark-mobile.png'), fullPage: true });
            await page.goto(url + '&prompt=login');
            await page.getByRole('textbox', { name: 'Email', exact: true }).waitFor();
            await page.screenshot({ path: path.join(shots, 'login-light-mobile.png') });
        }
        await dark.close();
        console.log('PASS dark scheme renders and countdown works under reduced motion');
        assert.deepEqual(errors, []);
        if (proxy) console.log('PASS prefix-stripping reverse proxy supports every login, logout, HTMX and navigation flow');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => callback.close(resolve));
        if (proxy) await new Promise(resolve => proxy.close(resolve));
        if (server.exitCode === null) { server.kill(); await new Promise(resolve => server.once('exit', resolve)); }
        fs.rmSync(directory, { recursive: true, force: true });
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
