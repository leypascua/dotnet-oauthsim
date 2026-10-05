// Run: node tests/browser-application-claims.cjs <path-to-playwright-module> [installed-tool]
// Requires Playwright with Chromium; set OAUTHSIM_SHOTS to retain screenshots.
const { chromium } = require(process.argv[2] || 'playwright');
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
    const socket = net.createServer();
    await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
    const port = socket.address().port;
    await new Promise(resolve => socket.close(resolve));
    const url = 'http://localhost:' + port;
    const settings = fs.mkdtempSync(path.join(os.tmpdir(), 'oauthsim-claims-'));
    const executable = process.argv[3] || path.join(root, 'src/OAuthSim.Web/bin/Release/net10.0/OAuthSim.Web.dll');
    const server = spawn(process.argv[3] ? executable : 'dotnet', [
        ...(process.argv[3] ? [] : [executable]), '--port', String(port), '--settings-dir', settings,
        '--no-browser', '--clientId', 'editor-client', '--clientSecret', 'test-secret'
    ], { cwd: root });
    let logs = '';
    server.stdout.on('data', data => { logs += data; });
    server.stderr.on('data', data => { logs += data; });
    let browser;
    try {
        for (let attempt = 0; ; attempt++) {
            try { if ((await fetch(url)).ok) break; } catch { }
            if (attempt > 100 || server.exitCode !== null) throw new Error('Server failed: ' + logs);
            await delay(100);
        }
        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ viewport: { width: 1100, height: 1100 }, colorScheme: 'dark' });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(url);
        await page.waitForFunction(() => window.Alpine && window.htmx);
        const card = page.locator('.client-card').first();
        const editor = card.locator('.application-claims');
        await editor.locator('.claims-editor').waitFor({ state: 'visible' });
        let requests = 0;
        page.on('request', request => { if (request.url().endsWith('/Admin/SaveClient')) requests++; });
        const addScope = async name => {
            await editor.getByLabel('New scope').fill(name);
            await editor.getByRole('button', { name: '+ Add scope', exact: true }).click();
        };
        const addClaim = async (name, type, value) => {
            await editor.getByRole('button', { name: '+ Add claim', exact: true }).click();
            const row = editor.locator('.claims-row').last();
            await row.getByLabel('Claim name', { exact: true }).fill(name);
            await row.getByLabel('Type', { exact: true }).selectOption(type);
            if (type === 'boolean') await row.getByLabel('Value', { exact: true }).selectOption(value);
            else if (type !== 'null') await row.getByLabel('Value', { exact: true }).fill(value);
        };
        const save = async () => {
            const response = page.waitForResponse(r => r.url().endsWith('/Admin/SaveClient'));
            await card.getByRole('button', { name: 'Save client', exact: true }).click();
            assert.equal((await response).status(), 200);
            await page.locator('.banner.is-success').waitFor();
            await editor.locator('.claims-editor').waitFor({ state: 'visible' });
        };
        await addScope('api.read');
        await addClaim('role', 'string', 'service "quoted" café');
        await addClaim('huge', 'number', '900719925474099312345');
        await addClaim('enabled', 'boolean', 'true');
        await addClaim('empty', 'null');
        await addClaim('context', 'object', '{"id":900719925474099312345,"sandbox":true}');
        await addClaim('features', 'array', '["read",null,900719925474099312345]');
        await addClaim('__proto__', 'string', 'special-key');
        await addScope('api.write');
        await addClaim('write_permission', 'boolean', 'true');
        await editor.getByRole('button', { name: 'api.read 7', exact: true }).click();
        assert.equal(await editor.locator('.claims-row').first().getByLabel('Value', { exact: true }).inputValue(), 'service "quoted" café');
        assert.equal(await card.locator('[name=scopes]').inputValue(), '');
        console.log('PASS all six types, scope switching and independent Allowed scopes');

        // An unselected invalid draft must cancel submission before HTMX collects the form.
        const numberRow = editor.locator('.claims-row').nth(1);
        await numberRow.getByLabel('Value', { exact: true }).fill('NaN');
        await editor.getByRole('button', { name: 'api.write 1', exact: true }).click();
        await card.getByRole('button', { name: 'Save client', exact: true }).click();
        await delay(250);
        assert.equal(requests, 0);
        assert.equal(await editor.locator('.claims-scope-select[aria-pressed=true] .mono').innerText(), 'api.read');
        assert.match(await editor.locator('[role=alert]').innerText(), /Review/);
        await numberRow.getByLabel('Value', { exact: true }).fill('900719925474099312345');
        await editor.getByLabel('New scope').fill('api.read');
        await editor.getByLabel('New scope').press('Enter');
        assert.equal(requests, 0);
        assert.match(await editor.locator('[id*=scope-error]').innerText(), /already/);
        console.log('PASS hidden-draft validation and Enter cannot accidentally submit');
        await save();
        assert.equal(await editor.locator('.claims-row').nth(1).getByLabel('Value', { exact: true }).inputValue(), '900719925474099312345');
        assert.equal((await editor.locator('.claims-row').nth(4).getByLabel('Value', { exact: true }).inputValue()).replace(/\s+/g, ''), '{"id":900719925474099312345,"sandbox":true}');
        const stored = fs.readFileSync(path.join(settings, 'settings.json'), 'utf8');
        assert.match(stored, /900719925474099312345/);
        assert.equal(JSON.parse(stored).clients[0].claimsByScope['api.read'].__proto__, 'special-key');
        const tokenResponse = await context.request.post(url + '/token', { form: { grant_type: 'client_credentials', client_id: 'editor-client', client_secret: 'test-secret', scope: 'api.read' } });
        assert.equal(tokenResponse.status(), 200);
        const jwt = (await tokenResponse.json()).access_token;
        const payload = Buffer.from(jwt.split('.')[1], 'base64url').toString();
        assert.match(payload, /"huge":900719925474099312345/);
        assert.match(payload, /"id":900719925474099312345/);
        assert.equal(JSON.parse(payload).enabled, true);
        assert.equal(JSON.parse(payload).empty, null);
        assert.equal(JSON.parse(payload).write_permission, undefined);
        console.log('PASS HTMX save/reinitialization, precision, special keys and scoped token emission');

        await card.locator('[name=scopes]').fill('api.write');
        await page.waitForFunction(() => document.querySelector('.client-card .claims-detail').innerText.includes('not in Allowed scopes'));
        await card.locator('[name=relaxScopes]').check();
        await page.waitForFunction(() => ![...document.querySelectorAll('.client-card .claims-detail .help')].some(el => el.offsetParent && el.textContent.includes('not in Allowed scopes')));
        await addClaim('iss', 'string', 'ignored');
        await editor.locator('.claims-row').last().getByText('Reserved claim; token generation ignores this value.').waitFor({ state: 'visible' });
        await editor.locator('.claims-row').last().getByLabel('Claim name', { exact: true }).fill('role');
        const beforeDuplicateSave = requests;
        await card.getByRole('button', { name: 'Save client', exact: true }).click();
        await delay(250);
        assert.equal(requests, beforeDuplicateSave);
        await editor.locator('.claims-row').last().getByRole('button', { name: 'Remove claim role', exact: true }).click();
        await editor.getByRole('button', { name: 'Remove scope api.write', exact: true }).click();
        await save();
        assert.equal(JSON.parse(fs.readFileSync(path.join(settings, 'settings.json'), 'utf8')).clients[0].claimsByScope['api.write'], undefined);
        console.log('PASS live policy hints, reserved guidance, duplicate-name validation and removal');

        const addClient = page.locator('details.ghost-card').filter({ has: page.locator('summary', { hasText: /^Add client$/ }) });
        await addClient.locator('summary').click();
        await addClient.locator('[name=clientId]').fill('second-client');
        await addClient.getByRole('button', { name: 'Save client', exact: true }).click();
        await page.waitForFunction(() => document.querySelectorAll('.client-card').length === 2);
        await editor.locator('.claims-editor').waitFor({ state: 'visible' });
        const secondEditor = page.locator('.client-card').nth(1).locator('.application-claims');
        await secondEditor.getByLabel('New scope').fill('second.scope');
        await secondEditor.getByRole('button', { name: '+ Add scope', exact: true }).click();
        assert.equal(await editor.locator('.claims-scope-item').count(), 1);
        const ids = await page.locator('.application-claims [id]').evaluateAll(elements => elements.map(el => el.id));
        assert.equal(ids.length, new Set(ids).size);
        console.log('PASS multiple-client isolation and unique accessible control IDs');

        await editor.scrollIntoViewIfNeeded();
        const shots = process.env.OAUTHSIM_SHOTS;
        if (shots) {
            fs.mkdirSync(shots, { recursive: true });
            await page.screenshot({ path: path.join(shots, 'application-claims-desktop-dark.png'), fullPage: true });
        }
        const desktop = await editor.locator('.claims-editor').evaluate(el => getComputedStyle(el).gridTemplateColumns.split(' ').length);
        assert.equal(desktop, 2);
        await page.setViewportSize({ width: 390, height: 844 });
        await page.emulateMedia({ colorScheme: 'light' });
        await editor.scrollIntoViewIfNeeded();
        const columns = await editor.locator('.claims-editor').evaluate(el => getComputedStyle(el).gridTemplateColumns.split(' ').length);
        assert.equal(columns, 1);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
        if (shots) await page.screenshot({ path: path.join(shots, 'application-claims-mobile-light.png'), fullPage: true });
        const issuerOverride = 'https://identity.example.com/browser-tenant/';
        const audienceOverride = 'browser-orders-api';
        await card.getByLabel('Issuer override', { exact: true }).fill(issuerOverride);
        await card.getByLabel('Access-token audience override', { exact: true }).fill(audienceOverride);
        await save();
        await page.reload();
        await editor.locator('.claims-editor').waitFor({ state: 'visible' });
        assert.equal(await card.getByLabel('Issuer override', { exact: true }).inputValue(), issuerOverride);
        assert.equal(await card.getByLabel('Access-token audience override', { exact: true }).inputValue(), audienceOverride);
        await card.getByRole('tab', { name: 'Integration', exact: true }).click();
        await card.getByText(issuerOverride, { exact: true }).waitFor({ state: 'visible' });
        await card.getByText(audienceOverride, { exact: true }).waitFor({ state: 'visible' });
        const discoveryUrl = await card.getByRole('link', { name: url + '/.well-known/openid-configuration?client_id=editor-client', exact: true }).getAttribute('href');
        const discovery = await (await context.request.get(discoveryUrl)).json();
        assert.equal(discovery.issuer, issuerOverride);
        assert.equal(discovery.token_endpoint, url + '/oauth/v2/token');
        assert.equal((await (await context.request.get(url + '/.well-known/openid-configuration?client_id=second-client')).json()).issuer, url);
        const overriddenResponse = await context.request.post(url + '/token', { form: { grant_type: 'client_credentials', client_id: 'editor-client', client_secret: 'test-secret', scope: 'api.read' } });
        assert.equal(overriddenResponse.status(), 200);
        const overriddenToken = (await overriddenResponse.json()).access_token;
        const overriddenPayload = JSON.parse(Buffer.from(overriddenToken.split('.')[1], 'base64url').toString());
        assert.equal(overriddenPayload.iss, issuerOverride);
        assert.equal(overriddenPayload.aud, audienceOverride);
        assert.equal(overriddenPayload.client_id, 'editor-client');
        assert.deepEqual(await (await context.request.post(url + '/introspect', { form: { token: jwt } })).json(), { active: false });
        await card.getByRole('tab', { name: 'Settings', exact: true }).click();
        await card.getByLabel('Issuer override', { exact: true }).fill('');
        await card.getByLabel('Access-token audience override', { exact: true }).fill('');
        await save();
        const fallbackResponse = await context.request.post(url + '/token', { form: { grant_type: 'client_credentials', client_id: 'editor-client', client_secret: 'test-secret', scope: 'api.read' } });
        const fallbackToken = (await fallbackResponse.json()).access_token;
        const fallbackPayload = JSON.parse(Buffer.from(fallbackToken.split('.')[1], 'base64url').toString());
        assert.equal(fallbackPayload.iss, url);
        assert.equal(fallbackPayload.aud, 'editor-client');
        console.log('PASS issuer/audience controls persist, publish matching discovery and restore defaults when cleared');
        assert.deepEqual(errors, []);
        console.log('PASS responsive dark/light layouts, no horizontal overflow or JavaScript errors');
    } finally {
        if (browser) await browser.close();
        if (server.exitCode === null) { server.kill(); await new Promise(resolve => server.once('exit', resolve)); }
        fs.rmSync(settings, { recursive: true, force: true });
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
