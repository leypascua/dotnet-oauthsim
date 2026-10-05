// Optional dependency-free UI logic checks: node --test tests/OAuthSim.Tests/ApplicationClaimsEditor.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

let factory;
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../src/OAuthSim.Web/Views/Shared/_ApplicationClaimsScript.cshtml'), 'utf8'), {
    Alpine: { data: (_, component) => { factory = component; } }
});
let editorId = 0;
function editor(groups = []) {
    const listeners = new Map();
    const fields = { scopes: { value: 'api.read api.write' }, relaxScopes: { checked: false }, isPublic: { checked: false } };
    const form = {
        elements: { namedItem: name => fields[name] },
        addEventListener: (name, listener) => listeners.set(name, listener),
        removeEventListener: name => listeners.delete(name)
    };
    const component = factory(groups, ['iss', 'sub']);
    component.$id = () => 'editor-' + editorId++;
    component.$el = { closest: () => form, querySelector: () => null };
    component.$refs = { payload: { value: '' }, newScope: { focus() {} }, claimRows: { querySelectorAll: () => [] } };
    component.$nextTick = callback => callback();
    component.init();
    return { component, listeners, fields, form };
}
function group(name, claims) { return { name, claims }; }
function claim(name, type, value) { return { name, type, value }; }

test('lossless serialization preserves every type, nested large numbers and special keys', () => {
    const { component } = editor([group('__proto__', [
        claim('role', 'string', 'service "quoted" \\ café'),
        claim('huge', 'number', '900719925474099312345'),
        claim('decimal', 'number', '1.234567890123456789'),
        claim('enabled', 'boolean', 'true'), claim('empty', 'null', 'null'),
        claim('context', 'object', '{"id":900719925474099312345}'),
        claim('features', 'array', '[null,false,900719925474099312345]'),
        claim('"\\<>&', 'string', '')
    ])]);
    assert.equal(component.validate(), true);
    const json = component.serialize();
    const parsed = JSON.parse(json).__proto__;
    assert.equal(parsed.role, 'service "quoted" \\ café');
    assert.equal(parsed.empty, null);
    assert.equal(parsed.enabled, true);
    assert.equal(parsed['"\\<>&'], '');
    assert.match(json, /"huge":900719925474099312345/);
    assert.match(json, /"decimal":1\.234567890123456789/);
    assert.match(json, /"context":\{"id":900719925474099312345\}/);
    assert.match(json, /"features":\[null,false,900719925474099312345\]/);
});

test('invalid drafts in unselected scopes cancel submission and select the offending mapping', () => {
    const { component, listeners } = editor([
        group('api.read', [claim('limit', 'number', 'NaN')]),
        group('api.write', [claim('role', 'string', 'writer')])
    ]);
    component.selectedId = component.groups[1].id;
    let prevented = false, stopped = false;
    listeners.get('submit')({ preventDefault() { prevented = true; }, stopImmediatePropagation() { stopped = true; } });
    assert.equal(prevented && stopped, true);
    assert.equal(component.selected.name, 'api.read');
    assert.equal(component.$refs.payload.value, '');
    component.selected.claims[0].value = '12';
    listeners.get('submit')({ preventDefault() { assert.fail('valid draft blocked'); } });
    assert.equal(component.$refs.payload.value, '{"api.read":{"limit":12},"api.write":{"role":"writer"}}');
});

test('HTMX receives current edits synchronously, including an empty mapping', () => {
    const { component, listeners, form } = editor([group('api.read', [claim('role', 'string', 'old')]), group('api.write', [])]);
    component.selected.claims[0].value = 'just edited';
    const event = { detail: { elt: form, parameters: { claims: 'stale' } }, preventDefault() { assert.fail('valid request blocked'); } };
    listeners.get('htmx:configRequest')(event);
    assert.equal(event.detail.parameters.claims, '{"api.read":{"role":"just edited"},"api.write":{}}');
    component.selected.claims.push({ ...claim('role', 'string', 'duplicate'), id: component.id() });
    let cancelled = false;
    event.preventDefault = () => { cancelled = true; };
    listeners.get('htmx:configRequest')(event);
    assert.equal(cancelled, true);
});

test('scope switching and removal retain independent drafts without modifying allowed scopes', () => {
    const { component, fields } = editor();
    component.newScope = 'api.read'; component.addScope(); component.addClaim();
    component.selected.claims[0].name = 'role'; component.selected.claims[0].value = 'reader';
    const first = component.selectedId;
    component.newScope = 'custom'; component.addScope();
    assert.equal(fields.scopes.value, 'api.read api.write');
    assert.match(component.scopeHint(component.selected), /not in Allowed scopes/);
    component.selectedId = first;
    assert.equal(component.selected.claims[0].value, 'reader');
    component.newScope = 'api.read'; component.addScope();
    assert.match(component.newScopeError, /already/);
    assert.equal(component.groups.length, 2);
    component.removeClaim(component.selected.claims[0].id);
    component.removeScope(first);
    assert.equal(component.selected.name, 'custom');
    component.removeScope(component.selectedId);
    assert.equal(component.selected, null);
    assert.equal(component.serialize(), '{}');
});

test('validation distinguishes JSON types and accepts precise JSON numbers without Number conversion', () => {
    const { component } = editor();
    for (const value of ['NaN', 'Infinity', '01', '.5', '1.', '+1', '', '0x10'])
        assert.notEqual(component.valueError(claim('x', 'number', value)), '', value);
    for (const value of ['-0', '1.234567890123456789', '1e400', ' 900719925474099312345 '])
        assert.equal(component.valueError(claim('x', 'number', value)), '', value);
    assert.notEqual(component.valueError(claim('x', 'object', '[]')), '');
    assert.notEqual(component.valueError(claim('x', 'object', 'null')), '');
    assert.notEqual(component.valueError(claim('x', 'array', '{}')), '');
    assert.notEqual(component.valueError(claim('x', 'array', '[1,]')), '');
    for (const value of ['two scopes', 'quoted"', 'back\\slash', '', 'café']) assert.notEqual(component.scopeNameError(value), '', value);
    assert.equal(component.scopeNameError('api.read:service'), '');
});

test('scope guidance tracks unsaved policy changes and reserved claims remain compatible', () => {
    const { component, fields, listeners } = editor([group('custom', [claim('iss', 'string', 'ignored')])]);
    assert.match(component.scopeHint(component.selected), /not in Allowed scopes/);
    fields.relaxScopes.checked = true;
    listeners.get('change')({ target: { name: 'relaxScopes' } });
    assert.equal(component.scopeHint(component.selected), '');
    assert.match(component.scopeHint({ name: 'openid' }), /not supported/);
    fields.isPublic.checked = true;
    listeners.get('input')({ target: { name: 'isPublic' } });
    assert.equal(component.publicClient, true);
    assert.equal(component.isReserved('iss'), true);
    assert.equal(component.validate(), true);
});

test('editors have isolated state and detach their form listeners on dashboard replacement', () => {
    const first = editor([group('api.read', [])]), second = editor([group('api.read', [])]);
    assert.notEqual(first.component.selectedId, second.component.selectedId);
    first.component.addClaim();
    assert.equal(second.component.selected.claims.length, 0);
    first.component.destroy();
    assert.equal(first.listeners.size, 0);
    assert.equal(second.listeners.size, 4);
});
