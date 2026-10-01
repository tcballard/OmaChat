const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const theme = vm.createContext({});
vm.runInContext(fs.readFileSync(__dirname + '/../Theme.js', 'utf8'), theme);
const palettes = [
    {background:'#1a1b26', foreground:'#c0caf5', accent:'#7aa2f7'},
    {background:'#eff1f5', foreground:'#4c4f69', accent:'#8839ef'},
    {background:'#282828', foreground:'#ebdbb2', accent:'#b8bb26'},
    {background:'#ffffff', foreground:'#cccccc', accent:'#eeeeee'},
    {background:'#000000', foreground:'#111111', accent:'#222222'}
];
// Include every neutral brightness, especially mid-tones with limited contrast.
for (let n=0;n<=255;n++) palettes.push({background:'#'+n.toString(16).padStart(2,'0').repeat(3), foreground:'#777777', accent:'#777777'});
for (const palette of palettes) {
    const t = theme.tokens(palette, palettes[0]);
    assert.equal(t.surface, palette.background);
    for (const bg of ['surface','panel','control','selected'])
        assert.ok(theme.contrast(t.ink,t[bg]) >= 4.5, `body on ${bg}`);
    assert.ok(theme.contrast(t.muted,t.control) >= 4.5, 'secondary text');
    assert.ok(theme.contrast(t.accent,t.panel) >= 4.5, 'accent text');
    assert.ok(theme.contrast(t.primaryInk,t.accent) >= 4.5, 'primary action');
}
assert.equal(theme.tokens({}, palettes[1]).surface, palettes[1].background);
console.log('Theme contrast, custom palettes and system fallback passed');
