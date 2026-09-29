const fs = require('fs'), vm = require('vm'), assert = require('assert');
const S = {}, D = {};
vm.createContext(S); vm.createContext(D);
vm.runInContext(fs.readFileSync('desktop/ChatState.js', 'utf8'), S);
vm.runInContext(fs.readFileSync('desktop/Drafts.js', 'utf8'), D);
function fixture(text = '') {
    const s = S.create(); S.snapshot(s, {status:{drafts_version:1},messages:[]});
    S.select(s, '#gcpvj'); D.reset(s); D.next(s); // metadata request
    const c = S.current(s), req = D.next(s);
    D.response(s,{id:req.id,ok:true,data:{conversation:c.id,text,revision:2}},S.ensure);
    return {s,c};
}
function reply(s, request, text, revision, saved = true) {
    return D.response(s,{id:request.id,ok:true,data:{conversation:request.params.conversation,text,revision,saved}},S.ensure);
}
{
    const {s,c} = fixture('recovered');
    assert.equal(c.draft, 'recovered'); assert.equal(D.canSend(s,c),false);
    D.meta(c).recovered=false; assert.equal(D.canSend(s,c),true);
    D.edit(c,'first'); const save=D.next(s); D.edit(c,'newer typing');
    reply(s,save,'first',3); assert.equal(c.draft,'newer typing');
    assert.equal(D.meta(c).dirty,true);
    const second=D.next(s); assert.equal(second.params.expected_revision,3);
    reply(s,second,'newer typing',4); assert.equal(D.meta(c).dirty,false);
}
{
    const {s,c} = fixture(); D.edit(c,'mine'); const save=D.next(s);
    reply(s,save,'theirs',3,false); assert.equal(c.draft,'mine'); assert.equal(D.next(s),null);
    D.resolve(c,true); const again=D.next(s); assert.equal(again.params.text,'mine');
    assert.equal(again.params.expected_revision,3);
    reply(s,again,'changed again',4,false); D.resolve(c,false);
    assert.equal(c.draft,'changed again'); assert.equal(D.meta(c).dirty,false);
}
{
    const {s,c}=fixture(); D.edit(c,'mine'); D.next(s); // unknown save outcome
    D.reset(s); D.next(s); const get=D.next(s); reply(s,get,'mine',3);
    assert.equal(c.draft,'mine'); assert.equal(D.meta(c).dirty,false);
    D.edit(c,'new local'); D.reset(s); D.next(s); const get2=D.next(s);
    reply(s,get2,'remote edit',4); assert.equal(c.draft,'new local'); assert.ok(D.meta(c).conflict);
}
{
    const s=S.create(); S.snapshot(s,{status:{drafts_version:1},messages:[]});
    S.select(s,'#gcpvj'); D.reset(s); D.next(s); const get=D.next(s),c=S.current(s);
    D.edit(c,'typed while loading'); reply(s,get,'saved elsewhere',2);
    assert.equal(c.draft,'typed while loading'); assert.ok(D.meta(c).conflict);
}
{
    const {s,c}=fixture(); D.edit(c,'🙂'.repeat(1025)); assert.equal(D.next(s),null); assert.ok(D.meta(c).error);
    D.edit(c,'valid'); const save=D.next(s); assert.equal(save.params.text,'valid');
    D.response(s,{id:save.id,ok:false,error:'disk full'},S.ensure);
    assert.equal(c.draft,'valid'); assert.equal(D.next(s),null); assert.match(D.label(s,c),/disk full/);
}
{
    const {s,c}=fixture('sent text'); D.meta(c).recovered=false;
    c.draft=''; D.meta(c).dirty=true; const clear=D.next(s);
    assert.equal(clear.params.text,''); assert.equal(clear.params.expected_revision,2);
    reply(s,clear,'',3); assert.equal(D.meta(c).dirty,false);
    s.status={}; D.edit(c,'old daemon'); assert.equal(D.next(s),null); assert.match(D.label(s,c),/Session/);
}
console.log('PASS: recovery, late acknowledgements, conflicts, reconnects, UTF-8 limits, failures and clear-after-send');
