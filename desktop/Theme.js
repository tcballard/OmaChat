// Palette utilities shared by every surface. Keep user hues; improve text contrast.
function rgb(value) {
    if (typeof value === "string" && /^#[0-9a-f]{6}$/i.test(value))
        return [parseInt(value.slice(1,3),16)/255,parseInt(value.slice(3,5),16)/255,parseInt(value.slice(5,7),16)/255];
    return [value.r, value.g, value.b];
}
function hex(value) { return "#" + value.map(function(v) { return Math.round(Math.max(0,Math.min(1,v))*255).toString(16).padStart(2,"0"); }).join(""); }
function mix(a,b,amount) { a=rgb(a); b=rgb(b); return hex(a.map(function(v,i) { return v+(b[i]-v)*amount; })); }
function luminance(color) { var c=rgb(color).map(function(v) { return v<=0.04045?v/12.92:Math.pow((v+0.055)/1.055,2.4); }); return c[0]*0.2126+c[1]*0.7152+c[2]*0.0722; }
function contrast(a,b) { var x=luminance(a),y=luminance(b); return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05); }
function readable(color,background,minimum) {
    if (contrast(color,background)>=minimum) return hex(rgb(color));
    var target=contrast("#000000",background)>contrast("#ffffff",background)?"#000000":"#ffffff";
    for(var step=1;step<=100;step++) { var candidate=mix(color,target,step/100); if(contrast(candidate,background)>=minimum) return candidate; }
    return target;
}
// Reduce surface tint when a mid-tone user background leaves little contrast headroom.
function surfaceTint(background, tint, amount, foreground) {
    for (var i=10;i>=0;i--) {
        var candidate=mix(background,tint,amount*i/10);
        if (contrast(foreground,candidate)>=4.5) return candidate;
    }
    return hex(rgb(background));
}
function tokens(source,system) {
    var bg=source.background || system.background;
    var fg=readable(source.foreground || system.foreground,bg,7);
    var panel=surfaceTint(bg,fg,0.035,fg), control=surfaceTint(bg,fg,0.065,fg);
    var accent=readable(source.accent || system.accent,panel,4.5);
    var selected=surfaceTint(bg,accent,0.14,fg);
    var muted=readable(mix(bg,fg,0.64),control,4.5);
    if (contrast(muted,selected)<4.5) muted=fg;
    return {surface:hex(rgb(bg)),panel:panel,ink:fg,muted:muted,accent:accent,
        primaryInk:readable(bg,accent,4.5),line:mix(bg,fg,0.2),control:control,
        hover:surfaceTint(bg,fg,0.11,fg),selected:selected,
        warning:readable(source.color3 || fg,panel,4.5),danger:readable(source.color1 || fg,panel,4.5)};
}
