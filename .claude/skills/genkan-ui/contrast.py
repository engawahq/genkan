#!/usr/bin/env python3
"""WCAG 2.2 contrast of the sign-in pages' colour tokens.

Converts OKLCH tokens to linear sRGB (OKLab matrices from B. Ottosson, "A perceptual color space
for image processing", 2020), clips to the sRGB gamut, composites alpha in gamma-encoded sRGB as
browsers do, and applies the WCAG relative-luminance contrast formula. Edit the token values and
pairs at the bottom to match ui/styles/app.css, then run: python3 contrast.py
"""
import math
def oklch(L,C=0,h=0):
    a=C*math.cos(math.radians(h)); b=C*math.sin(math.radians(h))
    l_=L+0.3963377774*a+0.2158037573*b; m_=L-0.1055613458*a-0.0638541728*b; s_=L-0.0894841775*a-1.2914855480*b
    l,m,s=l_**3,m_**3,s_**3
    r=4.0767416621*l-3.3077115913*m+0.2309699292*s
    g=-1.2684380046*l+2.6097574011*m-0.3413193965*s
    bb=-0.0041960863*l-0.7034186147*m+1.7076147010*s
    return tuple(min(1,max(0,x)) for x in (r,g,bb))  # linear sRGB, gamut-clipped
def mix(fg,bg,alpha):  # composite in gamma-encoded sRGB as browsers do
    enc=lambda c: 12.92*c if c<=0.0031308 else 1.055*c**(1/2.4)-0.055
    dec=lambda c: c/12.92 if c<=0.04045 else ((c+0.055)/1.055)**2.4
    return tuple(dec(alpha*enc(f)+(1-alpha)*enc(b)) for f,b in zip(fg,bg))
def Y(c): return 0.2126*c[0]+0.7152*c[1]+0.0722*c[2]
def ratio(a,b):
    ya,yb=sorted((Y(a),Y(b)),reverse=True); return (ya+0.05)/(yb+0.05)
W=oklch(1)
rows=[]
def check(name,a,b,need): r=ratio(a,b); rows.append((name,r,need,'ok' if r>=need else 'FAIL'))
# light
bg=card=W; fg=oklch(.145); muted=oklch(.97); mfg=oklch(.5); destr=oklch(.577,.245,27.325)
check('L fg/card',fg,card,4.5)
check('L muted-fg/card',mfg,card,4.5)
check('L muted-fg/muted',mfg,muted,4.5)
check('L destructive/card',destr,card,4.5)
check('L destructive/10% tint (button variant, unused)',destr,mix(destr,card,.10),4.5)
check('L primary-fg/primary',oklch(.985),oklch(.205),4.5)
check('L input border/card',oklch(.6),card,3)
check('L ring/card',oklch(.556),card,3)
check('L upstream muted-fg .556/muted',oklch(.556),muted,4.5)
# dark
bg=oklch(.145); card=oklch(.205); fg=oklch(.985); muted=oklch(.269); mfg=oklch(.708); destr=oklch(.704,.191,22.216)
inputc=mix(W,card,.45); field=mix(W,card,.45*.30)
check('D fg/card',fg,card,4.5)
check('D muted-fg/card',mfg,card,4.5)
check('D muted-fg/muted',mfg,muted,4.5)
check('D destructive/card',destr,card,4.5)
check('D destructive/10% tint (button variant, unused)',destr,mix(destr,card,.10),4.5)
check('D primary-fg/primary',oklch(.205),oklch(.922),4.5)
check('D input border/card',inputc,card,3)
check('D input border/field bg',inputc,field,3)
check('D ring/card',oklch(.708),card,3)
check('D ring/background',oklch(.708),bg,3)
for r in rows: print(f'{r[0]:52} {r[1]:6.2f} need {r[2]:<4} {r[3]}')
