"""Static site: landing page, public registry, one page per repo, docs, pricing, badges and a JSON API.

Plain files, no build step, no JavaScript framework and no third-party
requests, so it can be served from GitHub Pages or any bucket. Everything that
comes from a scanned repository is untrusted and is escaped on the way out.
"""

from __future__ import annotations

import html
import json
import shutil
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from . import __version__, registry, rules
from .registry import Disclosure, Entry

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class SiteConfig:
    name: str = "Plugin Warden"
    base_url: str = "https://battlettt.github.io/plugin-warden"
    repo_url: str = "https://github.com/battlettt/plugin-warden"
    contact_url: str = "https://github.com/battlettt/plugin-warden/issues/new?template=pilot.yml"
    security_url: str = "https://github.com/battlettt/plugin-warden/security/advisories/new"
    team_price: int = 249
    business_price: int = 749
    team_checkout_url: str = ""
    business_checkout_url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def load_config(path: Path) -> SiteConfig:
    cfg = SiteConfig()
    if not path.is_file():
        return cfg
    data = tomllib.loads(path.read_text())
    pricing = data.pop("pricing", {}) if isinstance(data.get("pricing"), dict) else {}
    for key, value in {**data, **pricing}.items():
        if hasattr(cfg, key) and key != "extra":
            setattr(cfg, key, value)
        else:
            cfg.extra[key] = value
    for key in ("base_url", "repo_url", "contact_url", "security_url", "team_checkout_url", "business_checkout_url"):
        value = getattr(cfg, key)
        if value and not str(value).startswith("https://"):
            raise registry.RegistryError(f"site.toml: {key} must be an https URL")
    cfg.base_url = cfg.base_url.rstrip("/")
    return cfg


def e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _date(iso: str | None) -> str:
    return str(iso or "")[:10]


def _n(value: int | None) -> str:
    return f"{value:,}" if isinstance(value, int) else "n/a"


# -------------------------------------------------------------------------- CSS
CSS = """
:root{--paper:#f4f1ea;--panel:#fbfaf6;--ink:#1a1814;--soft:#5f5a50;--rule:#d9d3c4;--wash:#ebe6da;--code:#efeadd;
--stamp:#b4320f;--stamp-ink:#fff8f2;--ok:#2c6a4b;--warn:#8f5a00;--bad:#b3261e;--mute:#6a6558;--link:#7a2408;
--serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
--sans:ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#12110f;--panel:#1a1916;--ink:#ece7da;--soft:#aaa393;--rule:#33302a;--wash:#211f1b;--code:#201e1a;
--stamp:#ff7a4d;--stamp-ink:#1a0c05;--ok:#77d3a2;--warn:#f0c15a;--bad:#ff7a6e;--mute:#8d8778;--link:#ffab8a}}
:root[data-theme="dark"]{--paper:#12110f;--panel:#1a1916;--ink:#ece7da;--soft:#aaa393;--rule:#33302a;--wash:#211f1b;--code:#201e1a;
--stamp:#ff7a4d;--stamp-ink:#1a0c05;--ok:#77d3a2;--warn:#f0c15a;--bad:#ff7a6e;--mute:#8d8778;--link:#ffab8a}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 var(--sans)}
a{color:var(--link);text-underline-offset:3px}a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--stamp);outline-offset:2px}
.wrap{max-width:1120px;margin:0 auto;padding:0 20px}
code,pre,.mono{font-family:var(--mono)}code{font-size:.9em;background:var(--code);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--rule);border-radius:8px;padding:14px 16px;overflow-x:auto;font-size:13.5px;line-height:1.55;margin:14px 0}
pre code{background:none;padding:0;font-size:inherit}
h1,h2,h3{font-family:var(--serif);font-weight:600;letter-spacing:-.012em;line-height:1.15;margin:0;text-wrap:balance}
h1{font-size:clamp(2.1rem,5.2vw,3.6rem)}h2{font-size:clamp(1.55rem,3vw,2.15rem)}h3{font-size:1.2rem}
p{margin:0 0 14px;max-width:68ch}.lede{font-size:1.16rem;color:var(--soft);max-width:60ch}
.eyebrow{font:600 12px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--stamp);margin-bottom:14px}
.skip{position:absolute;left:-999px}.skip:focus{left:12px;top:12px;background:var(--panel);padding:8px 12px;z-index:9}

.nav{border-bottom:1px solid var(--rule);background:var(--paper)}
.nav .wrap{display:flex;align-items:center;gap:22px;min-height:60px;flex-wrap:wrap}
.brand{font:600 1.15rem var(--serif);color:var(--ink);text-decoration:none;display:flex;align-items:center;gap:9px;margin-right:auto}
.brand i{width:22px;height:22px;border:2px solid var(--stamp);border-radius:50%;display:grid;place-items:center;font:700 11px var(--mono);color:var(--stamp);font-style:normal;transform:rotate(-8deg)}
.nav a.l{color:var(--soft);text-decoration:none;font-size:.95rem;padding:6px 0}.nav a.l:hover,.nav a.l[aria-current]{color:var(--ink)}
.nav a.l[aria-current]{box-shadow:0 2px 0 var(--stamp)}
.tt{font:12px var(--mono);background:none;color:var(--soft);border:1px solid var(--rule);border-radius:6px;padding:5px 9px;cursor:pointer}

.btn{display:inline-block;font:600 .95rem var(--sans);padding:11px 18px;border-radius:8px;text-decoration:none;border:1px solid var(--ink);color:var(--ink);background:transparent}
.btn.p{background:var(--ink);color:var(--paper)}.btn:hover{border-color:var(--stamp);color:var(--stamp)}.btn.p:hover{background:var(--stamp);color:var(--stamp-ink)}
.cta{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}

.hero{padding:64px 0 48px}.hero .wrap{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);gap:48px;align-items:center}
.slip{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:20px 20px 16px;position:relative;box-shadow:0 1px 0 var(--rule),6px 6px 0 var(--wash)}
.slip h3{font:600 13px var(--mono);letter-spacing:.04em;margin-bottom:2px;overflow-wrap:anywhere}
.slip .sub{font:12px var(--mono);color:var(--mute);margin-bottom:14px}
.slip ol{list-style:none;margin:0;padding:0;border-top:1px dashed var(--rule)}
.slip li{padding:9px 0;border-bottom:1px dashed var(--rule);font-size:13px;display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px}
.slip li b{font:600 11px var(--mono);color:var(--stamp);text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;padding-top:2px}
.slip li code{background:none;padding:0;font-size:12.5px}
.slip .foot{font:12px var(--mono);color:var(--mute);margin-top:12px}
.stamp{position:absolute;top:-14px;right:14px;font:700 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--stamp);border:2px solid var(--stamp);border-radius:6px;padding:4px 9px;background:var(--panel);transform:rotate(3deg)}

.band{border-top:1px solid var(--rule);padding:56px 0}.band.w{background:var(--wash)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;border:1px solid var(--rule);border-radius:10px;background:var(--panel);overflow:hidden}
.stats div{padding:20px;border-right:1px solid var(--rule)}.stats div:last-child{border-right:0}
.stats b{display:block;font:600 2.1rem/1 var(--serif);font-variant-numeric:tabular-nums}.stats span{font-size:.88rem;color:var(--soft)}
.cols{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:28px;margin-top:28px}
.cols h3{margin-bottom:8px}.cols p{color:var(--soft);font-size:.97rem}
.jobs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;margin-top:28px}
.job{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:20px;min-width:0}
.job .k{font:600 12px var(--mono);color:var(--stamp);letter-spacing:.08em;text-transform:uppercase}
.job h3{margin:6px 0 8px}.job p{color:var(--soft);font-size:.96rem;margin-bottom:8px}.job pre{margin:10px 0 0;font-size:12.5px}
.head{display:flex;justify-content:space-between;align-items:end;gap:16px;flex-wrap:wrap;margin-bottom:8px}

table{width:100%;border-collapse:collapse;font-size:.92rem}
th{font:600 11.5px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--mute);text-align:left;padding:10px 12px;border-bottom:1px solid var(--ink)}
td{padding:11px 12px;border-bottom:1px solid var(--rule);vertical-align:top}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.tw{overflow-x:auto;background:var(--panel);border:1px solid var(--rule);border-radius:10px}
td a.repo{font-weight:600;text-decoration:none;color:var(--ink)}td a.repo:hover{color:var(--stamp)}td .d{color:var(--mute);font-size:.84rem;display:block;max-width:46ch}
.tag{display:inline-block;font:600 11px var(--mono);letter-spacing:.04em;padding:3px 8px;border-radius:5px;border:1px solid var(--rule);color:var(--soft);white-space:nowrap}
.tag.low{color:var(--ok);border-color:var(--ok)}.tag.caution{color:var(--warn);border-color:var(--warn)}.tag.review,.tag.block{color:var(--bad);border-color:var(--bad)}
.tag.block{background:var(--bad);color:var(--paper)}.tag.muted{border-style:dashed}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
.tools input,.tools select{font:15px var(--sans);padding:10px 12px;border:1px solid var(--rule);border-radius:8px;background:var(--panel);color:var(--ink);min-width:0}
.tools input{flex:1 1 260px}.count{font:13px var(--mono);color:var(--mute);margin:0 0 10px}

.note{background:var(--wash);border-left:3px solid var(--stamp);padding:14px 16px;border-radius:0 8px 8px 0;margin:18px 0;font-size:.96rem}
.note p:last-child{margin:0}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0;border:1px solid var(--rule);border-radius:10px;background:var(--panel);overflow:hidden;margin:20px 0}
.kv div{padding:14px 16px;border-right:1px solid var(--rule);border-bottom:1px solid var(--rule);margin:0 -1px -1px 0}
.kv b{display:block;font:600 1.5rem/1.1 var(--serif);font-variant-numeric:tabular-nums}.kv span{font-size:.82rem;color:var(--soft)}
.sec{margin-top:40px}.sec h2{font-size:1.45rem;margin-bottom:12px}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{font:12.5px var(--mono);background:var(--code);border-radius:5px;padding:3px 8px;overflow-wrap:anywhere}
.find{border:1px solid var(--rule);border-left:4px solid var(--mute);border-radius:8px;background:var(--panel);padding:14px 16px;margin:10px 0}
.find.critical,.find.high{border-left-color:var(--bad)}.find.medium{border-left-color:var(--warn)}.find.low{border-left-color:var(--ok)}
.find h3{font:600 1rem var(--sans);letter-spacing:0}.find .m{font:12px var(--mono);color:var(--mute);margin:4px 0 8px;overflow-wrap:anywhere}.find p{font-size:.94rem;margin-bottom:6px}
.crumb{font:13px var(--mono);color:var(--mute);margin:28px 0 10px}.crumb a{color:var(--mute)}
.title{display:flex;gap:16px;align-items:start;justify-content:space-between;flex-wrap:wrap}
.title h1{font-size:clamp(1.7rem,4vw,2.5rem);overflow-wrap:anywhere}

.tiers{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;margin-top:28px;align-items:start}
.tier{background:var(--panel);border:1px solid var(--rule);border-radius:12px;padding:24px;min-width:0}
.tier.f{border:2px solid var(--ink)}.tier .price{font:600 2.4rem/1 var(--serif);margin:12px 0 4px}.tier .price small{font:400 .95rem var(--sans);color:var(--soft)}
.tier ul{padding:0;margin:18px 0;list-style:none}.tier li{padding:7px 0 7px 22px;border-top:1px solid var(--rule);font-size:.94rem;position:relative}
.tier li::before{content:"";position:absolute;left:2px;top:15px;width:9px;height:5px;border-left:2px solid var(--ok);border-bottom:2px solid var(--ok);transform:rotate(-45deg)}
.tier .btn{width:100%;text-align:center}
.faq details{border-top:1px solid var(--rule);padding:14px 0}.faq summary{cursor:pointer;font-weight:600}.faq details p{margin:10px 0 0;color:var(--soft)}

.doc{display:grid;grid-template-columns:210px minmax(0,1fr);gap:44px;padding:40px 0 64px}
.toc{position:sticky;top:20px;align-self:start;font-size:.92rem}.toc a{display:block;padding:5px 0;color:var(--soft);text-decoration:none}.toc a:hover{color:var(--ink)}
.doc h2{margin:44px 0 12px;padding-top:8px;border-top:1px solid var(--rule)}.doc h2:first-of-type{margin-top:0;border:0;padding:0}.doc h3{margin:24px 0 8px}
.doc ul,.doc ol{max-width:68ch;padding-left:22px}.doc li{margin-bottom:6px}.doc table{margin:14px 0}

footer{border-top:1px solid var(--rule);padding:32px 0 48px;color:var(--soft);font-size:.9rem}
footer .wrap{display:flex;gap:24px;justify-content:space-between;flex-wrap:wrap}footer a{color:var(--soft)}footer p{margin:0 0 6px}

@media (max-width:860px){.hero{padding:40px 0 32px}.hero .wrap{grid-template-columns:minmax(0,1fr)}.cols,.tiers{grid-template-columns:minmax(0,1fr)}
.jobs{grid-template-columns:minmax(0,1fr)}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stats div:nth-child(2){border-right:0}.stats div:nth-child(-n+2){border-bottom:1px solid var(--rule)}
.doc{grid-template-columns:minmax(0,1fr);gap:8px}.toc{position:static;display:flex;flex-wrap:wrap;gap:4px 16px;border-bottom:1px solid var(--rule);padding-bottom:12px}}
@media (max-width:640px){.wrap{padding:0 16px}.nav .wrap{gap:14px;padding-top:8px;padding-bottom:8px}.band{padding:40px 0}
.stack thead{display:none}.stack tr{display:block;padding:10px 4px;border-bottom:1px solid var(--rule)}.stack td{display:block;border:0;padding:3px 10px;text-align:left}
.stack td.num{text-align:left}.stack td[data-l]::before{content:attr(data-l) ": ";font:600 11px var(--mono);color:var(--mute);text-transform:uppercase;letter-spacing:.05em}}
.check{margin-top:26px;max-width:540px}.check label{display:block;font:600 .9rem var(--sans);margin-bottom:6px}
.check .row{display:flex;gap:8px}.check input{flex:1;min-width:0;font:15px var(--mono);padding:11px 12px;border:1px solid var(--ink);border-radius:8px;background:var(--panel);color:var(--ink)}
.check input::placeholder{color:var(--mute)}.check .out{margin-top:10px;font-size:.93rem;min-height:1.6em;color:var(--soft)}
.check .out ul{list-style:none;margin:0;padding:0}.check .out li{padding:2px 0}.check .out a{font:600 .9rem var(--mono)}
.alt{margin-top:14px;font-size:.93rem;color:var(--soft)}
.tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--ink);margin-top:26px}
.tab{font:600 .95rem var(--sans);padding:10px 18px;border:1px solid transparent;border-bottom:0;border-radius:8px 8px 0 0;background:none;color:var(--soft);cursor:pointer}
.tab:hover{color:var(--ink)}.tab[aria-selected=true]{background:var(--ink);color:var(--paper)}
.panel{display:grid;grid-template-columns:minmax(0,.8fr) minmax(0,1.2fr);gap:32px;padding-top:26px;align-items:start}.panel[hidden]{display:none}
.panel h3{font-size:1.45rem;margin-bottom:10px}.panel p{color:var(--soft)}.panel pre{margin:0;max-height:420px;overflow:auto}
.cap{font:12px var(--mono);color:var(--mute);margin:0 0 8px}
.pw{position:relative;margin:14px 0}.pw pre{margin:0}.panel .pw{margin:0}
.cp{position:absolute;top:7px;right:7px;font:11px var(--mono);padding:4px 8px;border:1px solid var(--rule);border-radius:5px;background:var(--panel);color:var(--soft);cursor:pointer;opacity:.85}
.cp:hover{color:var(--stamp);border-color:var(--stamp);opacity:1}
.fset{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.fset+.fset{margin-top:8px}.fset span{font:600 11px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--mute);margin-right:4px}
.chipb{font:600 12.5px var(--mono);padding:6px 11px;border:1px solid var(--rule);border-radius:6px;background:var(--panel);color:var(--soft);cursor:pointer}
.chipb:hover{border-color:var(--ink);color:var(--ink)}.chipb[aria-pressed=true]{background:var(--ink);color:var(--paper);border-color:var(--ink)}
th button{all:unset;cursor:pointer;font:inherit;letter-spacing:inherit;text-transform:inherit}th button:hover{color:var(--ink)}th button:focus-visible{outline:2px solid var(--stamp);outline-offset:2px}
th[aria-sort] button{color:var(--ink)}th[aria-sort=ascending] button::after{content:" \2191"}th[aria-sort=descending] button::after{content:" \2193"}
.none{padding:22px 16px;color:var(--soft)}
details.sec>summary{cursor:pointer;list-style:none;display:flex;align-items:baseline;gap:10px}details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary h2{margin:0}details.sec>summary::after{content:"show";font:12px var(--mono);color:var(--mute)}details.sec[open]>summary::after{content:"hide"}
details.sec[open]>summary{margin-bottom:12px}
.chooser{display:grid;grid-template-columns:repeat(2,minmax(0,220px)) minmax(0,1fr);gap:20px;align-items:end;background:var(--panel);border:1px solid var(--rule);border-radius:12px;padding:20px 24px;margin-top:28px}
.chooser label{display:block;font:600 .88rem var(--sans);margin-bottom:6px}.chooser input{width:100%;font:16px var(--sans);padding:10px 12px;border:1px solid var(--ink);border-radius:8px;background:var(--paper);color:var(--ink)}
.chooser output{font-weight:600;padding-bottom:10px}.tier.pick{border:2px solid var(--stamp);padding:23px}.tier.pick h3::after{content:"fits";font:600 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--stamp);border:1px solid var(--stamp);border-radius:5px;padding:2px 7px;margin-left:10px;vertical-align:middle}
.faq summary{display:flex;justify-content:space-between;gap:16px;list-style:none}.faq summary::-webkit-details-marker{display:none}.faq summary::after{content:"+";font:400 1.3rem/1 var(--mono);color:var(--stamp)}.faq details[open] summary::after{content:"\2212"}
.toc a[aria-current]{color:var(--ink);box-shadow:inset 2px 0 0 var(--stamp);padding-left:10px}
.svc{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:36px;padding:36px 0;border-top:1px solid var(--rule);align-items:start}
.svc h2{font-size:1.6rem;margin-bottom:10px}.svc .facts{font:13px var(--mono);color:var(--mute);margin:14px 0}.svc .facts a{color:var(--mute)}
.svc h3{font:600 12px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:0 0 8px}.svc ul{margin:0 0 20px;padding-left:18px}.svc li{margin-bottom:6px;font-size:.95rem}
.svc .lim li{color:var(--soft)}.svc .price{font-weight:600;margin:0 0 14px}
@media (max-width:860px){.panel,.svc{grid-template-columns:minmax(0,1fr);gap:18px}.chooser{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){.check .row{flex-direction:column}.check .btn{text-align:center}.tab{padding:9px 12px}.toc a[aria-current]{box-shadow:0 2px 0 var(--stamp);padding-left:0}}
@media (prefers-reduced-motion:no-preference){.btn,.nav a.l,.tab,.chipb,.cp{transition:color .15s,background-color .15s,border-color .15s}.btn:active,.chipb:active,.tab:active{transform:translateY(1px)}}
"""

THEME_JS = (
    "(function(){var d=document.documentElement;try{var t=localStorage.getItem('warden-theme');if(t)d.dataset.theme=t}catch(e){}"
    "document.addEventListener('click',function(ev){var b=ev.target.closest('.tt');if(!b)return;"
    "var dark=d.dataset.theme==='dark'||(!d.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches);"
    "d.dataset.theme=dark?'light':'dark';try{localStorage.setItem('warden-theme',d.dataset.theme)}catch(e){}})})();"
)

# Runs on every page. Each block looks for its own elements and does nothing when they are absent.
# Repository text only ever reaches the page through textContent, never innerHTML.
SITE_JS = r"""
(function(){var D=document;function all(q,r){return [].slice.call((r||D).querySelectorAll(q))}
all('pre').forEach(function(p){var w=D.createElement('div');w.className='pw';p.parentNode.insertBefore(w,p);w.appendChild(p);
var b=D.createElement('button');b.type='button';b.className='cp';b.textContent='copy';b.setAttribute('aria-label','Copy to clipboard');w.appendChild(b);
b.addEventListener('click',function(){function done(t){b.textContent=t;setTimeout(function(){b.textContent='copy'},1600)}
if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(p.textContent).then(function(){done('copied')},function(){done('press Ctrl+C')})}
else{var r=D.createRange();r.selectNodeContents(p);var s=getSelection();s.removeAllRanges();s.addRange(r);done('selected')}})});
all('[role=tablist]').forEach(function(tl){var tabs=all('[role=tab]',tl);
function sel(t,f){tabs.forEach(function(x){var on=x===t;x.setAttribute('aria-selected',on);x.tabIndex=on?0:-1;D.getElementById(x.getAttribute('aria-controls')).hidden=!on});if(f)t.focus()}
tabs.forEach(function(t,i){t.addEventListener('click',function(){sel(t)});t.addEventListener('keydown',function(ev){var d=ev.key==='ArrowRight'?1:ev.key==='ArrowLeft'?-1:0;
if(d){ev.preventDefault();sel(tabs[(i+d+tabs.length)%tabs.length],1)}})});if(tabs.length)sel(tabs[0])});
var faq=all('.faq details');faq.forEach(function(d){d.addEventListener('toggle',function(){if(d.open)faq.forEach(function(o){if(o!==d)o.open=false})})});
var toc=D.querySelector('.toc');if(toc){var links={};all('a',toc).forEach(function(a){links[a.getAttribute('href').slice(1)]=a});
function mark(id){if(!links[id])return;for(var k in links)links[k].removeAttribute('aria-current');links[id].setAttribute('aria-current','true')}
function fromHash(){mark((location.hash||'').slice(1)||Object.keys(links)[0])}fromHash();window.addEventListener('hashchange',fromHash);
if('IntersectionObserver' in window){var io=new IntersectionObserver(function(es){es.forEach(function(en){if(en.isIntersecting)mark(en.target.id)})},{rootMargin:'0px 0px -70% 0px'});
for(var k in links){var h=D.getElementById(k);if(h)io.observe(h)}}}
var f=D.getElementById('chk');if(f){var inp=D.getElementById('repo'),out=D.getElementById('chkout'),idx=JSON.parse(D.getElementById('idx').textContent);
function norm(v){return v.trim().toLowerCase().replace(/^https?:\/\/(www\.)?github\.com\//,'').replace(/\.git$/,'').replace(/\/+$/,'')}
function show(){var q=norm(inp.value);out.textContent='';if(!q)return;var hits=idx.filter(function(s){return s.indexOf(q)>-1}).slice(0,5);
if(hits.length){var ul=D.createElement('ul');hits.forEach(function(s){var li=D.createElement('li'),a=D.createElement('a');a.href='r/'+s+'/';a.textContent=s;li.appendChild(a);ul.appendChild(li)});out.appendChild(ul)}
else{out.appendChild(D.createTextNode('Not in the registry yet. Scan it yourself: '));var c=D.createElement('code');c.textContent='warden scan '+q;out.appendChild(c)}}
inp.addEventListener('input',show);f.addEventListener('submit',function(ev){ev.preventDefault();var q=norm(inp.value);if(!q)return;
if(idx.indexOf(q)>-1)location.href='r/'+q+'/';else if(idx.some(function(s){return s.indexOf(q)>-1}))location.href='registry/?q='+encodeURIComponent(q);else show()})}
var dv=D.getElementById('devs'),rv=D.getElementById('revs');if(dv&&rv){var pick=D.getElementById('pick');
function plan(){var d=+dv.value||0,r=+rv.value||0,k,t;
if(r<=0){k='community';t='Community fits: you run the reviews yourselves with the free CLI.'}
else if(d<=25&&r<=15){k='team';t='Team fits: up to 25 developers and 15 reviewed approvals a month.'}
else if(d<=150&&r<=50){k='business';t='Business fits: up to 150 developers and 50 reviewed approvals a month.'}
else{k='';t='Larger than the listed plans. Ask about a custom pilot.'}
pick.textContent=t;all('.tier').forEach(function(x){x.classList.toggle('pick',x.dataset.plan===k)})}
dv.addEventListener('input',plan);rv.addEventListener('input',plan);plan()}
var q=D.getElementById('q'),tb=D.querySelector('#reg tbody');if(q&&tb){var rows=[].slice.call(tb.rows),cnt=D.getElementById('count'),none=D.getElementById('none'),st={k:'',s:''};
function run(){var t=(q.value||'').toLowerCase().trim(),n=0;rows.forEach(function(r){var ok=(!t||r.dataset.t.indexOf(t)>-1)&&(!st.k||r.dataset.k===st.k)&&(!st.s||r.dataset.s===st.s);r.hidden=!ok;if(ok)n++});
cnt.textContent=n+' of '+rows.length+' repositories';none.hidden=n>0}
q.addEventListener('input',run);
all('.chipb').forEach(function(b){b.addEventListener('click',function(){st[b.dataset.f]=b.dataset.v;all('.chipb').forEach(function(x){if(x.dataset.f===b.dataset.f)x.setAttribute('aria-pressed',x===b)});run()})});
all('#reg thead th').forEach(function(th,ci){var b=th.querySelector('button');if(!b)return;b.addEventListener('click',function(){var num=th.classList.contains('num'),cur=th.getAttribute('aria-sort');
var asc=cur?cur!=='ascending':!num;all('#reg thead th').forEach(function(x){x.removeAttribute('aria-sort')});th.setAttribute('aria-sort',asc?'ascending':'descending');
function val(r){var c=r.cells[ci],v=c.dataset.v!==undefined?c.dataset.v:c.textContent.trim();if(!num)return String(v).toLowerCase();var n=parseFloat(String(v).replace(/,/g,''));return isNaN(n)?-1:n}
rows.sort(function(a,z){var x=val(a),y=val(z);return(x<y?-1:x>y?1:0)*(asc?1:-1)});rows.forEach(function(r){tb.appendChild(r)})})});
try{var pq=new URLSearchParams(location.search).get('q');if(pq)q.value=pq}catch(e){}run()}
})();
"""


# ----------------------------------------------------------------------- layout
def _page(cfg: SiteConfig, *, title: str, description: str, body: str, depth: int, active: str = "", path: str = "", script: str = "") -> str:
    root = "../" * depth or "./"
    links = [("registry/", "Registry", "registry"), ("docs/", "Docs", "docs")]
    if cfg.extra.get("has_services"):
        links.append(("services/", "Services", "services"))
    links.append(("pricing/", "Pricing", "pricing"))
    nav = "".join(f"<a class='l' href='{root}{href}'" + (" aria-current='page'" if key == active else "") + f">{label}</a>" for href, label, key in links)
    canonical = f"{cfg.base_url}/{path}"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{e(title)}</title><meta name='description' content='{e(description)}'>"
        f"<link rel='canonical' href='{e(canonical)}'><meta property='og:title' content='{e(title)}'>"
        f"<meta property='og:description' content='{e(description)}'><meta property='og:type' content='website'><meta property='og:url' content='{e(canonical)}'>"
        "<meta name='color-scheme' content='light dark'><meta name='referrer' content='no-referrer'>"
        f"<style>{CSS}</style></head><body><a class='skip' href='#main'>Skip to content</a>"
        f"<header class='nav'><div class='wrap'><a class='brand' href='{root}'><i>W</i>{e(cfg.name)}</a>{nav}"
        f"<a class='l' href='{e(cfg.repo_url)}'>GitHub</a><button class='tt' type='button' aria-label='Switch colour theme'>theme</button></div></header>"
        f"<main id='main'>{body}</main>"
        f"<footer><div class='wrap'><div><p><b>{e(cfg.name)}</b> {e(__version__)}. MIT licensed.</p>"
        "<p>This site makes no third-party requests: no analytics, no web fonts, no trackers.</p></div>"
        f"<div><p><a href='{root}docs/#disclosure'>Disclosure policy</a> · <a href='{root}docs/#method'>How the registry works</a> · "
        f"<a href='{root}api/v1/index.json'>JSON API</a></p><p><a href='{e(cfg.security_url)}'>Report a problem with a listing</a></p></div></div></footer>"
        f"<script>{THEME_JS}{SITE_JS}{script}</script></body></html>"
    )


def _status_tag(view: dict[str, Any]) -> str:
    if view["verdict"] is None:
        return "<span class='tag muted'>not yet reviewed</span>"
    v = view["verdict"]
    return f"<span class='tag {e(v['level'])}'>{e(v['label'])}</span>"


def _entry_href(view: dict[str, Any]) -> str:
    return f"r/{view['source']}/"


def _reg_rows(views: list[dict[str, Any]], root: str) -> str:
    rows = []
    for v in views:
        desc = f"<span class='d'>{e(str(v['description'])[:140])}</span>" if v.get("description") else ""
        rows.append(
            f"<tr data-t='{e((v['source'] + ' ' + str(v.get('description') or '')).lower())}' data-k='{e(v['kind'])}' data-s='{e(v['state'])}'>"
            f"<td data-l='Repository' data-v='{e(v['source'])}'><a class='repo mono' href='{root}{e(_entry_href(v))}'>{e(v['source'])}</a>{desc}</td>"
            f"<td data-l='Kind'>{e(v['kind_label'])}</td><td data-l='Status'>{_status_tag(v)}</td>"
            f"<td class='num' data-l='Runs on its own'>{len(v['auto_runs'])}</td><td class='num' data-l='Processes'>{len(v['processes'])}</td>"
            f"<td class='num' data-l='Hosts'>{len(v['hosts'])}</td><td class='num' data-l='Stars'>{_n(v.get('stars'))}</td>"
            f"<td data-l='Scanned' class='mono' style='font-size:.82rem;white-space:nowrap'>{e(_date(v['scanned_at']))}</td></tr>")
    return "".join(rows)


_REG_COLS = [("Repository", ""), ("Kind", ""), ("Status", ""), ("Runs on its own", "num"), ("Processes", "num"), ("Hosts", "num"), ("Stars", "num"), ("Scanned", "")]


def _reg_head(sortable: bool = False) -> str:
    cells = "".join(f"<th{f' class={c!r}' if c else ''}>" + (f"<button type='button'>{label}</button>" if sortable else label) + "</th>" for label, c in _REG_COLS)
    return f"<thead><tr>{cells}</tr></thead>"


REG_HEAD = _reg_head()


def _totals(views: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "repos": len(views),
        "reviewed": sum(1 for v in views if v["state"] == "reviewed"),
        "auto_runs": sum(len(v["auto_runs"]) for v in views),
        "with_auto": sum(1 for v in views if v["auto_runs"]),
        "processes": sum(len(v["processes"]) for v in views),
        "with_processes": sum(1 for v in views if v["processes"]),
        "hosts": len({h for v in views for h in v["hosts"]}),
        "files": sum(int(v.get("files") or 0) for v in views),
        "matches": sum(int(v["matches_total"]) for v in views if v["state"] != "reviewed"),
    }


def _checks() -> int:
    return len(rules.LINE_RULES) + len(rules.STRUCTURAL_RULES) + len(rules.SECRET_PATTERNS)


# Walkthrough samples. The scan output is the real run printed in the README; the rest are the README's own examples.
_WALK_SCAN = """Static scan: 9 files, 21 findings, 4.6s
Agent review with claude-opus-5-5 (effort high, budget $5.00)
  agent: get_overview
  agent: list_findings
  agent: read scripts/setup.sh
  agent: read scripts/approve.js
  agent: read scripts/lib/helpers.sh
  ...
  agent: verdicts 21 confirmed
  agent: new finding  Remote script output from SessionStart hook flows into Claude's context at scripts/setup.sh:2
  agent: submit_assessment
Agent: 21 findings reviewed, 2 new, 17 turns, $0.22, 64.8s

 DO NOT INSTALL  risk score 100/100
 9 critical  8 high  3 medium  3 low
 Prompt-injection text found: agent dismissals of serious findings are ignored in the score.

 The plugin is named 'claude-official-tools' and says it "Formats code." It contains no formatting
 code. It is malware. As soon as a session starts, its SessionStart hook (hooks/hooks.json:8 ->
 scripts/setup.sh) does four things:
  - Downloads https://cdn.evil-updates.net/install.sh and runs it with bash (setup.sh:2).
  - Packs up your whole ~/.ssh directory, private keys included, and POSTs it to webhook.site (setup.sh:3).
  - Adds `source ~/.cache/.evil` to ~/.zshrc, so every new shell runs that file (setup.sh:4).
  - Sources a helper script that decodes and runs base64 text (scripts/lib/helpers.sh:2)."""
_WALK_GATE = """[policy]
mode = "allowlist"            # or "threshold"
max_verdict = "caution"
require_pinned = true
deny_categories = ["remote-code", "exfiltration", "persistence", "config-tampering"]

[[allow]]
source = "obra/superpowers"
commit = "22f0b463e7a5"
approved_by = "Dana Li"
approved_at = 2026-11-14
reason = "Read hooks and skills at this commit"

# Exit code 0 when everything is allowed, 1 when something is not, 2 when the policy is invalid.
# When upstream moves, the approval stops matching and the check fails with COMMIT-DRIFT."""
_WALK_WATCH = """alert    A new hook, monitor or server, a new high or critical finding, or a worse verdict
notice   New network hosts, new credential-like environment variables, or new lower-severity findings
none     Nothing the scanner tracks changed

# Findings are matched by rule, file and code, not by line number,
# so code that only moved is not reported as new.
# WARDEN_WEBHOOK_URL sends the result to an https Slack-compatible webhook."""
_WALK_PROVE = """evidence pack (folder and zip)
  the policy as enforced
  the decision for every enabled plugin
  the scan behind each decision
  a readable summary
  manifest.json with the SHA-256 of every file

# With WARDEN_EVIDENCE_KEY set, the manifest is signed with HMAC-SHA256.
# warden evidence --verify <folder> reports any file that changed, went missing or was added.
# Plugin Warden does not certify compliance."""


# ------------------------------------------------------------------------ pages
def _landing(cfg: SiteConfig, views: list[dict[str, Any]]) -> str:
    t = _totals(views)
    # The slip shows a real entry: the one with the most automatic entry points.
    sample = max(views, key=lambda v: (len(v["auto_runs"]), v.get("stars") or 0), default=None)
    slip = ""
    if sample and sample["auto_runs"]:
        items = "".join(f"<li><b>{e(a.get('when', ''))[:28]}</b><code>{e(str(a.get('what', ''))[:110])}</code></li>" for a in sample["auto_runs"][:4])
        more = len(sample["auto_runs"]) - 4
        slip = (f"<aside class='slip' aria-label='Example registry entry'><span class='stamp'>runs on its own</span>"
                f"<h3>{e(sample['source'])}</h3><div class='sub'>@ {e(str(sample['commit'])[:12])} · scanned {e(_date(sample['scanned_at']))}</div>"
                f"<ol>{items}</ol><div class='foot'>" + (f"and {more} more. " if more > 0 else "")
                + f"<a href='{e(_entry_href(sample))}'>Open the full entry</a></div></aside>")
    top = sorted(views, key=lambda v: -(v.get("stars") or 0))[:8]
    idx = json.dumps(sorted(v["source"] for v in views)).replace("<", "\\u003c")
    hero = (
        "<section class='hero'><div class='wrap'><div><div class='eyebrow'>Supply-chain security for AI coding agents</div>"
        "<h1>Know what a plugin will run before your team installs it.</h1>"
        "<p class='lede' style='margin-top:18px'>Claude Code plugins and MCP servers run with your full user access, outside the permission system. "
        "Plugin Warden reads the code first and shows what runs and when.</p>"
        "<form class='check' id='chk' action='registry/' method='get' role='search'><label for='repo'>Check a repository</label>"
        "<div class='row'><input id='repo' name='q' type='text' placeholder='owner/repo' autocomplete='off' autocapitalize='none' spellcheck='false' aria-describedby='chkout'>"
        "<button class='btn p' type='submit'>Check</button></div><div class='out' id='chkout' aria-live='polite'></div></form>"
        f"<script type='application/json' id='idx'>{idx}</script>"
        f"<p class='alt'>Or <a href='docs/#start'>install the CLI</a> and scan anything yourself.</p></div>{slip}</div></section>"
    )
    stats = (
        "<section class='band' style='padding-top:0;border:0'><div class='wrap'><div class='stats'>"
        f"<div><b>{t['repos']}</b><span>public plugin and MCP server repos tracked</span></div>"
        f"<div><b>{t['auto_runs']}</b><span>components that run on their own, across {t['with_auto']} of them</span></div>"
        f"<div><b>{t['processes']}</b><span>background processes started at session start</span></div>"
        f"<div><b>{_checks()}</b><span>built-in checks on every scan</span></div></div></div></section>"
    )
    why = (
        "<section class='band w'><div class='wrap'><h2>The install prompt does not show you this.</h2><div class='cols'>"
        "<div><h3>Hooks run outside the sandbox</h3><p>A hook fires on session start or on every tool call. It is a shell command with your access. "
        "Permission rules and the Bash sandbox govern Claude's own tools, not hooks.</p></div>"
        "<div><h3>Servers start in the background</h3><p>MCP and LSP servers launch as processes when a session starts. Many are fetched fresh from a package registry "
        "each time, with no version pin.</p></div>"
        "<div><h3>Approved today, different tomorrow</h3><p>A plugin that was clean when you reviewed it updates itself. Nobody on the team re-reads it. "
        "That is how a trusted dependency turns into an incident.</p></div></div></div></section>"
    )
    steps = [
        ("scan", "Scan", "Read it before you run it",
         f"Maps every hook, server, monitor and PATH executable, traces each to the files it runs, and applies {_checks()} checks. "
         "An optional read-only Claude agent confirms or dismisses each match with a cited reason.",
         "warden scan owner/repo", "Real output from the project README: the demo plugin, reviewed with Opus 5.5", _WALK_SCAN),
        ("gate", "Gate", "Enforce a policy in CI",
         "One TOML file says which plugins are approved, at which commit, by whom. A pull request that enables anything else fails, "
         "with the reason on the line that enabled it.",
         "warden check . --sarif warden.sarif", "The policy file, from the README", _WALK_GATE),
        ("watch", "Watch", "Catch the update that gains reach",
         "Each night it compares every approved plugin with its upstream. If an update adds a hook, a process or a serious finding, it opens an issue with the diff.",
         "warden watch --fail-on-alert", "What each level means, from the README", _WALK_WATCH),
        ("prove", "Prove", "Hand your auditor a pack",
         "Policy, decisions, the scan behind each one and a hashed manifest. Evidence that third-party agent software is reviewed before it runs.",
         "warden evidence . --period 2026-Q4", "What a pack holds, from the README", _WALK_PROVE),
    ]
    tabs = "".join(f"<button class='tab' type='button' role='tab' id='t-{k}' aria-controls='p-{k}' aria-selected='{'true' if n == 0 else 'false'}'>{label}</button>"
                   for n, (k, label, *_rest) in enumerate(steps))
    panels = "".join(
        f"<div class='panel' role='tabpanel' id='p-{k}' aria-labelledby='t-{k}'><div><h3>{title}</h3><p>{text}</p><pre><code>{e(cmd)}</code></pre></div>"
        f"<div><p class='cap'>{cap}</p><pre tabindex='0'><code>{e(sample)}</code></pre></div></div>" for k, _label, title, text, cmd, cap, sample in steps)
    jobs = (f"<section class='band'><div class='wrap'><h2>Four jobs, one tool.</h2><div class='tabs' role='tablist' aria-label='What Plugin Warden does'>{tabs}</div>{panels}</div></section>")
    reg = (
        "<section class='band w'><div class='wrap'><div class='head'>"
        f"<h2>{t['repos']} repositories, scanned in the open.</h2><a class='btn' href='registry/'>See all {t['repos']}</a></div>"
        "<p class='lede'>What each one runs on your machine, which processes it starts and which hosts its code names. "
        f"{t['reviewed']} {'has' if t['reviewed'] == 1 else 'have'} a completed agent review and a verdict. The rest show facts only, with no verdict, until they are reviewed.</p>"
        f"<div class='tw' style='margin-top:20px'><table class='stack'>{REG_HEAD}<tbody>{_reg_rows(top, '')}</tbody></table></div></div></section>"
    )
    more = "<a class='btn' href='services/'>Other services</a>" if cfg.extra.get("has_services") else "<a class='btn' href='docs/#teams'>Set it up in ten minutes</a>"
    teams = (
        "<section class='band'><div class='wrap'><h2>Free to run yourself. Paid when you want it reviewed for you.</h2>"
        "<p class='lede'>The CLI, the policy gate, the nightly watch and the evidence packs are open source and run in your own CI. "
        "The paid plans are a pilot. They add an agent review plus a human second read on every plugin your team approves.</p>"
        f"<div class='cta'><a class='btn p' href='pricing/'>See plans</a>{more}</div></div></section>"
    )
    return hero + stats + why + jobs + reg + teams


def _registry_page(cfg: SiteConfig, views: list[dict[str, Any]]) -> str:
    t = _totals(views)

    def chips(key: str, label: str, options: list[tuple[str, str]]) -> str:
        return (f"<div class='fset' role='group' aria-label='{label}'><span>{label}</span>"
                + "".join(f"<button class='chipb' type='button' data-f='{key}' data-v='{e(v)}' aria-pressed='{'true' if not v else 'false'}'>{e(text)}</button>" for v, text in options)
                + "</div>")

    kinds = [("", "All")] + [(k, label) for k, label in registry.KINDS.items() if any(v["kind"] == k for v in views)]
    states = [("", "Any"), ("reviewed", "Agent-reviewed"), ("static-only", "Not yet reviewed")]
    ordered = sorted(views, key=lambda v: (-(v.get("stars") or 0), v["source"]))
    return (
        "<div class='wrap'><div class='crumb'>registry</div><h1 style='font-size:clamp(1.9rem,4.4vw,2.9rem)'>The registry</h1>"
        f"<p class='lede' style='margin-top:12px'>{t['repos']} public Claude Code plugin, skill and MCP server repositories. "
        f"Across them: {t['auto_runs']} components that run on their own, {t['processes']} background processes and {t['hosts']} distinct network hosts named in code.</p>"
        "<div class='note'><p><b>How to read this.</b> A verdict appears only after a completed agent review. "
        f"\"Not yet reviewed\" means the static scan ran and its {t['matches']} rule matches are waiting for review. Rule matches are leads, not findings, "
        "so they are counted here and not shown. <a href='../docs/#method'>How the registry works</a>.</p></div>"
        "<div class='tools'><label class='skip' for='q'>Search</label><input id='q' type='search' placeholder='Search by repository or description' autocomplete='off'></div>"
        f"{chips('k', 'Kind', kinds)}{chips('s', 'Status', states)}<p class='count' id='count' aria-live='polite' style='margin-top:14px'></p>"
        f"<div class='tw'><table class='stack' id='reg'>{_reg_head(sortable=True)}<tbody>{_reg_rows(ordered, '../')}</tbody></table>"
        "<p class='none' id='none' hidden>No repository matches. Clear the search or pick another filter.</p></div>"
        "<p style='margin:24px 0 56px;color:var(--soft)'>Missing a repository? Add it to <code>registry/targets.toml</code> in a pull request. "
        "Maintainer of one listed here? See the <a href='../docs/#disclosure'>disclosure policy</a>.</p></div>"
    )


def _entry_page(cfg: SiteConfig, v: dict[str, Any]) -> str:
    root = "../../../"
    src = v["source"]
    parts: list[str] = []
    parts.append(f"<div class='wrap'><div class='crumb'><a href='{root}registry/'>registry</a> / {e(src)}</div>")
    parts.append(f"<div class='title'><div><h1 class='mono'>{e(src)}</h1>"
                 + (f"<p class='lede' style='margin-top:10px'>{e(str(v['description'])[:240])}</p>" if v.get("description") else "")
                 + f"</div><div>{_status_tag(v)}</div></div>")
    meta = [f"{e(v['kind_label'])}", f"commit <code>{e(str(v['commit'])[:12])}</code>", f"scanned {e(_date(v['scanned_at']))}",
            f"Plugin Warden {e(v['tool_version'])}"]
    if v.get("license"):
        meta.append(f"license {e(v['license'])}")
    parts.append(f"<p class='mono' style='font-size:.85rem;color:var(--mute);max-width:none'>{' · '.join(meta)} · <a href='{e(v['url'])}'>source</a></p>")

    if v["state"] != "reviewed":
        parts.append(
            "<div class='note'><p><b>Not yet reviewed, so no verdict.</b> The static scan has run. "
            f"It produced {v['matches_total']} rule matches that an agent or a person still has to confirm or dismiss. "
            "Rule matches are leads: on reviewed repositories most are dismissed. Everything below is a fact about what the code does, not a judgement of it.</p></div>")
    else:
        vd = v["verdict"]
        a = v.get("agent") or {}
        parts.append(f"<div class='note'><p><b>{e(vd['label'])}</b>, risk score {e(vd['score'])} of 100. "
                     f"Agent review completed with {e(a.get('model'))}: {e(a.get('reviewed'))} matches reviewed, {e(v['dismissed'])} dismissed with a cited reason, "
                     f"{e(a.get('new_findings'))} added that the rules missed.</p></div>")

    comp = v["component_counts"]
    parts.append(
        "<div class='kv'>"
        f"<div><b>{len(v['auto_runs'])}</b><span>run on their own</span></div><div><b>{len(v['processes'])}</b><span>background processes</span></div>"
        f"<div><b>{len(v['hosts'])}</b><span>network hosts in code</span></div><div><b>{_n(v.get('files'))}</b><span>files read</span></div>"
        f"<div><b>{e(v['plugins'])}</b><span>plugin roots</span></div><div><b>{_n(v.get('stars'))}</b><span>GitHub stars</span></div></div>")

    parts.append("<div class='sec'><h2>What runs on its own</h2>")
    if v["auto_runs"]:
        rows = "".join(
            f"<tr><td data-l='When'>{e(a.get('when', ''))}</td><td data-l='Type'>{e(a.get('type', ''))}</td>"
            f"<td data-l='What runs'><code>{e(a.get('what', ''))}</code></td><td data-l='Declared in'><code>{e(a.get('file', ''))}</code></td></tr>"
            for a in v["auto_runs"][:60])
        more = f"<p class='count' style='margin-top:8px'>Showing 60 of {len(v['auto_runs'])}.</p>" if len(v["auto_runs"]) > 60 else ""
        parts.append("<p>These start without anyone asking, with the access of the person running Claude Code. Permission rules and the Bash sandbox do not apply to them.</p>"
                     f"<div class='tw'><table class='stack'><thead><tr><th>When</th><th>Type</th><th>What runs</th><th>Declared in</th></tr></thead><tbody>{rows}</tbody></table></div>{more}")
    else:
        parts.append("<p>Nothing. No hooks, monitors, status lines, MCP or LSP servers were found in this repository's plugin config.</p>")
    parts.append("</div>")

    if v["processes"]:
        rows = "".join(f"<tr><td data-l='Name'><code>{e(p.get('name', ''))}</code></td><td data-l='Kind'>{e(p.get('kind', ''))}</td>"
                       f"<td data-l='Launch'><code>{e(p.get('launch', ''))}</code></td><td data-l='Declared in'><code>{e(p.get('file', ''))}</code></td></tr>" for p in v["processes"][:40])
        parts.append(f"<details class='sec' open><summary><h2>Background processes</h2></summary><div class='tw'><table class='stack'><thead><tr><th>Name</th><th>Kind</th><th>Launch</th><th>Declared in</th></tr></thead><tbody>{rows}</tbody></table></div></details>")
    if v["hosts"]:
        parts.append("<details class='sec' open><summary><h2>Network hosts named in code</h2></summary><p>Hosts that appear in code that makes requests. Being listed is not a problem in itself: it is what you would allow through a firewall.</p>"
                     f"<div class='chips'>{''.join(f'<span class=chip>{e(h)}</span>' for h in v['hosts'][:80])}</div></details>")
    if v["env_vars"]:
        parts.append("<details class='sec' open><summary><h2>Credential-like environment variables read</h2></summary>"
                     f"<div class='chips'>{''.join(f'<span class=chip>{e(h)}</span>' for h in v['env_vars'][:60])}</div></details>")
    if comp:
        parts.append("<details class='sec'><summary><h2>Components Claude Code would load</h2></summary><div class='chips'>"
                     + "".join(f"<span class='chip'>{e(k.replace('_', ' '))} {e(n)}</span>" for k, n in comp.items()) + "</div></details>")

    ch = v.get("change")
    if ch:
        lines = []
        for a in ch["new_auto_runs"][:10]:
            lines.append(f"<li>New automatic entry point: {e(a.get('type', ''))} on {e(a.get('when', ''))}, <code>{e(str(a.get('what', ''))[:140])}</code></li>")
        for p in ch["new_processes"][:10]:
            lines.append(f"<li>New background process: {e(p.get('kind', ''))} <code>{e(p.get('name', ''))}</code></li>")
        if ch["new_hosts"]:
            lines.append("<li>New hosts: " + ", ".join(f"<code>{e(h)}</code>" for h in ch["new_hosts"][:12]) + "</li>")
        if ch["removed_auto_runs"]:
            lines.append(f"<li>{e(ch['removed_auto_runs'])} automatic entry point(s) removed</li>")
        body = f"<ul>{''.join(lines)}</ul>" if lines else "<p>No change in what runs on its own, which processes start or which hosts appear.</p>"
        parts.append(f"<div class='sec'><h2>Since the previous scan</h2><p class='mono' style='font-size:.85rem;color:var(--mute)'>"
                     f"{e(str(ch['from'])[:12])} to {e(str(ch['to'])[:12])}</p>{body}</div>")

    parts.append("<div class='sec'><h2>Findings</h2>")
    if v["state"] != "reviewed":
        m = v["matches"]
        chips = "".join(f"<span class='chip'>{e(m[s])} {s}</span>" for s in SEVERITIES if m.get(s))
        parts.append(f"<p>{v['matches_total']} rule matches are waiting for review. They are not published until someone has confirmed them, "
                     "because an unreviewed match is not a finding.</p>" + (f"<div class='chips'>{chips}</div>" if chips else "")
                     + f"<p style='margin-top:14px'>Review it yourself: <code>warden scan {e(src)}</code></p>")
    else:
        if v["withheld"]:
            d = v.get("disclosure")
            when = f" Details are due on {e(d['publish_date'])}." if d and d.get("publish_date") else ""
            parts.append(f"<div class='note'><p><b>{v['withheld']} confirmed high or critical finding(s) are withheld</b> while the maintainer is notified.{when} "
                         f"<a href='{root}docs/#disclosure'>Disclosure policy</a>.</p></div>")
        if v.get("summary"):
            parts.append("".join(f"<p>{e(p)}</p>" for p in str(v["summary"]).split("\n") if p.strip()))
        if not v["findings"] and not v["withheld"]:
            parts.append("<p>No findings survived review.</p>")
        for f in v["findings"]:
            parts.append(f"<article class='find {e(f['severity'])}'><h3>{e(f['title'])}</h3>"
                         f"<div class='m'>{e(f['severity'])} · {e(f['location'])} · {e(f['rule_id'])} · {e(f['category_label'])}</div>"
                         f"<p>{e(f['why'])}</p><p><b>Where to fix.</b> {e(f['fix'])}</p></article>")
    parts.append("</div>")

    hist = "".join(f"<tr><td data-l='Commit'><code>{e(str(h.get('commit'))[:12])}</code></td><td data-l='Scanned'>{e(_date(h.get('scanned_at')))}</td>"
                   f"<td data-l='Status'>{e(h.get('level') or 'not yet reviewed')}</td><td class='num' data-l='Runs on its own'>{e(h.get('auto_runs'))}</td></tr>"
                   for h in reversed(v["history"][-12:]))
    parts.append(f"<details class='sec'><summary><h2>Scan history</h2></summary><div class='tw'><table class='stack'><thead><tr><th>Commit</th><th>Scanned</th><th>Status</th>"
                 f"<th class='num'>Runs on its own</th></tr></thead><tbody>{hist}</tbody></table></div></details>")

    badge_url = f"{cfg.base_url}/badge/{src}.svg"
    page_url = f"{cfg.base_url}/r/{src}/"
    parts.append("<div class='sec'><h2>Badge and data</h2>"
                 f"<p><img src='{root}badge/{e(src)}.svg' alt='Plugin Warden status for {e(src)}' height='20'></p>"
                 f"<pre><code>[![Plugin Warden]({e(badge_url)})]({e(page_url)})</code></pre>"
                 f"<p>Machine-readable: <a href='{root}api/v1/r/{e(src)}.json'>api/v1/r/{e(src)}.json</a></p>"
                 f"<p style='color:var(--soft)'>Maintainer of this repository and something here is wrong? <a href='{e(cfg.security_url)}'>Tell us</a> and it gets fixed or removed. "
                 f"<a href='{root}docs/#disclosure'>Disclosure policy</a>.</p></div>")
    parts.append("<div style='height:56px'></div></div>")
    return "".join(parts)


def _pricing_page(cfg: SiteConfig) -> str:
    def cta(url: str, label: str) -> str:
        return f"<a class='btn p' href='{e(url or cfg.contact_url)}'>{e(label if url else 'Request a pilot')}</a>"

    return (
        "<div class='wrap'><div class='crumb'>pricing</div><h1 style='font-size:clamp(1.9rem,4.4vw,2.9rem)'>Free to run. Paid to have it reviewed.</h1>"
        "<p class='lede' style='margin-top:12px'>Everything that runs on your machines is open source. The paid plans are a review service on top: "
        "we read the plugins your team wants, and we respond when one of them changes.</p>"
        "<div class='chooser'><div><label for='devs'>Developers using Claude Code</label><input id='devs' type='number' min='1' max='5000' value='20' inputmode='numeric'></div>"
        "<div><label for='revs'>Plugins to review a month</label><input id='revs' type='number' min='0' max='500' value='10' inputmode='numeric'></div>"
        "<output id='pick' for='devs revs' aria-live='polite'>Enter your team size to see which plan fits.</output></div>"
        "<div class='tiers'>"
        "<div class='tier' data-plan='community'><h3>Community</h3><div class='price'>$0</div><p style='color:var(--soft)'>For individuals and any team that wants to run it themselves.</p><ul>"
        f"<li>The full CLI, MIT licensed, {_checks()} checks</li><li>Agent review with your own Anthropic API key</li>"
        "<li>Policy file, CI gate and SARIF output</li><li>Nightly watch and update diffs</li><li>Audit evidence packs</li><li>Public registry, badges and JSON API</li></ul>"
        f"<a class='btn' href='{e(cfg.repo_url)}'>Get it on GitHub</a></div>"
        f"<div class='tier' data-plan='team'><h3>Team</h3><div class='price'>${cfg.team_price}<small> / month</small></div><p style='color:var(--soft)'>Up to 25 developers. Pilot pricing.</p><ul>"
        "<li>Everything in Community</li><li>Reviewed approvals: agent review plus a human second read, 15 plugins a month</li>"
        "<li>Update reviews within one business day when an approved plugin gains reach</li><li>Private reports that never enter the public registry</li>"
        "<li>Policy and CI set up in your GitHub organisation</li><li>Email support</li></ul>"
        f"{cta(cfg.team_checkout_url, 'Start Team')}</div>"
        f"<div class='tier' data-plan='business'><h3>Business</h3><div class='price'>${cfg.business_price}<small> / month</small></div><p style='color:var(--soft)'>Up to 150 developers. Pilot pricing.</p><ul>"
        "<li>Everything in Team</li><li>50 reviewed approvals a month</li><li>Custom rules for your internal marketplace</li>"
        "<li>Quarterly evidence pack with a walkthrough for your auditor</li><li>Shared channel for questions and alerts</li></ul>"
        f"{cta(cfg.business_checkout_url, 'Start Business')}</div></div>"
        f"<p style='margin-top:20px;color:var(--soft)'>Larger than 150 developers, or need on-premises review? <a href='{e(cfg.contact_url)}'>Talk to us</a>.</p>"
        "<div class='sec faq'><h2>Questions</h2>"
        "<details><summary>What do I get from a paid plan that the free CLI does not do?</summary><p>People and a response time. The CLI gives you a scan and a gate. "
        "A reviewed approval means the agent review was run for you, a person read the result and the code behind every confirmed finding, and you got a written recommendation "
        "you can paste into the policy file as the approval reason.</p></details>"
        "<details><summary>Does my code leave my network?</summary><p>No. The gate, the watch and the evidence pack run in your own CI. "
        "Plugin Warden scans the third-party plugin repositories you name, not your source code. Reviews are of those public or vendor repositories.</p></details>"
        "<details><summary>What does \"pilot pricing\" mean?</summary><p>The paid plans are new and are offered to a small number of design partners. "
        "There are no paying customers yet. You can cancel at any time and keep everything the open-source tool does.</p></details>"
        "<details><summary>Is a clean scan a guarantee?</summary><p>No, and nobody honest will tell you otherwise. Static analysis reads code and does not run it. "
        "A clean result means the checks that ran found nothing and a reviewer agreed. The watch exists because the code can change after that.</p></details>"
        "<details><summary>Do you support tools other than Claude Code?</summary><p>MCP servers are scanned wherever they are used. "
        "The plugin, hook and skill checks are written for Claude Code's formats today.</p></details></div><div style='height:56px'></div></div>"
    )


def _docs_page(cfg: SiteConfig) -> str:
    repo = e(cfg.repo_url)
    toc = [("start", "Quick start"), ("verdicts", "Verdicts"), ("teams", "Set up for a team"), ("policy", "Policy file"), ("gate", "CI gate"),
           ("watch", "Watching updates"), ("evidence", "Evidence packs"), ("method", "How the registry works"), ("disclosure", "Disclosure policy"),
           ("api", "Badges and API"), ("limits", "Limits")]
    nav = "".join(f"<a href='#{k}'>{label}</a>" for k, label in toc)
    body = f"""
<h2 id='start'>Quick start</h2>
<p>Requires Python 3.12 or newer and <a href='https://docs.astral.sh/uv/'>uv</a>.</p>
<pre><code>uvx --from git+{repo} warden scan owner/repo --no-agent</code></pre>
<p>That is a static scan: no API key, no network calls beyond fetching the repository. Nothing from the repository is executed, installed or imported.
For the agent review, set <code>ANTHROPIC_API_KEY</code> and drop <code>--no-agent</code>.</p>
<pre><code>git clone {repo}.git
cd plugin-warden &amp;&amp; uv sync
uv run warden scan obra/superpowers        # scan a GitHub repo
uv run warden installed                    # scan every plugin you already have
uv run warden rules                        # list every check</code></pre>

<h2 id='verdicts'>Verdicts</h2>
<p>The verdict is computed from the findings, never from a model's opinion. Critical findings score 40, high 15, medium 5, low 1 (lows capped at 10 in total).</p>
<div class='tw'><table><thead><tr><th>Verdict</th><th>When</th></tr></thead><tbody>
<tr><td><span class='tag low'>Low risk</span></td><td>Nothing of medium severity or above, score under 10</td></tr>
<tr><td><span class='tag caution'>Install with precautions</span></td><td>A medium finding, or score 10 or more</td></tr>
<tr><td><span class='tag review'>Review before installing</span></td><td>Any high finding, or score 40 or more</td></tr>
<tr><td><span class='tag block'>Do not install</span></td><td>Any critical finding</td></tr></tbody></table></div>
<p>If the repository contains text aimed at a model, the agent's dismissals of high and critical findings are ignored in the score.
A model that may have been steered cannot talk the verdict down.</p>

<h2 id='teams'>Set up for a team</h2>
<p>Ten minutes, in the repository whose <code>.claude/settings.json</code> your team shares.</p>
<pre><code>warden init                                  # writes warden-policy.toml and .github/workflows/warden.yml
warden approve obra/superpowers --by "Dana" --reason "Read hooks and skills at this commit"
warden check                                 # passes when every enabled plugin is approved
git add warden-policy.toml .github/workflows/warden.yml &amp;&amp; git commit -m "Add plugin policy"</code></pre>
<p>From then on: a pull request that enables an unapproved plugin fails, a nightly job tells you when an approved plugin changes upstream,
and a monthly job builds an evidence pack.</p>

<h2 id='policy'>Policy file</h2>
<p>One TOML file in git. Changes to it go through review like any other change, which is the point: the approval history is the commit history.</p>
<pre><code>[policy]
mode = "allowlist"            # or "threshold"
max_verdict = "caution"       # low, caution, review, block
require_pinned = true
deny_categories = ["remote-code", "exfiltration", "persistence", "config-tampering"]

[[allow]]
source = "obra/superpowers"
commit = "22f0b463e7a5..."
approved_by = "Dana"
approved_at = 2026-11-14
reason = "Read hooks and skills at this commit"

[[exception]]
source = "vendor/tool"
rule = "MCP-UNPINNED"
approved_by = "Dana"
reason = "Vendor pins on their side; revisit next quarter"
expires = 2027-02-01</code></pre>
<div class='tw'><table><thead><tr><th>Mode</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>allowlist</code></td><td>Only plugins with an <code>[[allow]]</code> entry may be enabled. An entry pinned to the scanned commit is a human approval of exactly that code, and stands in for the thresholds.</td></tr>
<tr><td><code>threshold</code></td><td>Any plugin may be enabled while its scan stays inside <code>max_verdict</code>, <code>deny_categories</code>, <code>deny_rules</code>, <code>allow_auto_run</code> and <code>allowed_hosts</code>.</td></tr></tbody></table></div>
<p>An exception accepts one rule or category for one plugin. It must carry a reason and an end date, so it is looked at again.</p>
<p>Why a check failed:</p>
<div class='tw'><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>NOT-ALLOWLISTED</code></td><td>Enabled in settings with no approval in the policy</td></tr>
<tr><td><code>COMMIT-DRIFT</code></td><td>The code is no longer the commit that was approved</td></tr>
<tr><td><code>UNPINNED</code> / <code>APPROVAL-EXPIRED</code></td><td>The approval names no commit, or its end date has passed</td></tr>
<tr><td><code>VERDICT</code> / <code>CATEGORY</code> / <code>RULE</code></td><td>The scan is outside the thresholds</td></tr>
<tr><td><code>AUTO-RUN</code> / <code>HOST</code></td><td>The plugin runs code on its own, or names a host outside the allowed list</td></tr>
<tr><td><code>UNRESOLVED</code> / <code>SCAN-FAILED</code></td><td>Its source cannot be found or fetched. What cannot be checked is not allowed.</td></tr>
<tr><td><code>DENIED</code></td><td>On the deny list</td></tr></tbody></table></div>

<h2 id='gate'>CI gate</h2>
<p><code>warden check</code> reads <code>enabledPlugins</code> and <code>extraKnownMarketplaces</code> from the project's settings, resolves each plugin to its repository,
scans it, and evaluates the policy. It also scans the project's own <code>.mcp.json</code> and settings hooks against the thresholds, because those run on every teammate's machine too.</p>
<pre><code>- uses: astral-sh/setup-uv@v6
- run: uvx --from git+{repo}@v{e(__version__)} warden check . --sarif warden.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: warden.sarif</code></pre>
<p>Exit code 0 when everything is allowed, 1 when something is not, 2 when the policy file is broken. With SARIF uploaded,
a failure appears on the settings line that enabled the plugin.</p>

<h2 id='watch'>Watching updates</h2>
<p><code>warden watch</code> asks each approved repository for its current commit. When one has moved, it scans both the approved commit and the new one and compares them.
Findings are matched by rule, file and code, not by line number, so code that only moved is not reported as new.</p>
<div class='tw'><table><thead><tr><th>Level</th><th>Raised when</th></tr></thead><tbody>
<tr><td><b>alert</b></td><td>A new hook, monitor or server; a new high or critical finding; or a worse verdict. Review before moving the pin.</td></tr>
<tr><td><b>notice</b></td><td>New network hosts, new credential-like environment variables, or new lower-severity findings</td></tr>
<tr><td><b>none</b></td><td>The update did not change anything the scanner tracks</td></tr></tbody></table></div>
<p>Set <code>WARDEN_WEBHOOK_URL</code> to an https Slack-compatible webhook to be told. The workflow from <code>warden init</code> opens a GitHub issue on an alert.</p>

<h2 id='evidence'>Evidence packs</h2>
<p><code>warden evidence</code> writes a folder and a zip: the policy as enforced, the decision for every enabled plugin, the scan behind each decision,
a readable summary, and <code>manifest.json</code> with the SHA-256 of every file. With <code>WARDEN_EVIDENCE_KEY</code> set, the manifest is signed with HMAC-SHA256.
Check a pack later with <code>warden evidence --verify &lt;folder&gt;</code>.</p>
<p>Teams commonly map this to vendor-risk and change-management controls such as SOC 2 CC9.2 and CC8.1, and ISO/IEC 27001:2022 A.5.19, A.5.21 and A.8.19.
That mapping is yours to make with your auditor. Plugin Warden does not certify compliance.</p>

<h2 id='method'>How the registry works</h2>
<p>The registry scans a list of well-known repositories (<code>registry/targets.toml</code>) and keeps the history of each. Two rules decide what it publishes.</p>
<ol><li><b>A static-only scan gets no verdict.</b> Rule matches are leads. On the four repositories in the project README, the agent dismissed 86 of 131 matches with a cited reason.
So without a completed agent review, an entry shows what the code does (what runs on its own, which processes start, which hosts appear) and how many matches are waiting. Nothing more.</li>
<li><b>Serious confirmed findings wait for the maintainer.</b> See the disclosure policy below.</li></ol>
<p>A listing is not an endorsement and not an accusation. Every entry names the exact commit scanned and can be reproduced with <code>warden scan owner/repo@commit</code>.</p>

<h2 id='disclosure'>Disclosure policy</h2>
<ol><li>When a review confirms a high or critical finding, the maintainer is told privately first, through the repository's security advisory channel where one exists.</li>
<li>The registry entry shows that findings are withheld, and the date details are due. It does not describe them.</li>
<li>Details are published {registry.DEFAULT_WINDOW_DAYS} days after notification, or as soon as a fix ships, whichever comes first. A maintainer who needs longer can ask.</li>
<li>Medium and low findings, and facts about what a plugin runs, are published with the review.</li>
<li>If an entry is wrong, <a href='{e(cfg.security_url)}'>report it</a>. Corrections are made in the open, in the registry's git history.</li></ol>

<h2 id='api'>Badges and API</h2>
<pre><code>{e(cfg.base_url)}/badge/OWNER/REPO.svg          # status badge
{e(cfg.base_url)}/api/v1/index.json             # every entry, summary fields
{e(cfg.base_url)}/api/v1/r/OWNER/REPO.json      # one entry, everything the page shows</code></pre>
<p>Owner and repository names are lower case in these paths. The API is static JSON, rebuilt with the site. It carries the same published view as the pages, with the same rules.</p>

<h2 id='limits'>Limits</h2>
<ul><li>Static analysis reads code and does not run it. Behaviour assembled at run time may only show up as "makes network calls" or "decodes and runs data".</li>
<li>The agent reviews within a budget. If it stops early the report says so.</li>
<li>Settings can limit Claude's own tools. They cannot contain a hook or a server process. The only complete control for those is not enabling the plugin.</li>
<li>A clean report is not a guarantee. It means the checks that ran found nothing, and the reviewer agreed.</li>
<li>No scanner checks for everything. <a href='{repo}/blob/main/docs/coverage.md'>The coverage document</a> lists what the rules look for, the benchmark results,
six evasions they are known to miss and ten kinds of thing they cannot catch.</li></ul>
"""
    return (f"<div class='wrap'><div class='doc'><nav class='toc' aria-label='On this page'>{nav}</nav><div><div class='crumb' style='margin-top:0'>docs</div>"
            f"<h1 style='font-size:clamp(1.9rem,4.4vw,2.9rem);margin-bottom:28px'>Documentation</h1>{body}</div></div></div>")


def load_services(path: Path) -> dict[str, Any] | None:
    """registry/services.toml, validated. None when the file does not exist."""
    if not path.is_file():
        return None
    data = tomllib.loads(path.read_text())
    services = data.get("service") or []
    for sv in services:
        for key in ("id", "name", "tool", "source_url", "tests", "status", "summary", "delivers", "limits"):
            if not sv.get(key):
                raise registry.RegistryError(f"services.toml: service {sv.get('id') or sv.get('name') or '?'} is missing {key}")
        if not str(sv["source_url"]).startswith("https://"):
            raise registry.RegistryError(f"services.toml: {sv['id']} source_url must be an https URL")
        if not isinstance(sv["tests"], int) or sv["tests"] <= 0:
            raise registry.RegistryError(f"services.toml: {sv['id']} tests must be a positive number")
    if not services:
        return None
    if not data.get("checked"):
        raise registry.RegistryError("services.toml: checked (the date the test suites were re-run) is required")
    return {"checked": str(data["checked"]), "services": services}


def _services_page(cfg: SiteConfig, data: dict[str, Any]) -> str:
    blocks = []
    for sv in data["services"]:
        pilot = sv["status"] == "pilot"
        price = f"<p class='price'>{e(sv['price'])}</p>" if sv.get("price") else ""
        needs = ("<h3>What we need from you</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in sv["needs"]) + "</ul>") if sv.get("needs") else ""
        blocks.append(
            f"<section class='svc' id='{e(sv['id'])}'><div><h2>{e(sv['name'])}</h2>"
            + (f"<p><span class='tag caution'>{'paid pilot' if pilot else e(sv['status'])}</span></p>")
            + f"<p>{e(sv['summary'])}</p>"
            f"<p class='facts'>Delivered with <a href='{e(sv['source_url'])}'>{e(sv['tool'])}</a> · {e(sv['tests'])} {e(sv.get('tests_note') or 'tests')} passed on {e(data['checked'])} · "
            f"<a href='{e(sv['source_url'])}'>source</a></p>{price}"
            f"<a class='btn' href='{e(cfg.contact_url)}'>Request a pilot</a></div>"
            "<div><h3>What you get</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in sv["delivers"]) + "</ul>"
            "<h3>Limits</h3><ul class='lim'>" + "".join(f"<li>{e(x)}</li>" for x in sv["limits"]) + f"</ul>{needs}</div></section>")
    return (
        "<div class='wrap'><div class='crumb'>services</div><h1 style='font-size:clamp(1.9rem,4.4vw,2.9rem)'>Services</h1>"
        f"<p class='lede' style='margin-top:12px'>{len(data['services'])} services, each delivered with an open-source tool you can read and run yourself. "
        "One person does the work, and every limit is written down before you start.</p>"
        "<div class='note'><p><b>These are pilots.</b> There are no paying customers yet, so there are no case studies or testimonials here. "
        f"A service is listed only if its tool's test suite was re-run and passed. That was last done on {e(data['checked'])}.</p></div>"
        + "".join(blocks) + "<div style='height:56px'></div></div>")


# ----------------------------------------------------------------------- assets
_BADGE_COLOURS = {"low": "#2c6a4b", "caution": "#8f5a00", "review": "#b3261e", "block": "#7a1410", "muted": "#6a6558"}


def badge_svg(view: dict[str, Any]) -> str:
    message, key = registry.badge_text(view)
    label = "plugin warden"
    lw, mw = 8 + len(label) * 6.6, 8 + len(message) * 6.6
    w = round(lw + mw)
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='20' role='img' aria-label='{e(label)}: {e(message)}'>"
        f"<title>{e(label)}: {e(message)}</title><rect width='{w}' height='20' rx='3' fill='#1a1814'/>"
        f"<rect x='{round(lw)}' width='{round(mw)}' height='20' rx='3' fill='{_BADGE_COLOURS[key]}'/>"
        f"<rect x='{round(lw)}' width='4' height='20' fill='{_BADGE_COLOURS[key]}'/>"
        "<g fill='#fff' font-family='Verdana,DejaVu Sans,sans-serif' font-size='11'>"
        f"<text x='{round(lw / 2)}' y='14' text-anchor='middle'>{e(label)}</text>"
        f"<text x='{round(lw + mw / 2)}' y='14' text-anchor='middle'>{e(message)}</text></g></svg>"
    )


def _index_row(v: dict[str, Any], cfg: SiteConfig) -> dict[str, Any]:
    return {"source": v["source"], "kind": v["kind"], "state": v["state"], "verdict": v["verdict"], "commit": v["commit"],
            "scanned_at": v["scanned_at"], "auto_runs": len(v["auto_runs"]), "processes": len(v["processes"]), "hosts": len(v["hosts"]),
            "stars": v.get("stars"), "page": f"{cfg.base_url}/r/{v['source']}/", "api": f"{cfg.base_url}/api/v1/r/{v['source']}.json"}


def build(entries: list[Entry], disclosures: dict[str, Disclosure], out: Path, cfg: SiteConfig | None = None, today: date | None = None,
          services: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or SiteConfig()
    cfg.extra["has_services"] = bool(services)
    today = today or datetime.now(UTC).date()
    views = [registry.public_view(en, disclosures.get(en.key), today) for en in entries]
    views.sort(key=lambda v: v["source"])
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    pages = 0

    def write(rel: str, text: str) -> None:
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    t = _totals(views)
    write("index.html", _page(cfg, title=f"{cfg.name}: know what a plugin runs before you install it",
                              description=f"Supply-chain security for Claude Code plugins and MCP servers. {t['repos']} public repositories scanned in the open, "
                                          "a policy gate for CI, update monitoring and audit evidence.",
                              body=_landing(cfg, views), depth=0, path=""))
    write("registry/index.html", _page(cfg, title=f"Registry: {t['repos']} plugin and MCP server repositories | {cfg.name}",
                                       description="What each public Claude Code plugin and MCP server repository runs on your machine, which processes it starts and which hosts it names.",
                                       body=_registry_page(cfg, views), depth=1, active="registry", path="registry/"))
    write("pricing/index.html", _page(cfg, title=f"Pricing | {cfg.name}", description="Free and open source to run yourself. Paid plans add reviewed approvals and a response when an approved plugin changes.",
                                      body=_pricing_page(cfg), depth=1, active="pricing", path="pricing/"))
    write("docs/index.html", _page(cfg, title=f"Documentation | {cfg.name}", description="Install the CLI, write a policy, gate pull requests, watch approved plugins and build audit evidence.",
                                   body=_docs_page(cfg), depth=1, active="docs", path="docs/"))
    write("404.html", _page(cfg, title=f"Not found | {cfg.name}", description="Page not found.",
                            body=f"<div class='wrap' style='padding:80px 20px'><h1>Nothing here.</h1><p class='lede' style='margin-top:14px'>Try the <a href='{e(cfg.base_url)}/registry/'>registry</a>.</p></div>",
                            depth=0, path="404.html"))
    pages += 5
    if services:
        write("services/index.html", _page(cfg, title=f"Services | {cfg.name}",
                                           description="Security services delivered with open-source tools: plugin and MCP server review, reported-email triage, "
                                                       "external exposure inventory and SSH access log review. Paid pilots, limits stated.",
                                           body=_services_page(cfg, services), depth=1, active="services", path="services/"))
        pages += 1
    for v in views:
        desc = (f"What {v['source']} runs on your machine: {len(v['auto_runs'])} automatic entry points, {len(v['processes'])} background processes, "
                f"{len(v['hosts'])} network hosts. Scanned at {str(v['commit'])[:12]}.")
        write(f"r/{v['source']}/index.html", _page(cfg, title=f"{v['source']} | {cfg.name} registry", description=desc, body=_entry_page(cfg, v),
                                                   depth=3, active="registry", path=f"r/{v['source']}/"))
        write(f"badge/{v['source']}.svg", badge_svg(v))
        write(f"api/v1/r/{v['source']}.json", json.dumps(v, indent=1, default=str) + "\n")
        pages += 1
    write("api/v1/index.json", json.dumps({"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "tool_version": __version__,
                                           "totals": t, "entries": [_index_row(v, cfg) for v in views]}, indent=1) + "\n")
    urls = ["", "registry/", "docs/", "pricing/"] + (["services/"] if services else []) + [f"r/{v['source']}/" for v in views]
    write("sitemap.xml", "<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
          + "".join(f"<url><loc>{e(cfg.base_url)}/{e(u)}</loc></url>" for u in urls) + "</urlset>\n")
    write("robots.txt", f"User-agent: *\nAllow: /\nSitemap: {cfg.base_url}/sitemap.xml\n")
    write(".nojekyll", "")
    return {"pages": pages, "entries": len(views), "reviewed": t["reviewed"], "totals": t}
