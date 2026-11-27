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
from .verdict import STAMPS

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
CSS = r"""
/* Customs inspection bay. Plugins arrive as cargo, the registry is an arrivals board, each entry is an inspection docket,
   verdicts are rubber stamps. System fonts only: the site makes no third-party requests.
   Shape rule: every surface is square; only physical objects (stamps, flap tiles) get a 3px corner.
   Colour rule: signal amber is the one accent. Stamp inks (clear, cond, hold, refuse) carry verdict meaning only.
   The board, x-ray and header are physical displays and stay dark in both themes. */
:root{--paper:#e6e9e2;--sheet:#f5f6f1;--ink:#15181b;--soft:#464c52;--mute:#5a6168;--hair:#c2c7bd;--wash:#dcdfd6;--code:#eceee7;
--grid:rgba(21,24,27,.045);--focus:#15181b;--under:#a87700;
--signal:#f2b200;--board:#17191b;--board2:#212427;--bhair:#33383d;--led:#ffb81c;--btext:#e6e9e3;--bsoft:#a3aaaf;
--clear:#1d6a43;--cond:#875400;--hold:#b3261e;--refuse:#b3261e;--refuse-ink:#fff6f3;--pend:#596067;
--x-hook:#ff9d2e;--x-mcp:#5fa6ff;--x-lsp:#5fd394;--x-other:#c7ccd0;
--display:"DIN Condensed","Bahnschrift","D-DIN Condensed","DIN Alternate","Roboto Condensed","Arial Narrow",sans-serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
--mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#101214;--sheet:#171a1d;--ink:#e4e7e1;--soft:#adb3ac;--mute:#939aa0;--hair:#2d3236;--wash:#1c1f22;--code:#1c1f22;
--grid:rgba(255,255,255,.028);--focus:#f2b200;--under:#f2b200;--board:#0a0b0c;--board2:#141618;--bhair:#272b2f;
--clear:#62d394;--cond:#f0b54a;--hold:#ff7468;--refuse:#ff6a5c;--refuse-ink:#1a0806;--pend:#9ba2a9}}
:root[data-theme="dark"]{--paper:#101214;--sheet:#171a1d;--ink:#e4e7e1;--soft:#adb3ac;--mute:#939aa0;--hair:#2d3236;--wash:#1c1f22;--code:#1c1f22;
--grid:rgba(255,255,255,.028);--focus:#f2b200;--under:#f2b200;--board:#0a0b0c;--board2:#141618;--bhair:#272b2f;
--clear:#62d394;--cond:#f0b54a;--hold:#ff7468;--refuse:#ff6a5c;--refuse-ink:#1a0806;--pend:#9ba2a9}
.bay,.board,.xray,.flaps,.tape{--clear:#62d394;--cond:#f0b54a;--hold:#ff7468;--refuse:#ff6a5c;--refuse-ink:#1a0806;--pend:#a3aab0;--focus:#f2b200;--stampbg:var(--board)}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;color:var(--ink);font:16px/1.6 var(--sans);background-color:var(--paper);
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:28px 28px}
a{color:var(--ink);text-decoration-color:var(--under);text-decoration-thickness:2px;text-underline-offset:3px}a:hover{text-decoration-thickness:3px}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.wrap{max-width:1180px;margin:0 auto;padding:0 24px}
code,pre,.mono{font-family:var(--mono)}code{font-size:.88em;background:var(--code);padding:1px 5px;overflow-wrap:anywhere}
pre{background:var(--code);border:2px solid var(--ink);padding:14px 16px;overflow-x:auto;font-size:13px;line-height:1.6;margin:14px 0}
pre code{background:none;padding:0;font-size:inherit}
h1,h2{font-family:var(--display);font-stretch:condensed;font-weight:700;text-transform:uppercase;letter-spacing:.01em;line-height:.98;margin:0;text-wrap:balance}
h3{font:650 1.08rem/1.3 var(--sans);margin:0;text-wrap:balance}
h1{font-size:clamp(2.5rem,5.6vw,4.6rem)}h2{font-size:clamp(1.9rem,3.6vw,2.9rem)}
p{margin:0 0 14px;max-width:66ch;text-wrap:pretty;overflow-wrap:break-word}.lede{font-size:1.12rem;color:var(--soft);max-width:58ch}
.lab{display:block;font:700 10.5px/1.2 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--mute)}
.skip{position:absolute;left:-999px}.skip:focus{left:12px;top:12px;background:var(--sheet);color:var(--ink);padding:8px 12px;z-index:9}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

/* header: the bay sign */
.bay{background:var(--board);color:var(--btext)}
.bay .wrap{display:flex;align-items:center;gap:6px 24px;min-height:66px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px;color:var(--btext);text-decoration:none;margin-right:auto;font:700 1.5rem/1 var(--display);font-stretch:condensed;letter-spacing:.05em;text-transform:uppercase;padding-top:3px}
.brand i{font-style:normal;display:grid;place-items:center;width:31px;height:31px;border:2px solid var(--signal);color:var(--signal);font:800 15px/1 var(--mono);transform:rotate(-6deg);margin-top:-3px}
.bay a.l{color:var(--bsoft);text-decoration:none;font:700 11.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;padding:9px 0 7px;border-bottom:3px solid transparent}
.bay a.l:hover{color:#fff}.bay a.l[aria-current]{color:#fff;border-bottom-color:var(--signal)}
.tt{font:700 10.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;background:none;color:var(--bsoft);border:1px solid #4a5056;padding:8px 10px;cursor:pointer}
.tt:hover{color:#fff;border-color:var(--bsoft)}
.hz{height:10px;background:repeating-linear-gradient(-45deg,var(--signal) 0 14px,#17191b 14px 28px)}

/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:700 12.5px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:15px 20px;
border:2px solid var(--ink);color:var(--ink);background:var(--sheet);text-decoration:none;cursor:pointer;box-shadow:4px 4px 0 var(--ink);white-space:nowrap}
.btn.p{background:var(--signal);color:#15181b}
.btn:hover{background:var(--ink);color:var(--paper)}.btn.p:hover{background:var(--signal);color:#15181b;box-shadow:6px 6px 0 var(--ink);transform:translate(-2px,-2px)}
.btn:active,.btn.p:active{transform:translate(3px,3px);box-shadow:1px 1px 0 var(--ink)}
.cta{display:flex;gap:16px;flex-wrap:wrap;margin-top:28px}

/* rubber stamps */
.stamp{--stampbg:var(--sheet);position:relative;display:inline-flex;flex-direction:column;align-items:center;gap:4px;padding:9px 16px 8px;color:var(--pend);
border:3px solid currentColor;border-radius:3px;box-shadow:inset 0 0 0 2px var(--stampbg),inset 0 0 0 4px currentColor;
font:700 1.55rem/1 var(--display);font-stretch:condensed;letter-spacing:.08em;text-transform:uppercase;transform:rotate(-4deg);white-space:nowrap;text-align:center}
.stamp small{font:700 10px/1.25 var(--mono);letter-spacing:.1em}
.stamp::after{content:"";position:absolute;inset:0;pointer-events:none;opacity:.4;
background:radial-gradient(circle at 18% 32%,var(--stampbg) 0 1.5px,transparent 2px),radial-gradient(circle at 63% 71%,var(--stampbg) 0 1px,transparent 1.6px),
radial-gradient(circle at 82% 22%,var(--stampbg) 0 2px,transparent 2.6px),radial-gradient(circle at 41% 88%,var(--stampbg) 0 1px,transparent 1.5px);background-size:37px 23px,29px 31px,53px 41px,23px 19px}
.stamp.low{color:var(--clear)}.stamp.caution{color:var(--cond)}.stamp.review{color:var(--hold)}
.stamp.block{color:var(--refuse-ink);background:var(--refuse);border-color:var(--refuse);box-shadow:inset 0 0 0 2px var(--refuse),inset 0 0 0 4px var(--refuse-ink)}
.stamp.block::after{display:none}
.stamp.muted{border-style:dashed;box-shadow:none;font-size:1.2rem}
.stamp.sm{font-size:1rem;padding:5px 9px 4px;border-width:2px;box-shadow:none;transform:rotate(-2deg);gap:2px}
.stamp.sm small{font-size:9px}.stamp.sm::after{display:none}.stamp.sm.muted{font-size:.9rem}

/* hero */
.hero{padding:56px 0 72px}.hero .wrap{display:grid;grid-template-columns:minmax(0,1.04fr) minmax(0,.96fr);gap:56px;align-items:start}
.kicker{display:inline-block;font:700 11.5px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;background:var(--ink);color:var(--paper);padding:8px 11px 7px;margin-bottom:24px}
.hero h1{font-size:clamp(2.7rem,5.9vw,5rem)}
.hero .lede{margin-top:22px}
.check{margin-top:30px;max-width:560px;border:2px solid var(--ink);background:var(--sheet);box-shadow:6px 6px 0 var(--wash)}
.check label{display:block;font:700 10.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;padding:9px 12px;border-bottom:2px solid var(--ink);color:var(--ink)}
.check .row{display:flex}.check input{flex:1;min-width:0;font:16px var(--mono);padding:14px;border:0;background:var(--sheet);color:var(--ink)}
.check input:focus-visible{outline-offset:-3px}
.check input::placeholder{color:var(--mute)}.check .row .btn{box-shadow:none;border-width:0 0 0 2px}.check .row .btn:active{transform:none}
.check .out{padding:0 12px;font-size:.93rem;color:var(--soft)}.check .out:not(:empty){padding:10px 12px;border-top:1px dashed var(--hair)}
.check .out ul{list-style:none;margin:0;padding:0}.check .out li{padding:3px 0}.check .out a{font:600 .9rem var(--mono)}
.alt{margin-top:18px;font-size:.95rem;color:var(--soft)}

/* x-ray: what runs and when */
.xray{position:relative;background:var(--board);color:var(--btext);border:2px solid var(--ink);padding:20px 20px 16px;overflow:hidden;
background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);background-size:20px 20px}
.xray .xh{display:flex;justify-content:space-between;gap:12px;align-items:start;padding-right:150px;min-height:56px}
.xray .xh b{display:block;font:700 11px/1 var(--mono);letter-spacing:.16em;color:var(--led);margin-bottom:8px}
.xray .xh strong{display:block;font:700 14px/1.3 var(--mono);overflow-wrap:anywhere}.xray .xh span{font:12px var(--mono);color:var(--bsoft)}
.xray .stamp{position:absolute;top:18px;right:16px}
.lanes{margin:16px 0 4px;border-top:1px solid var(--bhair)}
.lane{display:grid;grid-template-columns:150px minmax(0,1fr);gap:14px;align-items:center;padding:10px 0;border-bottom:1px solid var(--bhair)}
.lane dt{font:700 10.5px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--bsoft)}.lane dt b{color:var(--btext);font-size:13px;margin-right:6px}
.lane dd{margin:0;display:flex;flex-wrap:wrap;gap:3px}
.blk{width:11px;height:24px;background:var(--x-other);opacity:.92}.blk.hook{background:var(--x-hook)}.blk.mcp{background:var(--x-mcp)}.blk.lsp{background:var(--x-lsp)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font:11px var(--mono);color:var(--bsoft);margin:12px 0 0;padding:0;list-style:none}
.legend li{display:flex;align-items:center;gap:6px}.legend i{width:9px;height:14px;display:inline-block}
.xitems{list-style:none;margin:14px 0 0;padding:0}.xitems li{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;padding:7px 0;font-size:12.5px;border-top:1px dashed var(--bhair)}
.xitems b{font:700 10.5px/1.6 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--led);white-space:nowrap}
.xitems code{background:none;padding:0;color:var(--btext);font-size:12px}
.xray .foot{font:12px var(--mono);color:var(--bsoft);margin-top:12px}.xray a{color:var(--btext);text-decoration-color:var(--led)}
.xray::after{content:"";position:absolute;top:0;bottom:0;left:0;width:90px;pointer-events:none;opacity:0;
background:linear-gradient(90deg,transparent,rgba(255,184,28,.16) 60%,rgba(255,184,28,.42) 96%,transparent)}

/* arrivals board: registry totals */
.flaps{background:var(--board);color:var(--btext);border:2px solid var(--ink)}
.flaps .fh{display:flex;justify-content:space-between;gap:12px;padding:11px 18px;border-bottom:1px solid var(--bhair);font:700 11px/1.2 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--led)}
.flaps .fh a{color:var(--bsoft);text-decoration-color:var(--led)}
.flaps .fg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}
.flaps .fc{padding:20px 18px 18px;border-right:1px solid var(--bhair);min-width:0}.flaps .fc:last-child{border-right:0}
.fl{display:flex;gap:4px;margin-bottom:12px}
.fl i{position:relative;display:grid;place-items:center;width:.74em;height:1.08em;padding-top:.08em;background:var(--board2);border-radius:3px;font:700 clamp(2.3rem,4.4vw,3.5rem)/1 var(--display);font-style:normal;color:#f3f3ec;font-variant-numeric:tabular-nums}
.fl i::after{content:"";position:absolute;left:0;right:0;top:50%;height:2px;margin-top:-1px;background:var(--board)}
.flaps .fc>span:last-child{display:block;font-size:.9rem;color:var(--bsoft);line-height:1.45}

/* sections */
.band{padding:72px 0}.band.w{background:var(--wash);border-top:2px solid var(--ink);border-bottom:2px solid var(--ink)}
.band h2{margin-bottom:10px}
.hidden{list-style:none;margin:34px 0 0;padding:0;counter-reset:h}
.hidden li{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:36px;padding:26px 0;border-top:2px solid var(--ink)}
.hidden li:last-child{border-bottom:2px solid var(--ink)}
.hidden h3{font:700 clamp(1.5rem,2.6vw,2rem)/1 var(--display);font-stretch:condensed;text-transform:uppercase;letter-spacing:.01em;display:flex;gap:14px;align-items:baseline}
.hidden h3::before{counter-increment:h;content:counter(h);flex:none;display:grid;place-items:center;width:1.4em;height:1.4em;padding-top:.12em;background:var(--signal);color:#15181b;font-size:.7em}
.hidden p{color:var(--soft);margin:0}
.head{display:flex;justify-content:space-between;align-items:end;gap:18px;flex-wrap:wrap;margin-bottom:10px}

/* lanes of the procedure: tabs */
.tabs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:2px solid var(--ink);margin-top:30px;background:var(--sheet)}
.tab{display:flex;flex-direction:column;align-items:flex-start;gap:6px;text-align:left;padding:14px 16px 12px;border:0;border-right:2px solid var(--ink);background:none;color:var(--ink);cursor:pointer;
font:700 1.5rem/1 var(--display);font-stretch:condensed;text-transform:uppercase;letter-spacing:.03em;box-shadow:inset 0 5px 0 transparent}
.tab:last-child{border-right:0}.tab small{font:700 10px/1 var(--mono);letter-spacing:.12em;color:var(--mute)}
.tab:hover{background:var(--wash)}.tab[aria-selected=true]{background:var(--ink);color:var(--paper);box-shadow:inset 0 5px 0 var(--signal)}
.tab[aria-selected=true] small{color:var(--paper);opacity:.75}
.panel{display:grid;grid-template-columns:minmax(0,.82fr) minmax(0,1.18fr);gap:36px;padding-top:30px;align-items:start}.panel[hidden]{display:none}
.panel h3{font:700 1.9rem/1 var(--display);font-stretch:condensed;text-transform:uppercase;margin-bottom:14px}.panel p{color:var(--soft)}
.panel .pw{margin:0}.panel pre{margin:0}.panel pre.tape{max-height:430px;overflow:auto}
.cap{font:700 10.5px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin:0 0 8px}
pre.tape{background:var(--board);color:#dfe3de;border-color:var(--ink);border-top:6px solid var(--signal)}
.pw{position:relative;margin:14px 0}.pw pre{margin:0}
.cp{position:absolute;top:8px;right:8px;font:700 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:6px 8px;border:1px solid var(--hair);background:var(--sheet);color:var(--soft);cursor:pointer}
.cp:hover{color:var(--ink);border-color:var(--ink)}.tape+.cp{background:var(--board2);border-color:var(--bhair);color:var(--bsoft)}.tape+.cp:hover{color:#fff;border-color:var(--bsoft)}

/* tables and the departures board */
table{width:100%;border-collapse:collapse;font-size:.93rem}
th{font:700 10.5px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mute);text-align:left;padding:11px 12px;border-bottom:2px solid var(--ink)}
td{padding:11px 12px;border-bottom:1px solid var(--hair);vertical-align:top}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.tw{overflow-x:auto;background:var(--sheet);border:2px solid var(--ink)}
.board{background:var(--board);color:var(--btext);border:2px solid var(--ink)}
.board .bh{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:11px 14px;border-bottom:1px solid var(--bhair);font:700 11px/1.2 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--led)}
.board .bh span:last-child{color:var(--bsoft)}
.board .tw{background:none;border:0}
.board th{color:var(--bsoft);border-bottom:1px solid var(--bhair);background:var(--board2)}
.board td{border-bottom:1px solid var(--bhair);font-family:var(--mono);font-size:.86rem}
.board tbody tr:hover{background:rgba(255,255,255,.035)}
.board td a.repo{color:var(--led);font-weight:700;text-decoration:none;font-size:.92rem;overflow-wrap:anywhere}.board td a.repo:hover{text-decoration:underline;text-decoration-color:var(--led)}
.board td .d{display:block;color:var(--bsoft);font:.82rem/1.45 var(--sans);max-width:48ch;margin-top:3px}
.board td.num{color:#f3f3ec;font-size:.95rem}.board td.z{color:#80878d}
.board .when{white-space:nowrap;color:var(--bsoft);font-size:.8rem}
.board .kind{color:var(--bsoft);font-size:.8rem;white-space:nowrap}
.board th button{color:var(--bsoft)}.board th button:hover,.board th[aria-sort] button{color:var(--led)}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0 14px}
.tools input{flex:1 1 280px;min-width:0;font:15px var(--mono);padding:13px 14px;border:2px solid var(--ink);background:var(--sheet);color:var(--ink)}
.tools input::placeholder{color:var(--mute)}
.count{font:700 11px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin:0 0 10px}
.fset{display:flex;flex-wrap:wrap;gap:0;align-items:stretch}.fset+.fset{margin-top:10px}
.fset span{display:flex;align-items:center;font:700 10.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--mute);min-width:64px}
.chipb{font:700 11.5px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase;padding:10px 13px;border:2px solid var(--ink);margin:0 -2px -2px 0;background:var(--sheet);color:var(--ink);cursor:pointer}
.chipb:hover{background:var(--wash)}.chipb[aria-pressed=true]{background:var(--ink);color:var(--paper);box-shadow:inset 0 -4px 0 var(--signal)}
th button{all:unset;cursor:pointer;font:inherit;letter-spacing:inherit;text-transform:inherit}th button:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
th[aria-sort=ascending] button::after{content:" \2191"}th[aria-sort=descending] button::after{content:" \2193"}
.none{padding:22px 16px;color:var(--bsoft);margin:0}

/* notes: caution tape on the left edge */
.note{position:relative;background:var(--sheet);border:2px solid var(--ink);padding:15px 18px 15px 34px;margin:22px 0;font-size:.97rem;max-width:860px}
.note::before{content:"";position:absolute;left:0;top:0;bottom:0;width:14px;background:repeating-linear-gradient(-45deg,var(--signal) 0 8px,#17191b 8px 16px)}
.note p{max-width:none}.note p:last-child{margin:0}

/* docket */
.crumb{font:700 11px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin:30px 0 14px;overflow-wrap:anywhere}.crumb a{color:var(--mute)}
.docket{background:var(--sheet);border:2px solid var(--ink);box-shadow:8px 8px 0 var(--wash);overflow:clip}
.dk-top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:10px 18px;background:var(--ink);color:var(--paper);font:700 11px/1.2 var(--mono);letter-spacing:.14em;text-transform:uppercase}
.dk-body{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:28px;align-items:center;padding:26px 22px 22px}
.dk-body h1{font:700 clamp(1.5rem,3.4vw,2.35rem)/1.15 var(--mono);text-transform:none;letter-spacing:-.02em;overflow-wrap:anywhere}
.dk-body .lede{margin:12px 0 0;font-size:1.02rem}
.dk-stamp{padding:6px 12px}.dk-stamp .stamp{font-size:2.2rem;padding:12px 22px 10px}.dk-stamp .stamp small{font-size:11px}.dk-stamp .stamp.muted{font-size:1.5rem}
.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin:0;border-top:2px solid var(--ink)}
.fields div{padding:11px 16px 12px;border-right:1px solid var(--hair);border-bottom:1px solid var(--hair);margin:0 -1px -1px 0;min-width:0}
.fields dt{font:700 10px/1.2 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--mute);margin-bottom:5px}
.fields dd{margin:0;font:600 .92rem/1.35 var(--mono);overflow-wrap:anywhere}.fields dd code{background:none;padding:0;font-size:inherit}
.kv{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:2px solid var(--ink);background:var(--sheet);margin:22px 0}
.kv div{padding:16px 16px 14px;border-right:1px solid var(--hair);min-width:0}.kv div:last-child{border-right:0}
.kv b{display:block;font:700 2.3rem/1 var(--display);font-stretch:condensed;font-variant-numeric:tabular-nums;margin-bottom:6px}.kv span{font-size:.8rem;color:var(--soft);line-height:1.35;display:block}
.sec{margin-top:48px}.sec>h2,details.sec>summary h2{font-size:clamp(1.6rem,3vw,2.2rem);margin-bottom:14px}
.sec .lab{margin-bottom:8px}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{font:12.5px var(--mono);background:var(--sheet);border:1px solid var(--hair);padding:4px 9px;overflow-wrap:anywhere}
details.sec>summary{cursor:pointer;list-style:none;display:flex;align-items:baseline;justify-content:space-between;gap:12px;border-bottom:2px solid var(--ink);padding-bottom:10px}
details.sec>summary::-webkit-details-marker{display:none}details.sec>summary h2{margin:0}
details.sec>summary::after{content:"open";flex:none;font:700 10.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--ink);border:2px solid var(--ink);padding:6px 8px}
details.sec[open]>summary::after{content:"close"}details.sec[open]>summary{margin-bottom:16px}

/* the x-ray on a docket */
.scan{background:var(--board);color:var(--btext);border:2px solid var(--ink);position:relative;overflow:hidden;
background-image:linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);background-size:20px 20px}
.scan .sh{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:11px 16px;border-bottom:1px solid var(--bhair);font:700 11px/1.3 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--led)}
.scan .legend{margin:0}
.phase{display:grid;grid-template-columns:200px minmax(0,1fr);border-bottom:1px solid var(--bhair)}.phase:last-of-type{border-bottom:0}
.phase h3{padding:16px;font:700 1.35rem/1 var(--display);font-stretch:condensed;text-transform:uppercase;letter-spacing:.04em;color:var(--btext);border-right:1px solid var(--bhair)}
.phase h3 span{display:block;font:700 10.5px/1.3 var(--mono);letter-spacing:.1em;color:var(--led);margin-top:8px}
.phase ol{list-style:none;margin:0;padding:6px 16px}
.phase li{display:grid;grid-template-columns:110px minmax(0,1fr);gap:4px 14px;padding:10px 0;border-bottom:1px dashed var(--bhair)}.phase li:last-child{border-bottom:0}
.phase .ty{display:flex;align-items:flex-start;gap:7px;font:700 10.5px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--bsoft)}
.phase .ty i{flex:none;width:8px;height:15px;background:var(--x-other)}.phase .ty i.hook{background:var(--x-hook)}.phase .ty i.mcp{background:var(--x-mcp)}.phase .ty i.lsp{background:var(--x-lsp)}
.phase code{background:none;padding:0;color:var(--btext);font-size:12.5px}
.phase .wh{display:block;font:11.5px/1.5 var(--mono);color:var(--bsoft);margin-top:3px;overflow-wrap:anywhere}.phase .wh b{color:var(--led);font-weight:700}
.scan .empty{padding:22px 16px;margin:0;color:var(--bsoft)}

/* findings */
.find{border:2px solid var(--ink);background:var(--sheet);margin:14px 0;display:grid;grid-template-columns:118px minmax(0,1fr)}
.find .sv{padding:14px 12px;border-right:2px solid var(--ink);font:700 1.2rem/1 var(--display);font-stretch:condensed;letter-spacing:.06em;text-transform:uppercase;color:var(--pend)}
.find.critical .sv{background:var(--refuse);color:var(--refuse-ink)}.find.high .sv{color:var(--hold)}.find.medium .sv{color:var(--cond)}.find.low .sv{color:var(--clear)}
.find .fb{padding:14px 18px;min-width:0}
.find h3{font:650 1rem/1.35 var(--sans)}.find .m{font:12px var(--mono);color:var(--mute);margin:5px 0 10px;overflow-wrap:anywhere}.find p{font-size:.94rem;margin-bottom:6px}

/* pricing: a declaration form */
.form{border:2px solid var(--ink);background:var(--sheet);margin-top:30px}
.form .fh{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:10px 18px;background:var(--ink);color:var(--paper);font:700 11px/1.2 var(--mono);letter-spacing:.14em;text-transform:uppercase}
.chooser{display:grid;grid-template-columns:repeat(2,minmax(0,250px)) minmax(0,1fr)}
.chooser>div,.chooser output{padding:14px 18px 16px;border-right:1px solid var(--hair)}.chooser output{border-right:0;display:flex;align-items:center;font-weight:600;background:var(--wash)}
.chooser label{display:block;font:700 10.5px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin-bottom:8px}
.chooser input{width:100%;font:700 1.7rem/1 var(--display);padding:9px 10px 6px;border:2px solid var(--ink);background:var(--paper);color:var(--ink)}
.tiers{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;margin-top:26px;border:2px solid var(--ink);background:var(--sheet)}
.tier{position:relative;display:flex;flex-direction:column;padding:0;border-right:2px solid var(--ink);min-width:0}.tier:last-child{border-right:0}
.tier .th{padding:16px 20px 14px;border-bottom:1px solid var(--hair)}
.tier h3{font:700 2rem/1 var(--display);font-stretch:condensed;text-transform:uppercase;letter-spacing:.03em;margin-top:6px}
.tier .fee{padding:16px 20px;border-bottom:1px solid var(--hair);background:var(--wash)}
.tier .price{font:700 3.2rem/1 var(--display);font-stretch:condensed;margin-top:6px}.tier .price small{font:600 .85rem var(--mono);color:var(--soft);margin-left:4px}
.tier .who{padding:14px 20px 0;color:var(--soft);font-size:.95rem;margin:0}
.tier ul{list-style:none;margin:10px 0 18px;padding:0 20px;flex:1}
.tier li{position:relative;padding:8px 0 8px 28px;border-top:1px dashed var(--hair);font-size:.93rem}.tier li:first-child{border-top:0}
.tier li::before{content:"";position:absolute;left:0;top:11px;width:14px;height:14px;border:2px solid var(--ink)}
.tier li::after{content:"";position:absolute;left:4px;top:13px;width:5px;height:8px;border:solid var(--ink);border-width:0 2px 2px 0;transform:rotate(45deg)}
.tier .go{padding:0 20px 22px}.tier .btn{width:100%}
.tier.pick{background:var(--paper);box-shadow:inset 0 6px 0 var(--signal)}
.tier.pick::after{content:"fits";position:absolute;top:18px;right:16px;font:700 1.25rem/1 var(--display);font-stretch:condensed;letter-spacing:.1em;text-transform:uppercase;color:var(--clear);
border:3px solid var(--clear);border-radius:3px;padding:6px 10px 4px;transform:rotate(6deg)}
.faq{margin-top:56px;max-width:900px}.faq h2{margin-bottom:12px}
.faq details{border-top:2px solid var(--ink);padding:16px 0}.faq details:last-child{border-bottom:2px solid var(--ink)}
.faq summary{cursor:pointer;font-weight:650;display:flex;justify-content:space-between;gap:16px;list-style:none}.faq summary::-webkit-details-marker{display:none}
.faq summary::after{content:"+";flex:none;display:grid;place-items:center;width:24px;height:24px;border:2px solid var(--ink);font:700 15px/1 var(--mono)}.faq details[open] summary::after{content:"\2212";background:var(--signal);color:#15181b}
.faq details p{margin:12px 0 0;color:var(--soft)}

/* docs: the manifest */
.doc{display:grid;grid-template-columns:230px minmax(0,1fr);gap:48px;padding:36px 0 72px;counter-reset:d}
.toc{position:sticky;top:20px;align-self:start;border:2px solid var(--ink);background:var(--sheet);counter-reset:t;font-size:.9rem}
.toc .lab{padding:10px 14px;background:var(--ink);color:var(--paper)}
.toc a{display:flex;gap:10px;padding:7px 14px;color:var(--soft);text-decoration:none;border-top:1px solid var(--hair)}
.toc a::before{counter-increment:t;content:counter(t,decimal-leading-zero);font:700 11px/1.7 var(--mono);color:var(--mute)}
.toc a:hover{color:var(--ink);background:var(--wash)}.toc a[aria-current]{color:var(--ink);background:var(--wash);box-shadow:inset 4px 0 0 var(--signal)}
.doc h2{display:flex;gap:14px;align-items:baseline;margin:56px 0 14px;padding-top:16px;border-top:2px solid var(--ink);scroll-margin-top:20px}
.doc h2::before{counter-increment:d;content:counter(d,decimal-leading-zero);flex:none;font:700 12px/1 var(--mono);background:var(--signal);color:#15181b;padding:6px 7px 5px;transform:translateY(-.35em)}
.doc h2:first-of-type{margin-top:0}.doc h3{margin:24px 0 8px}
.doc ul,.doc ol{max-width:66ch;padding-left:22px}.doc li{margin-bottom:7px}.doc .tw{margin:14px 0}
.doc .stamp.sm{margin:2px 0}

/* services: one permit each */
.svc{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);border:2px solid var(--ink);background:var(--sheet);margin-top:28px}
.svc>div{padding:24px 24px 22px;min-width:0}.svc>div:first-child{border-right:2px solid var(--ink)}
.svc h2{font-size:2rem;margin:6px 0 12px}.svc .facts{font:12.5px/1.6 var(--mono);color:var(--mute);margin:14px 0}.svc .facts a{color:var(--mute)}
.svc h3{font:700 10.5px/1.3 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--mute);margin:0 0 8px}
.svc ul{margin:0 0 22px;padding-left:18px}.svc li{margin-bottom:6px;font-size:.95rem}.svc .lim li{color:var(--soft)}.svc .price{font-weight:700;margin:0 0 16px}
.svc .stamp{margin:4px 0 14px}

/* 404 */
.lost{padding:72px 0 96px}.lost h1{font-size:clamp(3rem,9vw,7rem)}.lost .stamp{margin:0 0 28px}

footer{margin-top:24px;border-top:2px solid var(--ink);padding:28px 0 48px;color:var(--soft);font-size:.88rem;background:var(--paper)}
footer .wrap{display:flex;gap:24px;justify-content:space-between;flex-wrap:wrap}footer a{color:var(--soft)}footer p{margin:0 0 6px}
footer b{font:700 1.1rem/1 var(--display);font-stretch:condensed;letter-spacing:.05em;text-transform:uppercase;color:var(--ink);margin-right:4px}

@media (max-width:900px){.hero{padding:36px 0 48px}.hero .wrap{grid-template-columns:minmax(0,1fr);gap:40px}
.flaps .fg{grid-template-columns:repeat(2,minmax(0,1fr))}.flaps .fc:nth-child(2){border-right:0}.flaps .fc:nth-child(-n+2){border-bottom:1px solid var(--bhair)}
.hidden li{grid-template-columns:minmax(0,1fr);gap:12px}.panel,.svc{grid-template-columns:minmax(0,1fr);gap:20px}.svc>div:first-child{border-right:0;border-bottom:2px solid var(--ink)}
.tiers{grid-template-columns:minmax(0,1fr)}.tier{border-right:0;border-bottom:2px solid var(--ink)}.tier:last-child{border-bottom:0}
.chooser{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.chooser output{grid-column:1/-1;border-top:1px solid var(--hair)}.chooser>div:nth-child(2){border-right:0}
.kv{grid-template-columns:repeat(3,minmax(0,1fr))}.kv div:nth-child(3){border-right:0}.kv div:nth-child(-n+3){border-bottom:1px solid var(--hair)}
.doc{grid-template-columns:minmax(0,1fr);gap:24px}.toc{position:static}
.phase{grid-template-columns:minmax(0,1fr)}.phase h3{border-right:0;border-bottom:1px solid var(--bhair);display:flex;justify-content:space-between;align-items:baseline;gap:10px}.phase h3 span{margin:0}}
@media (max-width:640px){.wrap{padding:0 16px}.bay .wrap{padding-top:10px;padding-bottom:6px;gap:4px 16px}.brand{flex:1 0 calc(100% - 110px);margin-bottom:4px}.tt{order:1}.bay a.l{order:2;font-size:11px;letter-spacing:.1em}.kicker{font-size:10.5px;letter-spacing:.1em}
.band{padding:52px 0}.tabs{grid-template-columns:repeat(2,minmax(0,1fr))}.tab:nth-child(2){border-right:0}.tab:nth-child(-n+2){border-bottom:2px solid var(--ink)}
.xray{padding:16px 14px 14px}.xray .xh{padding-right:0;flex-direction:column}.xray .stamp{position:static;align-self:flex-start;margin:4px 0 2px}
.lane{grid-template-columns:minmax(0,1fr);gap:6px}.xitems li{grid-template-columns:minmax(0,1fr);gap:2px}
.dk-body{grid-template-columns:minmax(0,1fr);gap:14px;padding:20px 16px 18px}.dk-stamp{padding:4px 2px}.dk-stamp .stamp{font-size:1.75rem}
.kv{grid-template-columns:repeat(2,minmax(0,1fr))}.kv div{border-bottom:1px solid var(--hair)}.kv div:nth-child(3){border-right:1px solid var(--hair)}.kv div:nth-child(2n){border-right:0}.kv div:nth-last-child(-n+2){border-bottom:0}
.phase li{grid-template-columns:minmax(0,1fr);gap:4px}
.find{grid-template-columns:minmax(0,1fr)}.find .sv{border-right:0;border-bottom:2px solid var(--ink);padding:9px 14px 7px}
.chooser{grid-template-columns:minmax(0,1fr)}.chooser>div{border-right:0;border-bottom:1px solid var(--hair)}.chooser output{border-top:0}
.check .row{flex-direction:column}.check .row .btn{border-width:2px 0 0}
.stack thead{display:none}.stack tr{display:block;padding:12px 4px;border-bottom:1px solid var(--hair)}.board .stack tr{border-bottom-color:var(--bhair)}
.stack td{display:block;border:0;padding:3px 12px;text-align:left}.stack td.num{text-align:left}
.stack td[data-l]::before{content:attr(data-l) ": ";font:700 10px var(--mono);color:var(--mute);text-transform:uppercase;letter-spacing:.08em}.board .stack td[data-l]::before{color:var(--bsoft)}
.stack td:first-child::before{display:none}.board .stack td.num,.board .stack td.when{display:inline-block;padding:4px 4px 4px 12px}.btn{white-space:normal;text-align:center}}
@media (prefers-reduced-motion:no-preference){
.btn,.bay a.l,.tab,.chipb,.cp,.faq summary::after{transition:color .15s,background-color .15s,border-color .15s,box-shadow .15s,transform .15s}
.fl i{animation:flap .55s cubic-bezier(.2,.8,.3,1) both;animation-delay:calc(var(--d,0) * 70ms + 150ms);transform-origin:50% 50%}
@keyframes flap{0%{transform:perspective(300px) rotateX(-92deg);filter:brightness(.4)}70%{transform:perspective(300px) rotateX(12deg)}100%{transform:none;filter:none}}
.dk-stamp .stamp,.xray .stamp{animation:thunk .42s cubic-bezier(.3,1.4,.5,1) .25s both}
@keyframes thunk{0%{opacity:0;transform:rotate(-12deg) scale(1.7)}100%{opacity:1;transform:rotate(-4deg) scale(1)}}
.xray::after{animation:sweep 2.2s cubic-bezier(.45,0,.55,1) .2s 1 both}
@keyframes sweep{0%{opacity:1;transform:translateX(-100px)}88%{opacity:1}100%{opacity:0;transform:translateX(640px)}}
.blk{animation:blk .3s ease-out both;animation-delay:calc(var(--d,0) * 18ms + 300ms)}@keyframes blk{from{opacity:0;transform:scaleY(.2)}}}
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
        f"<header class='bay'><div class='wrap'><a class='brand' href='{root}'><i aria-hidden='true'>W</i>{e(cfg.name)}</a>{nav}"
        f"<a class='l' href='{e(cfg.repo_url)}'>GitHub</a><button class='tt' type='button' aria-label='Switch colour theme'>theme</button></div></header>"
        "<div class='hz' aria-hidden='true'></div>"
        f"<main id='main'>{body}</main>"
        f"<footer><div class='wrap'><div><p><b>{e(cfg.name)}</b> {e(__version__)}. MIT licensed.</p>"
        "<p>This site makes no third-party requests: no analytics, no web fonts, no trackers.</p></div>"
        f"<div><p><a href='{root}docs/#disclosure'>Disclosure policy</a> · <a href='{root}docs/#method'>How the registry works</a></p>"
        f"<p><a href='{root}api/v1/index.json'>JSON API</a> · <a href='{e(cfg.security_url)}'>Report a problem with a listing</a></p></div></div></footer>"
        f"<script>{THEME_JS}{SITE_JS}{script}</script></body></html>"
    )




def _stamp(view: dict[str, Any], size: str = "", score: bool = True) -> str:
    """A rubber stamp for a registry view. No verdict means no clearance stamp: only a dashed 'not yet reviewed' mark."""
    cls = f"stamp {size}".strip()
    if view["verdict"] is None:
        return f"<span class='{cls} muted'>Not yet reviewed</span>"
    v = view["verdict"]
    word = STAMPS.get(v["level"], v["label"])
    sub = e(v["label"]) + (f" · {e(v['score'])}/100" if score else "")
    if word == v["label"]:
        sub = f"risk score {e(v['score'])}/100" if score else ""
    return f"<span class='{cls} {e(v['level'])}'>{e(word)}" + (f"<small>{sub}</small>" if sub else "") + "</span>"


def _status_tag(view: dict[str, Any]) -> str:
    return _stamp(view, "sm", score=False)


def _entry_href(view: dict[str, Any]) -> str:
    return f"r/{view['source']}/"


def _num(n: int) -> str:
    return f"<td class='num{' z' if not n else ''}'"


def _reg_rows(views: list[dict[str, Any]], root: str) -> str:
    rows = []
    for v in views:
        desc = f"<span class='d'>{e(str(v['description'])[:140])}</span>" if v.get("description") else ""
        a, p, h = len(v["auto_runs"]), len(v["processes"]), len(v["hosts"])
        rows.append(
            f"<tr data-t='{e((v['source'] + ' ' + str(v.get('description') or '')).lower())}' data-k='{e(v['kind'])}' data-s='{e(v['state'])}'>"
            f"<td data-l='Repository' data-v='{e(v['source'])}'><a class='repo' href='{root}{e(_entry_href(v))}'>{e(v['source'])}</a>{desc}</td>"
            f"<td data-l='Kind' class='kind'>{e(v['kind_label'])}</td><td data-l='Status'>{_status_tag(v)}</td>"
            f"{_num(a)} data-l='Runs on its own'>{a}</td>{_num(p)} data-l='Processes'>{p}</td>"
            f"{_num(h)} data-l='Hosts'>{h}</td><td class='num' data-l='Stars'>{_n(v.get('stars'))}</td>"
            f"<td data-l='Scanned' class='when'>{e(_date(v['scanned_at']))}</td></tr>")
    return "".join(rows)


_REG_COLS = [("Repository", ""), ("Kind", ""), ("Status", ""), ("Runs on its own", "num"), ("Processes", "num"), ("Hosts", "num"), ("Stars", "num"), ("Scanned", "")]


def _reg_head(sortable: bool = False) -> str:
    cells = "".join(f"<th{f' class={c!r}' if c else ''}>" + (f"<button type='button'>{label}</button>" if sortable else label) + "</th>" for label, c in _REG_COLS)
    return f"<thead><tr>{cells}</tr></thead>"


REG_HEAD = _reg_head()


# ------------------------------------------------------------------------ x-ray
# Hook events grouped into the moment of a Claude Code session they fire in. Servers declared in a plugin start with the session.
PHASES = [("start", "Session start"), ("prompt", "Each prompt"), ("tool", "Around tool calls"), ("stop", "Stop and session end"), ("other", "Other events")]


def _phase(when: str) -> str:
    w = str(when).lower().replace(" ", "")
    if w.startswith(("sessionstart", "setup")):
        return "start"
    if w.startswith("userprompt"):
        return "prompt"
    if w.startswith(("pretooluse", "posttool", "permissionrequest")):
        return "tool"
    if w.startswith(("stop", "subagentstop", "sessionend")):
        return "stop"
    return "other"


def _xtype(kind: str) -> str:
    k = str(kind).lower()
    return "hook" if "hook" in k else "mcp" if "mcp" in k else "lsp" if "lsp" in k else "other"


def _by_phase(runs: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k, _ in PHASES}
    for a in runs:
        groups[_phase(a.get("when", ""))].append(a)
    return [(k, label, groups[k]) for k, label in PHASES if groups[k]]


def _legend(runs: list[dict[str, Any]]) -> str:
    present = {_xtype(a.get("type", "")) for a in runs}
    names = [("hook", "Hook"), ("mcp", "MCP server"), ("lsp", "LSP server"), ("other", "Other")]
    return ("<ul class='legend' aria-label='Colour key'>"
            + "".join(f"<li><i class='blk {k}' aria-hidden='true'></i>{label}</li>" for k, label in names if k in present) + "</ul>")


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
def _flap(n: int, start: int = 0) -> str:
    """A number on split-flap tiles. The tiles are decoration; screen readers get the plain number."""
    tiles = "".join(f"<i style='--d:{start + i}'>{e(c)}</i>" for i, c in enumerate(f"{n}"))
    return f"<span class='fl' aria-hidden='true'>{tiles}</span><span class='vh'>{n}</span>"


def _xray_card(sample: dict[str, Any]) -> str:
    runs = sample["auto_runs"]
    lanes, k = [], 0
    for _key, label, items in _by_phase(runs):
        blocks = []
        for a in items[:80]:
            blocks.append(f"<i class='blk {_xtype(a.get('type', ''))}' style='--d:{k}'></i>")
            k += 1
        lanes.append(f"<div class='lane'><dt><b>{len(items)}</b>{e(label)}</dt><dd aria-hidden='true'>{''.join(blocks)}</dd></div>")
    items = "".join(f"<li><b>{e(str(a.get('when', ''))[:28])}</b><code>{e(str(a.get('what', ''))[:110])}</code></li>" for a in runs[:4])
    more = len(runs) - 4
    return (f"<aside class='xray' aria-label='Example registry entry: what runs on its own, and when'>"
            f"<div class='xh'><div><b>X-ray</b><strong>{e(sample['source'])}</strong><span>@ {e(str(sample['commit'])[:12])} · scanned {e(_date(sample['scanned_at']))}</span></div></div>"
            f"{_stamp(sample)}<dl class='lanes'>{''.join(lanes)}</dl>{_legend(runs)}<ol class='xitems'>{items}</ol>"
            "<div class='foot'>" + (f"And {more} more. " if more > 0 else "")
            + f"<a href='{e(_entry_href(sample))}'>Open the full docket</a></div></aside>")


def _landing(cfg: SiteConfig, views: list[dict[str, Any]]) -> str:
    t = _totals(views)
    # The x-ray shows a real entry: the one with the most automatic entry points.
    sample = max(views, key=lambda v: (len(v["auto_runs"]), v.get("stars") or 0), default=None)
    xray = _xray_card(sample) if sample and sample["auto_runs"] else ""
    top = sorted(views, key=lambda v: -(v.get("stars") or 0))[:8]
    idx = json.dumps(sorted(v["source"] for v in views)).replace("<", "\\u003c")
    hero = (
        "<section class='hero'><div class='wrap'><div><div class='kicker'>Supply-chain security for AI coding agents</div>"
        "<h1>Know what a plugin will run before your team installs it.</h1>"
        "<p class='lede'>Claude Code plugins and MCP servers run with your full user access, outside the permission system. "
        "Plugin Warden reads the code first and shows what runs and when.</p>"
        "<form class='check' id='chk' action='registry/' method='get' role='search'><label for='repo'>Check a repository</label>"
        "<div class='row'><input id='repo' name='q' type='text' placeholder='owner/repo' autocomplete='off' autocapitalize='none' spellcheck='false' aria-describedby='chkout'>"
        "<button class='btn p' type='submit'>Check</button></div><div class='out' id='chkout' aria-live='polite'></div></form>"
        f"<script type='application/json' id='idx'>{idx}</script>"
        f"<p class='alt'>Or <a href='docs/#start'>install the CLI</a> and scan anything yourself.</p></div>{xray}</div></section>"
    )
    stats = (
        "<section style='padding-bottom:72px'><div class='wrap'><div class='flaps'>"
        "<div class='fh'><span>Registry totals</span><a href='registry/'>Full board</a></div><div class='fg'>"
        f"<div class='fc'>{_flap(t['repos'], 0)}<span>public plugin and MCP server repos tracked</span></div>"
        f"<div class='fc'>{_flap(t['auto_runs'], 3)}<span>components that run on their own, across {t['with_auto']} of them</span></div>"
        f"<div class='fc'>{_flap(t['processes'], 6)}<span>background processes started at session start</span></div>"
        f"<div class='fc'>{_flap(_checks(), 9)}<span>built-in checks on every scan</span></div></div></div></div></section>"
    )
    why = (
        "<section class='band w'><div class='wrap'><h2>The install prompt does not show you this.</h2><ol class='hidden'>"
        "<li><h3>Hooks run outside the sandbox</h3><p>A hook fires on session start or on every tool call. It is a shell command with your access. "
        "Permission rules and the Bash sandbox govern Claude's own tools, not hooks.</p></li>"
        "<li><h3>Servers start in the background</h3><p>MCP and LSP servers launch as processes when a session starts. Many are fetched fresh from a package registry "
        "each time, with no version pin.</p></li>"
        "<li><h3>Approved today, different tomorrow</h3><p>A plugin that was clean when you reviewed it updates itself. Nobody on the team re-reads it. "
        "That is how a trusted dependency turns into an incident.</p></li></ol></div></section>"
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
    tabs = "".join(f"<button class='tab' type='button' role='tab' id='t-{k}' aria-controls='p-{k}' aria-selected='{'true' if n == 0 else 'false'}'>"
                   f"<small>Lane {n + 1}</small>{label}</button>" for n, (k, label, *_rest) in enumerate(steps))
    panels = "".join(
        f"<div class='panel' role='tabpanel' id='p-{k}' aria-labelledby='t-{k}'><div><h3>{title}</h3><p>{text}</p><pre><code>{e(cmd)}</code></pre></div>"
        f"<div><p class='cap'>{cap}</p><pre class='tape' tabindex='0'><code>{e(sample)}</code></pre></div></div>" for k, _label, title, text, cmd, cap, sample in steps)
    jobs = (f"<section class='band'><div class='wrap'><h2>Four jobs, one tool.</h2><div class='tabs' role='tablist' aria-label='What Plugin Warden does'>{tabs}</div>{panels}</div></section>")
    reg = (
        "<section class='band w'><div class='wrap'><div class='head'>"
        f"<h2>{t['repos']} repositories, scanned in the open.</h2><a class='btn' href='registry/'>See all {t['repos']}</a></div>"
        "<p class='lede'>What each one runs on your machine, which processes it starts and which hosts its code names. "
        f"{t['reviewed']} {'has' if t['reviewed'] == 1 else 'have'} a completed agent review and a verdict. The rest show facts only, with no verdict, until they are reviewed.</p>"
        "<div class='board' style='margin-top:26px'><div class='bh'><span>Arrivals</span><span>Most-starred 8</span></div>"
        f"<div class='tw'><table class='stack'>{REG_HEAD}<tbody>{_reg_rows(top, '')}</tbody></table></div></div></div></section>"
    )
    more = "<a class='btn' href='services/'>Other services</a>" if cfg.extra.get("has_services") else "<a class='btn' href='docs/#teams'>Set it up in ten minutes</a>"
    teams = (
        "<section class='band'><div class='wrap'><h2>Free to run yourself. Paid when you want it reviewed for you.</h2>"
        "<p class='lede' style='margin-top:14px'>The CLI, the policy gate, the nightly watch and the evidence packs are open source and run in your own CI. "
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
        "<div class='wrap'><div class='crumb'>registry</div><h1>The registry</h1>"
        f"<p class='lede' style='margin-top:16px'>{t['repos']} public Claude Code plugin, skill and MCP server repositories. "
        f"Across them: {t['auto_runs']} components that run on their own, {t['processes']} background processes and {t['hosts']} distinct network hosts named in code.</p>"
        "<div class='note'><p><b>How to read this.</b> A verdict appears only after a completed agent review. "
        f"\"Not yet reviewed\" means the static scan ran and its {t['matches']} rule matches are waiting for review. Rule matches are leads, not findings, "
        "so they are counted here and not shown. <a href='../docs/#method'>How the registry works</a>.</p></div>"
        "<div class='tools'><label class='skip' for='q'>Search</label><input id='q' type='search' placeholder='Search by repository or description' autocomplete='off'></div>"
        f"{chips('k', 'Kind', kinds)}{chips('s', 'Status', states)}<p class='count' id='count' aria-live='polite' style='margin-top:18px'></p>"
        f"<div class='board'><div class='bh'><span>Arrivals board</span><span>Sorted by GitHub stars</span></div>"
        f"<div class='tw'><table class='stack' id='reg'>{_reg_head(sortable=True)}<tbody>{_reg_rows(ordered, '../')}</tbody></table>"
        "<p class='none' id='none' hidden>No repository matches. Clear the search or pick another filter.</p></div></div>"
        "<p style='margin:28px 0 64px;color:var(--soft)'>Missing a repository? Add it to <code>registry/targets.toml</code> in a pull request. "
        "Maintainer of one listed here? See the <a href='../docs/#disclosure'>disclosure policy</a>.</p></div>"
    )


def _scan_html(runs: list[dict[str, Any]], cap: int = 60) -> str:
    """The docket x-ray: everything that starts on its own, grouped by the moment in a session it fires."""
    shown, phases = 0, []
    for _key, label, items in _by_phase(runs):
        rows = []
        for a in items:
            if shown >= cap:
                break
            shown += 1
            rows.append(f"<li><span class='ty'><i class='{_xtype(a.get('type', ''))}' aria-hidden='true'></i>{e(a.get('type', ''))}</span>"
                        f"<div><code>{e(a.get('what', ''))}</code><span class='wh'><b>{e(a.get('when', ''))}</b> · declared in {e(a.get('file', ''))}</span></div></li>")
        if rows:
            phases.append(f"<section class='phase'><h3>{e(label)}<span>{len(items)} {'item' if len(items) == 1 else 'items'}</span></h3><ol>{''.join(rows)}</ol></section>")
    return "".join(phases)


def _entry_page(cfg: SiteConfig, v: dict[str, Any]) -> str:
    root = "../../../"
    src = v["source"]
    parts: list[str] = []
    parts.append(f"<div class='wrap'><div class='crumb'><a href='{root}registry/'>registry</a> / {e(src)}</div>")
    fields = [("Kind", e(v["kind_label"])), ("Commit", f"<code>{e(str(v['commit'])[:12])}</code>"), ("Scanned", e(_date(v["scanned_at"]))),
              ("Plugin Warden", e(v["tool_version"]))]
    if v.get("license"):
        fields.append(("License", e(v["license"])))
    fields.append(("Source", f"<a href='{e(v['url'])}'>source</a>"))
    parts.append(
        "<section class='docket' aria-label='Inspection docket'><div class='dk-top'><span>Inspection docket</span>"
        f"<span>{'Agent-reviewed' if v['state'] == 'reviewed' else 'Static scan only'}</span></div>"
        f"<div class='dk-body'><div><h1>{e(src)}</h1>"
        + (f"<p class='lede'>{e(str(v['description'])[:240])}</p>" if v.get("description") else "")
        + f"</div><div class='dk-stamp'>{_stamp(v)}</div></div>"
        "<dl class='fields'>" + "".join(f"<div><dt>{k}</dt><dd>{val}</dd></div>" for k, val in fields) + "</dl></section>")

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

    parts.append("<div class='sec'><span class='lab'>X-ray</span><h2>What runs on its own</h2>")
    if v["auto_runs"]:
        more = f"<p class='count' style='margin-top:10px'>Showing 60 of {len(v['auto_runs'])}.</p>" if len(v["auto_runs"]) > 60 else ""
        parts.append("<p>These start without anyone asking, with the access of the person running Claude Code. Permission rules and the Bash sandbox do not apply to them.</p>"
                     f"<div class='scan'><div class='sh'><span>When it runs</span>{_legend(v['auto_runs'])}</div>{_scan_html(v['auto_runs'])}</div>{more}")
    else:
        parts.append("<div class='scan'><p class='empty'>Nothing. No hooks, monitors, status lines, MCP or LSP servers were found in this repository's plugin config.</p></div>")
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
            parts.append(f"<article class='find {e(f['severity'])}'><div class='sv'>{e(f['severity'])}</div><div class='fb'><h3>{e(f['title'])}</h3>"
                         f"<div class='m'>{e(f['location'])} · {e(f['rule_id'])} · {e(f['category_label'])}</div>"
                         f"<p>{e(f['why'])}</p><p><b>Where to fix.</b> {e(f['fix'])}</p></div></article>")
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
    parts.append("<div style='height:64px'></div></div>")
    return "".join(parts)


def _pricing_page(cfg: SiteConfig) -> str:
    def cta(url: str, label: str) -> str:
        return f"<a class='btn p' href='{e(url or cfg.contact_url)}'>{e(label if url else 'Request a pilot')}</a>"

    def tier(plan: str, name: str, price: str, who: str, items: list[str], button: str) -> str:
        return (f"<div class='tier' data-plan='{plan}'><div class='th'><span class='lab'>Plan</span><h3>{name}</h3></div>"
                f"<div class='fee'><span class='lab'>Fee</span><div class='price'>{price}</div></div><p class='who'>{who}</p>"
                f"<span class='vh'>Includes:</span><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul><div class='go'>{button}</div></div>")

    return (
        "<div class='wrap'><div class='crumb'>pricing</div><h1>Free to run. Paid to have it reviewed.</h1>"
        "<p class='lede' style='margin-top:16px'>Everything that runs on your machines is open source. The paid plans are a review service on top: "
        "we read the plugins your team wants, and we respond when one of them changes.</p>"
        "<div class='form'><div class='fh'><span>Declaration</span><span>Which plan fits</span></div>"
        "<div class='chooser'><div><label for='devs'>Developers using Claude Code</label><input id='devs' type='number' min='1' max='5000' value='20' inputmode='numeric'></div>"
        "<div><label for='revs'>Plugins to review a month</label><input id='revs' type='number' min='0' max='500' value='10' inputmode='numeric'></div>"
        "<output id='pick' for='devs revs' aria-live='polite'>Enter your team size to see which plan fits.</output></div></div>"
        "<div class='tiers'>"
        + tier("community", "Community", "$0", "For individuals and any team that wants to run it themselves.",
               [f"The full CLI, MIT licensed, {_checks()} checks", "Agent review with your own Anthropic API key", "Policy file, CI gate and SARIF output",
                "Nightly watch and update diffs", "Audit evidence packs", "Public registry, badges and JSON API"],
               f"<a class='btn' href='{e(cfg.repo_url)}'>Get it on GitHub</a>")
        + tier("team", "Team", f"${cfg.team_price}<small>/ month</small>", "Up to 25 developers. Pilot pricing.",
               ["Everything in Community", "Reviewed approvals: agent review plus a human second read, 15 plugins a month",
                "Update reviews within one business day when an approved plugin gains reach", "Private reports that never enter the public registry",
                "Policy and CI set up in your GitHub organisation", "Email support"],
               cta(cfg.team_checkout_url, "Start Team"))
        + tier("business", "Business", f"${cfg.business_price}<small>/ month</small>", "Up to 150 developers. Pilot pricing.",
               ["Everything in Team", "50 reviewed approvals a month", "Custom rules for your internal marketplace",
                "Quarterly evidence pack with a walkthrough for your auditor", "Shared channel for questions and alerts"],
               cta(cfg.business_checkout_url, "Start Business"))
        + "</div>"
        f"<p style='margin-top:22px;color:var(--soft)'>Larger than 150 developers, or need on-premises review? <a href='{e(cfg.contact_url)}'>Talk to us</a>.</p>"
        "<div class='faq'><h2>Questions</h2>"
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
        "The plugin, hook and skill checks are written for Claude Code's formats today.</p></details></div><div style='height:72px'></div></div>"
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
<p>Each verdict is printed as a stamp. The stamp word is shorthand. The verdict itself is what the policy file and the API use.</p>
<div class='tw'><table class='stack'><thead><tr><th>Stamp</th><th>Verdict</th><th>When</th></tr></thead><tbody>
<tr><td data-l='Stamp'><span class='stamp sm low'>Cleared</span></td><td data-l='Verdict'><b>Low risk</b></td><td data-l='When'>Nothing of medium severity or above, score under 10</td></tr>
<tr><td data-l='Stamp'><span class='stamp sm caution'>Conditions apply</span></td><td data-l='Verdict'><b>Install with precautions</b></td><td data-l='When'>A medium finding, or score 10 or more</td></tr>
<tr><td data-l='Stamp'><span class='stamp sm review'>Hold</span></td><td data-l='Verdict'><b>Review before installing</b></td><td data-l='When'>Any high finding, or score 40 or more</td></tr>
<tr><td data-l='Stamp'><span class='stamp sm block'>Do not install</span></td><td data-l='Verdict'><b>Do not install</b></td><td data-l='When'>Any critical finding</td></tr>
<tr><td data-l='Stamp'><span class='stamp sm muted'>Not yet reviewed</span></td><td data-l='Verdict'><b>None</b></td><td data-l='When'>Static scan only. The registry gives no verdict without a completed agent review.</td></tr></tbody></table></div>
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
    return (f"<div class='wrap'><div class='doc'><nav class='toc' aria-label='On this page'><span class='lab'>Manifest</span>{nav}</nav><div><div class='crumb' style='margin-top:0'>docs</div>"
            f"<h1 style='margin-bottom:36px'>Documentation</h1>{body}</div></div></div>")


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
            f"<section class='svc' id='{e(sv['id'])}'><div><span class='lab'>Service</span><h2>{e(sv['name'])}</h2>"
            f"<span class='stamp sm'>{'paid pilot' if pilot else e(sv['status'])}</span>"
            f"<p>{e(sv['summary'])}</p>"
            f"<p class='facts'>Delivered with <a href='{e(sv['source_url'])}'>{e(sv['tool'])}</a> · {e(sv['tests'])} {e(sv.get('tests_note') or 'tests')} passed on {e(data['checked'])} · "
            f"<a href='{e(sv['source_url'])}'>source</a></p>{price}"
            f"<a class='btn' href='{e(cfg.contact_url)}'>Request a pilot</a></div>"
            "<div><h3>What you get</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in sv["delivers"]) + "</ul>"
            "<h3>Limits</h3><ul class='lim'>" + "".join(f"<li>{e(x)}</li>" for x in sv["limits"]) + f"</ul>{needs}</div></section>")
    return (
        "<div class='wrap'><div class='crumb'>services</div><h1>Services</h1>"
        f"<p class='lede' style='margin-top:16px'>{len(data['services'])} services, each delivered with an open-source tool you can read and run yourself. "
        "One person does the work, and every limit is written down before you start.</p>"
        "<div class='note'><p><b>These are pilots.</b> There are no paying customers yet, so there are no case studies or testimonials here. "
        f"A service is listed only if its tool's test suite was re-run and passed. That was last done on {e(data['checked'])}.</p></div>"
        + "".join(blocks) + "<div style='height:72px'></div></div>")


# ----------------------------------------------------------------------- assets
_BADGE_COLOURS = {"low": "#1d6a43", "caution": "#875400", "review": "#b3261e", "block": "#7a1410", "muted": "#596067"}


def badge_svg(view: dict[str, Any]) -> str:
    message, key = registry.badge_text(view)
    label = "plugin warden"
    lw, mw = 8 + len(label) * 6.6, 8 + len(message) * 6.6
    w = round(lw + mw)
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='20' role='img' aria-label='{e(label)}: {e(message)}'>"
        f"<title>{e(label)}: {e(message)}</title><rect width='{w}' height='20' rx='3' fill='#17191b'/>"
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
                            body=f"<div class='wrap lost'><span class='stamp muted'>No such consignment</span><h1>Nothing here.</h1><p class='lede' style='margin-top:18px'>Try the <a href='{e(cfg.base_url)}/registry/'>registry</a>.</p></div>",
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
