#!/usr/bin/env python3
"""Render the real consent markup with harmless sample values, without a server login."""
import base64
from pathlib import Path
import re
import sys

repo = Path(__file__).resolve().parents[4]
output = Path(sys.argv[1]).resolve()
source = (repo / 'src/Agora.Web/Pages/Connect/Authorize.cshtml').read_text()
intro = source[source.index('<div class="max-w-md'):source.index('  @if (Model.Error')]
body = source.split('  else\n  {\n', 1)[1].rsplit('  }\n</div>', 1)[0]
body = body.replace('@Model.DeviceName', 'AgoraCapture on Alex\'s MacBook').replace('@Model.Email', 'alex@example.com')
body = re.sub(r'^.*(?:@Html.AntiForgeryToken|<input type="hidden").*\n', '', body, flags=re.M)
body = body.replace('<form method="post" action="/connect/authorize"', '<div').replace('</form>', '</div>')
body = re.sub(r'type="submit" name="decision" value="[^"]*"', 'type="button"', body)
fonts = []
for family, filename, weight in [('DM Sans', 'DMSans-Regular.ttf', 400), ('DM Sans', 'DMSans-Medium.ttf', 500), ('DM Sans', 'DMSans-Semibold.ttf', 600), ('Instrument Serif', 'InstrumentSerif-Regular.ttf', 400)]:
    data = (repo / 'clients/macos/AgoraCapture/Resources/Fonts' / filename).read_bytes()
    fonts.append(f"@font-face{{font-family:'{family}';font-weight:{weight};src:url(data:font/ttf;base64,{base64.b64encode(data).decode()}) format('truetype')}}")
css = (repo / 'src/Agora.Web/wwwroot/css/site.css').read_text()
layout = (repo / 'src/Agora.Web/Pages/Shared/_Layout.cshtml').read_text()
header = layout[layout.index('  <header'):layout.index('      @if (isAuthenticated)')]
header += '''<span class="inline-flex items-center gap-2 rounded-lg border border-border bg-white px-3 py-1.5 text-sm text-ink-light"><span class="leading-tight"><span class="block text-xs text-ink-light">Alex</span><span class="block text-[10px] text-ink-muted">alex@example.com</span></span></span></div></header>'''
html = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect an app - Agora</title><style>{css}\n{''.join(fonts)}</style><body class="bg-cream text-ink min-h-screen relative"><div style="position:fixed;inset:0;background:rgba(255,255,255,0.75);pointer-events:none"></div>{header}<main class="max-w-5xl mx-auto px-6 py-10 relative z-10">{intro}{body}</div></main><footer class="border-t border-border mt-8 relative z-10"><div class="max-w-5xl mx-auto px-6 py-6 text-xs text-ink-muted">Agora - Self hosted secure file transfer</div></footer></body></html>'''
output.mkdir(parents=True, exist_ok=True)
(output / 'agora-approval.html').write_text(html)
