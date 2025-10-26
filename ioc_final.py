pip install streamlit requests jinja2 python-evtx -q; $code=@'
# ioc_final.py — Any-hash & External-IP Investigator (English, final)
import re, requests, datetime, json, base64, os, streamlit as st
from jinja2 import Template

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None

VT_API_KEY = "YOUR_KEY_HERE"
CACHE_FILE = "vt_cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE,"r",encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(c):
    try:
        with open(CACHE_FILE,"w",encoding="utf-8") as f:
            json.dump(c,f,indent=2)
    except:
        pass

vt_cache = load_cache()

def extract_iocs(text):
    hashes, ips = [], []
    if not text:
        return {"hashes":hashes,"ips":ips}
    for m in re.findall(r"\b[a-fA-F0-9]{32,128}\b", text):
        h = m.upper()
        if h not in hashes:
            hashes.append(h)
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        try:
            parts = [int(p) for p in ip.split(".")]
            if parts[0]==10 or (parts[0]==192 and parts[1]==168) or (parts[0]==172 and 16<=parts[1]<=31):
                continue
            if all(0<=p<=255 for p in parts) and ip not in ips:
                ips.append(ip)
        except:
            continue
    return {"hashes":hashes,"ips":ips}

def vt_check_hash(h):
    if h in vt_cache:
        return h, vt_cache[h]
    if not VT_API_KEY:
        res={"status":"no_key"}
        vt_cache[h]=res
        return h,res
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey":VT_API_KEY}, timeout=15)
        if r.status_code==200:
            attrs=r.json().get("data",{}).get("attributes",{})
            stats=attrs.get("last_analysis_stats",{})
            total=sum(stats.values()) if isinstance(stats,dict) else 0
            mal=stats.get("malicious",0) if isinstance(stats,dict) else 0
            res={"status":"ok","malicious":mal,"total":total,"link":f"https://www.virustotal.com/gui/file/{h}"}
        elif r.status_code==404:
            res={"status":"not_found"}
        else:
            res={"status":"error","code":r.status_code,"text":r.text}
    except Exception as e:
        res={"status":"error","text":str(e)}
    vt_cache[h]=res
    return h,res

def ip_info(ip):
    try:
        r=requests.get(f"http://ip-api.com/json/{ip}",timeout=6)
        if r.status_code==200:
            j=r.json()
            return {"status":"ok","country":j.get("country"),"isp":j.get("isp"),"link":f"https://abuseipdb.com/check/{ip}"}
    except Exception as e:
        return {"status":"error","text":str(e)}
    return {"status":"error"}

HTML_TEMPLATE = Template("""
<!doctype html>
<html><head><meta charset='utf-8'><title>IOC Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body{background:#f6f8fa;padding:20px;font-family:Arial,Helvetica,sans-serif}
.card{margin-bottom:12px}
.hdr{display:flex;align-items:center;gap:12px}
.muted{color:#6c757d}
.badge-clean{background:#198754;color:#fff;padding:4px 8px;border-radius:6px}
.badge-susp{background:#ffc107;color:#000;padding:4px 8px;border-radius:6px}
.badge-mal{background:#dc3545;color:#fff;padding:4px 8px;border-radius:6px}
.table-fixed {width:100%; border-collapse:collapse;}
.table-fixed th, .table-fixed td {border:1px solid #ddd; padding:8px;}
.table-fixed th {background:#e9ecef;}
tr:nth-child(even) {background:#fbfbfb;}
</style></head><body>
<div class="container">
<header class="mb-4">
<div class="hdr">
{% if logo_b64 %}
<img src="data:image/png;base64,{{ logo_b64 }}" style="height:60px;border-radius:6px"/>
{% endif %}
<div><h2 class="mb-0">IOC Investigation Report</h2>
<div class="muted">Generated: {{ date }}{% if analyst %} — Analyst: {{ analyst }}{% endif %}</div>
</div></div>
<div class="row g-2 mt-3">
<div class="col-auto"><div class="card p-2"><strong>Hashes</strong><div class="muted">{{ summary.hashes }}</div></div></div>
<div class="col-auto"><div class="card p-2"><strong>External IPs</strong><div class="muted">{{ summary.ips }}</div></div></div>
</div>
</header>
<section><h5>Hashes (VirusTotal)</h5>
<table class="table-fixed">
<tr><th>Hash</th><th>VT Result</th><th>Severity</th></tr>
{% for r in results if r.type=='Hash' %}
<tr>
<td style="font-family:monospace;">{{ r.value }}</td>
<td>{{ r.result_text }} {% if r.link %}- <a href="{{ r.link }}" target="_blank">VT Link</a>{% endif %}</td>
<td>{% if r.severity=='clean' %}<span class="badge-clean">CLEAN</span>{% elif r.severity=='suspicious' %}<span class="badge-susp">SUSPICIOUS</span>{% elif r.severity=='malicious' %}<span class="badge-mal">MALICIOUS</span>{% else %}<span class="muted">UNKNOWN</span>{% endif %}</td>
</tr>
{% endfor %}
{% if not (results | selectattr('type','equalto','Hash') | list) %}
<tr><td colspan="3" class="muted">No hashes were checked.</td></tr>
{% endif %}
</table></section>
<section class="mt-4"><h5>External IPs</h5>
{% for r in results if r.type=='IP' %}
<div class="card p-3"><strong>{{ r.value }}</strong><div class="mt-1">{{ r.result_text }} — <a href="{{ r.link }}" target="_blank">AbuseIPDB</a></div></div>
{% endfor %}
{% if not (results | selectattr('type','equalto','IP') | list) %}
<p class="muted">No external IPs found.</p>
{% endif %}
</section>
</div></body></html>
""")

def generate_report(iocs, results, summary, analyst="", logo_b64=""):
    return HTML_TEMPLATE.render(date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                iocs=iocs, results=results, summary=summary,
                                analyst=analyst, logo_b64=logo_b64)

st.set_page_config(page_title='IOC Investigator', page_icon='🕵️', layout='wide')
st.title('🕵️ IOC — Any-hash & External-IP Investigator')

analyst = st.text_input('Analyst / Identifier (appears in report):', value='')
logo_file = st.file_uploader('Upload logo (optional)', type=['png','jpg','jpeg'])
logo_b64 = ""
if logo_file:
    logo_b64 = base64.b64encode(logo_file.read()).decode('utf-8')
    st.image(logo_file, width=120)

st.markdown('Paste text or upload EVTX/TXT log for any Hash and external IP analysis.')

option = st.radio('Input method:', ['Paste text', 'Upload file'])
text = ''
if option=='Paste text':
    text = st.text_area('Paste your log here:', height=260)
else:
    f = st.file_uploader('Choose TXT or EVTX file', type=['txt','evtx'])
    if f:
        if f.name.lower().endswith('.txt'):
            text = f.read().decode('utf-8', errors='ignore')
        elif f.name.lower().endswith('.evtx') and Evtx:
            with Evtx(f) as log:
                text="\n".join([r.xml() for r in log.records()])

if st.button('Start Analysis 🚀') and text.strip():
    with st.spinner('Analyzing...'):
        iocs = extract_iocs(text)
        st.subheader('Detected IOCs:')
        st.json(iocs)
        results=[]
        for h in iocs.get('hashes', []):
            h,res = vt_check_hash(h)
            if res.get('status')=='ok':
                txt=f"{res.get('malicious')}/{res.get('total')} malicious"
                sev='clean' if res.get('malicious',0)==0 else 'suspicious' if res.get('malicious',0)<5 else 'malicious'
                link=res.get('link')
            elif res.get('status')=='not_found':
                txt='Not found in VT'
                link=''
                sev='unknown'
            else:
                txt=f"Error: {res.get('text',res)}"
                link=''
                sev='unknown'
            results.append({'type':'Hash','value':h,'result_text':txt,'link':link,'severity':sev})
        save_cache(vt_cache)

        for ip in iocs.get('ips',[]):
            info = ip_info(ip)
            txt = f"Country: {info.get('country')} ISP: {info.get('isp')}" if info.get('status')=='ok' else f"Error: {info.get('text',info)}"
            link = info.get('link') if info.get('status')=='ok' else f"https://abuseipdb.com/check/{ip}"
            results.append({'type':'IP','value':ip,'result_text':txt,'link':link})

        summary={'hashes':len([r for r in results if r['type']=='Hash']),
                 'ips':len([r for r in results if r['type']=='IP'])}

        html=generate_report(iocs,results,summary,analyst=analyst,logo_b64=logo_b64)
        filename=f"IOC_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        st.download_button('Download HTML Report', html, file_name=filename, mime='text/html')
'@; Set-Content -Path "ioc_final.py" -Value $code -Encoding UTF8; streamlit run ioc_final.py
