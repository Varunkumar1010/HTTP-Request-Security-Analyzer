import re
from typing import Dict, List, Any

SEVERITY_POINTS = {"LOW": 1, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 10}

def finding(fid, severity, title, description, recommendation):
    return {"id": fid, "severity": severity, "title": title,
            "description": description, "recommendation": recommendation}

def parse_cookie_header(value):
    result={}
    for item in value.split(";"):
        if "=" in item:
            k,v=item.split("=",1); result[k.strip()]=v.strip()
    return result

def analyze_security_headers(headers):
    findings=[]
    checks=[
        ("content-security-policy","MEDIUM","Missing Content-Security-Policy",
         "CSP was not observed.","Review and deploy an appropriate CSP."),
        ("x-content-type-options","LOW","Missing X-Content-Type-Options",
         "The header was not observed.","Consider X-Content-Type-Options: nosniff."),
        ("strict-transport-security","LOW","Missing Strict-Transport-Security",
         "HSTS was not observed.","For HTTPS applications, consider an appropriate HSTS policy.")
    ]
    for i,(h,s,t,d,r) in enumerate(checks,1):
        if h not in headers:
            findings.append(finding(f"HDR-{i:03d}",s,t,d,r))
    return findings

def analyze_cookies(headers):
    value=headers.get("cookie","")
    if not value: return []
    cookies=parse_cookie_header(value)
    names={"session","sessionid","session_id","sid","auth","token","access_token","jwt"}
    if any(k.lower() in names for k in cookies):
        return [finding("COOKIE-001","MEDIUM","Sensitive Session Cookie Observed",
                         "A cookie appears to represent a session or authentication token.",
                         "Use safe demo data and review Secure, HttpOnly and SameSite protections.")]
    return []

def analyze_methods(method):
    if method.upper()=="TRACE":
        return [finding("METHOD-002","HIGH","TRACE Method Observed",
                         "TRACE was observed.","Disable TRACE unless explicitly required.")]
    if method.upper() in {"PUT","DELETE","CONNECT"}:
        return [finding("METHOD-001","MEDIUM","Sensitive HTTP Method Observed",
                         f"The request uses {method.upper()}.",
                         "Verify authentication and authorization controls.")]
    return []

def analyze_authentication(headers):
    if headers.get("authorization","").lower().startswith("basic "):
        return [finding("AUTH-001","MEDIUM","Basic Authentication Observed",
                         "Basic authentication was observed.",
                         "Use HTTPS and review whether stronger authentication is appropriate.")]
    return []

def analyze_cors(headers):
    origin=headers.get("origin","").strip().lower()
    if origin in {"null","*"}:
        return [finding("CORS-001","MEDIUM","Broad or Null Origin Observed",
                         f"Origin: {origin}.","Review CORS policy and avoid unnecessarily broad origins.")]
    return []

def analyze_information_disclosure(headers):
    out=[]
    for h in ("server","x-powered-by"):
        if h in headers:
            out.append(finding("INFO-001","LOW","Technology Disclosure Header",
                                f"The {h} header may reveal implementation details.",
                                "Minimize unnecessary technology disclosure."))
    return out

def analyze_suspicious_input(url, body=""):
    combined=(url+" "+body).lower()
    patterns=[
        (r"\.\./","path traversal-style indicator"),
        (r"%2e%2e","encoded traversal-style indicator"),
        (r"<script","script-tag indicator"),
        (r"union\s+select","SQL injection-style indicator"),
        (r"\bor\s+1\s*=\s*1\b","boolean SQL injection-style indicator")
    ]
    hits=[desc for pat,desc in patterns if re.search(pat,combined,re.I)]
    if hits:
        return [finding("INPUT-001","HIGH","Suspicious Input Pattern",
                         "Observed: "+", ".join(hits),
                         "Validate/normalize input, use parameterized queries and manually validate the finding.")]
    return []

def calculate_risk(findings):
    score=min(100,sum(SEVERITY_POINTS.get(x["severity"],0) for x in findings))
    level="CRITICAL" if score>=20 else "HIGH" if score>=12 else "MEDIUM" if score>=5 else "LOW" if score else "INFO"
    return {"score":score,"level":level}

def analyze_request(request):
    method=request.get("method","GET").upper()
    url=request.get("url","/")
    headers={str(k).lower():str(v) for k,v in request.get("headers",{}).items()}
    body=request.get("body","")
    findings=[]
    for fn,args in [
        (analyze_security_headers,(headers,)),(analyze_cookies,(headers,)),
        (analyze_methods,(method,)),(analyze_authentication,(headers,)),
        (analyze_cors,(headers,)),(analyze_information_disclosure,(headers,)),
        (analyze_suspicious_input,(url,body))
    ]: findings.extend(fn(*args))
    risk=calculate_risk(findings)
    return {"request":{"method":method,"url":url,"headers":headers,"body":body},
            "summary":{"risk_score":risk["score"],"risk_level":risk["level"],"finding_count":len(findings)},
            "findings":findings}
