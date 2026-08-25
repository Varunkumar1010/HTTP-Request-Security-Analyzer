from app.analyzer import analyze_request

def test_missing_headers():
    r=analyze_request({"method":"GET","url":"/","headers":{},"body":""})
    assert any(x["title"]=="Missing Content-Security-Policy" for x in r["findings"])

def test_cookie():
    r=analyze_request({"method":"GET","url":"/","headers":{"Cookie":"session=demo"},"body":""})
    assert any(x["id"]=="COOKIE-001" for x in r["findings"])

def test_method():
    r=analyze_request({"method":"DELETE","url":"/users/1","headers":{},"body":""})
    assert any(x["id"]=="METHOD-001" for x in r["findings"])

def test_input():
    r=analyze_request({"method":"GET","url":"/search?q=../admin","headers":{},"body":""})
    assert any(x["id"]=="INPUT-001" for x in r["findings"])

def test_score():
    r=analyze_request({"method":"GET","url":"/","headers":{},"body":""})
    assert 0 <= r["summary"]["risk_score"] <= 100
