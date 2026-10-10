"""Regression tests for HTML report output safety."""

from utils import report_gen


def test_html_report_builders_escape_untrusted_values():
    hostile = '<script>alert("xss")</script>'
    finding_html = report_gen.build_findings_html([{
        "severity": 'HIGH\"><script>alert(1)</script>',
        "type": hostile,
        "location": hostile,
        "detail": hostile,
        "payload": hostile,
        "recommendation": hostile,
        "timestamp": hostile,
    }])
    ports_html = report_gen.build_ports_html([{
        "port": hostile, "state": hostile, "service": hostile, "banner": hostile,
    }])
    tech_html = report_gen.build_tech_html([{
        "tech": hostile, "version": hostile, "cve_hints": [hostile], "timestamp": hostile,
    }])
    subdomains_html = report_gen.build_subdomains_html([{
        "fqdn": hostile, "ips": [hostile], "timestamp": hostile,
    }])
    creds_html = report_gen.build_creds_html([{
        "username": hostile, "password": hostile, "service": hostile,
        "host": hostile, "timestamp": hostile,
    }])
    webpaths_html = report_gen.build_webpaths_html([{
        "status": 200, "url": hostile, "size": hostile, "note": hostile,
    }])

    for rendered in (finding_html, ports_html, tech_html, subdomains_html, creds_html, webpaths_html):
        assert "<script>" not in rendered
        assert "&lt;script&gt;" in rendered

    assert 'sev-HIGH"><script>' not in finding_html
    assert 'sev-INFO' in finding_html


def test_html_escape_helper_escapes_metadata_and_quotes():
    assert report_gen.esc('<img src=x onerror="alert(1)">') == (
        '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'
    )
