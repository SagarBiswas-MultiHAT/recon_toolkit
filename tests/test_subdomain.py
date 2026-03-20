from modules.subdomain_enum import _normalize_subdomain


def test_subdomain_dedup_and_normalization() -> None:
    domain = "example.com"
    values = {
        _normalize_subdomain("A.EXAMPLE.COM", domain),
        _normalize_subdomain("a.example.com", domain),
        _normalize_subdomain("*.b.example.com", domain),
        _normalize_subdomain("not-example.org", domain),
    }
    assert "a.example.com" in values
    assert "b.example.com" in values
    assert None in values
