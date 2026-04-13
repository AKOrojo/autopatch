import pytest
from src.api.services.scanner_service import get_scanner_backend, ScannerBackend

def test_get_openvas_backend():
    backend = get_scanner_backend("openvas")
    assert isinstance(backend, ScannerBackend)

def test_get_nuclei_backend():
    backend = get_scanner_backend("nuclei")
    assert isinstance(backend, ScannerBackend)

def test_get_unknown_backend():
    with pytest.raises(ValueError, match="Unknown scanner"):
        get_scanner_backend("nessus")
