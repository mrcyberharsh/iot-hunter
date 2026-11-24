import pytest
from fastapi import HTTPException
from webapp import validate_ports, validate_subnets

pytestmark = pytest.mark.unit


def test_private_subnet_allowed():
    assert validate_subnets("192.168.10.0/24") == ["192.168.10.0/24"]

@pytest.mark.parametrize("value", ["8.8.8.0/24", "192.168.1.0/16", "2001:db8::/64", "127.0.0.1/32"])
def test_non_private_or_oversized_rejected(value):
    with pytest.raises(HTTPException):
        validate_subnets(value)

def test_multiple_private_ranges():
    assert len(validate_subnets("192.168.1.0/24,10.0.0.1/32")) == 2

def test_port_allowlist():
    assert validate_ports([22, 443]) == [22, 443]
    with pytest.raises(HTTPException):
        validate_ports([3389])
