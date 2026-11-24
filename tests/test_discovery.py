import asyncio
import inspect

import pytest

from modules import discovery


@pytest.mark.parametrize(
    "subnet",
    [
        "8.8.8.0/24",
        "192.168.0.0/16",
        "127.0.0.1/32",
        "224.0.0.0/24",
        "2001:db8::/64",
    ],
)
@pytest.mark.unit
def test_async_scan_network_rejects_out_of_scope_ranges(subnet):
    with pytest.raises(ValueError):
        asyncio.run(discovery.async_scan_network(subnet))


@pytest.mark.unit
def test_async_scan_network_accepts_private_host_and_returns_open_ports(monkeypatch):
    async def scan_ports(ip, ports, timeout):
        assert ip == "192.168.10.5"
        assert ports == [80]
        assert timeout == 0.25
        return [80]

    monkeypatch.setattr(discovery, "async_scan_ports", scan_ports)

    results = asyncio.run(
        discovery.async_scan_network(
            "192.168.10.5/32",
            ports=[80],
            timeout=0.25,
        )
    )

    assert results == [{"ip": "192.168.10.5", "open_ports": [80]}]


@pytest.mark.unit
def test_async_scan_ports_bounds_concurrent_checks(monkeypatch):
    active = 0
    maximum_active = 0

    async def fake_scan_port(_ip, port, _timeout):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.001)
        active -= 1
        return port % 2 == 0

    monkeypatch.setattr(discovery, "async_scan_port", fake_scan_port)
    ports = list(range(discovery.MAX_CONCURRENT_PORT_CHECKS * 3))

    opened = asyncio.run(discovery.async_scan_ports("192.168.10.5", ports))

    assert opened == ports[::2]
    assert 1 < maximum_active <= discovery.MAX_CONCURRENT_PORT_CHECKS


@pytest.mark.unit
def test_async_scan_port_times_out_and_propagates_cancellation(monkeypatch):
    async def never_connect(_ip, _port):
        await asyncio.sleep(60)

    monkeypatch.setattr(asyncio, "open_connection", never_connect)
    assert not asyncio.run(discovery.async_scan_port("192.168.10.5", 80, 0.001))

    async def cancel_connection():
        task = asyncio.create_task(
            discovery.async_scan_port("192.168.10.5", 80, 30)
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_connection())


@pytest.mark.unit
def test_sync_scanner_signature_and_arguments_remain_compatible(monkeypatch):
    async def fake_scan_network(subnet, ports, timeout):
        return [{"subnet": subnet, "ports": ports, "timeout": timeout}]

    monkeypatch.setattr(discovery, "async_scan_network", fake_scan_network)
    signature = inspect.signature(discovery.scan_target_network)
    assert list(signature.parameters) == ["subnet", "ports", "timeout"]
    assert discovery.scan_target_network("192.168.10.0/24", [80], 1.5) == [
        {
            "subnet": "192.168.10.0/24",
            "ports": [80],
            "timeout": 1.5,
        }
    ]


@pytest.mark.unit
def test_sync_scanner_rejects_call_from_running_event_loop():
    async def call_sync_scanner():
        with pytest.raises(RuntimeError, match="use the corresponding async_scan"):
            discovery.scan_target_network("192.168.10.0/24")

    asyncio.run(call_sync_scanner())


@pytest.mark.integration
def test_async_scan_port_finds_a_local_listener():
    async def scan_local_service():
        server = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        port = server.sockets[0].getsockname()[1]
        try:
            return await discovery.async_scan_port("127.0.0.1", port, timeout=1)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(scan_local_service())
