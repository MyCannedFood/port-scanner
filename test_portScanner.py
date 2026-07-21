import asyncio
import os
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from portScanner import SERVICE_PORTS, PortScanner


@pytest.fixture
def scanner():
    return PortScanner(api_key="test-key")


@pytest.fixture
def scanner_no_key():
    return PortScanner()


class TestParseBanner:
    def test_ssh(self):
        s, v = PortScanner._parse_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert s == "OpenSSH"
        assert v == "8.9p1"

    def test_ssh_with_dash(self):
        s, v = PortScanner._parse_banner(b"SSH-2.0-OpenSSH_8.9p1-Ubuntu-3")
        assert s == "OpenSSH"
        assert v.startswith("8.9")

    def test_ftp(self):
        s, v = PortScanner._parse_banner(b"220 ProFTPD 1.3.5 Server Ready")
        assert s == "ProFTPD"
        assert v == "1.3.5"

    def test_http_server_header(self):
        s, v = PortScanner._parse_banner(
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
        )
        assert s == "Apache"
        assert v == "2.4.41"

    def test_generic_slash(self):
        s, v = PortScanner._parse_banner(b"nginx/1.18.0")
        assert s == "nginx"
        assert v == "1.18.0"

    def test_generic_space(self):
        s, v = PortScanner._parse_banner(b"Postfix 3.4.8 ready")
        assert s == "Postfix"
        assert v == "3.4.8"

    def test_unknown(self):
        s, v = PortScanner._parse_banner(b"garbage data here")
        assert s is None
        assert v is None

    def test_empty(self):
        s, v = PortScanner._parse_banner(b"")
        assert s is None
        assert v is None


class TestGetCveText:
    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_success_with_cves(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability one"}
                        ],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability two"}
                        ],
                    }
                },
            ]
        }
        mock_get.return_value = mock_response

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "CVE-2024-0001" in result
        assert "CVE-2024-0002" in result
        assert "Found 2 CVE(s)" in result
        mock_get.assert_called_once()

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_success_no_cves(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        result = await scanner._get_cve_text("NonExistent", "1.0")

        assert "No CVEs found" in result

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_rate_limit_then_success(self, mock_get, scanner):
        mock_response_429 = MagicMock()
        mock_response_429.status_code = 429
        mock_response_429.headers = {"Retry-After": "1"}

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"vulnerabilities": []}

        mock_get.side_effect = [mock_response_429, mock_response_200]

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "No CVEs found" in result
        assert mock_get.call_count == 2

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_rate_limit_bad_retry_after(self, mock_get, scanner):
        mock_response_429 = MagicMock()
        mock_response_429.status_code = 429
        mock_response_429.headers = {"Retry-After": "not-a-number"}

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"vulnerabilities": []}

        mock_get.side_effect = [mock_response_429, mock_response_200]

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "No CVEs found" in result

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_http_error(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("500 Server Error")
        )
        mock_get.return_value = mock_response

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "CVE lookup failed" in result

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_json_parse_error(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "Failed to parse CVE response" in result

    @patch("portScanner.requests.get")
    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("500 Server Error")
        )
        mock_get.return_value = mock_response

        result = await scanner._get_cve_text("OpenSSH", "8.9")

        assert "CVE lookup failed" in result
        assert mock_get.call_count == 3


class TestScanPort:
    @patch.object(PortScanner, "_get_cve_text", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_connection_refused(self, mock_cve, scanner):
        with patch("portScanner.asyncio.open_connection") as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError

            await scanner._scan_port("127.0.0.1", 22, 1, 0)

        assert 22 not in scanner.open_ports
        mock_cve.assert_not_called()

    @patch.object(PortScanner, "_get_cve_text", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_connection_timeout(self, mock_cve, scanner):
        with patch("portScanner.asyncio.open_connection") as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError

            await scanner._scan_port("127.0.0.1", 22, 1, 0)

        assert 22 not in scanner.open_ports
        mock_cve.assert_not_called()

    @patch.object(PortScanner, "_get_cve_text", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_banner_timeout(self, mock_cve, scanner):
        mock_cve.return_value = ""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("portScanner.asyncio.open_connection") as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)

            await scanner._scan_port("127.0.0.1", 22, 1, 0)

        assert 22 in scanner.open_ports
        mock_writer.close.assert_called_once()

    @patch.object(PortScanner, "_get_cve_text", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_successful_scan(self, mock_cve, scanner):
        mock_cve.return_value = ""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1 ")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("portScanner.asyncio.open_connection") as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)

            await scanner._scan_port("127.0.0.1", 22, 1, 0)

        assert 22 in scanner.open_ports
        mock_cve.assert_awaited_once_with("OpenSSH", "8.9p1")
        mock_writer.close.assert_called_once()

    @patch.object(PortScanner, "_get_cve_text", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_port_based_service_fallback(self, mock_cve, scanner):
        mock_cve.return_value = ""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"\x00\x01\x02")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("portScanner.asyncio.open_connection") as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)

            await scanner._scan_port("127.0.0.1", 80, 1, 0)

        assert 80 in scanner.open_ports
        mock_cve.assert_awaited_once_with("HTTP", "unknown")


class TestScanValidation:
    @pytest.mark.asyncio
    async def test_invalid_port_start(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", port_start=0)
        assert scanner.open_ports == []

    @pytest.mark.asyncio
    async def test_invalid_port_end(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", port_end=70000)
        assert scanner.open_ports == []

    @pytest.mark.asyncio
    async def test_port_start_greater_than_end(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", port_start=100, port_end=50)
        assert scanner.open_ports == []

    @pytest.mark.asyncio
    async def test_timeout_zero(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", timeout=0)
        assert scanner.open_ports == []

    @pytest.mark.asyncio
    async def test_threads_zero(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", threads=0)
        assert scanner.open_ports == []

    @pytest.mark.asyncio
    async def test_delay_negative(self, scanner):
        with patch("portScanner.PortScanner._scan_port"):
            await scanner.scan("127.0.0.1", delay=-1)
        assert scanner.open_ports == []


class TestApiKey:
    def test_key_from_constructor(self):
        s = PortScanner(api_key="my-key")
        assert s.api_key == "my-key"
        assert s._rate_interval == 0.6

    def test_key_from_env(self):
        with patch.dict(os.environ, {"NVD_API_KEY": "env-key"}):
            s = PortScanner()
        assert s.api_key == "env-key"
        assert s._rate_interval == 0.6

    def test_no_key(self, scanner_no_key):
        assert scanner_no_key.api_key is None
        assert scanner_no_key._rate_interval == 6.0

    def test_constructor_overrides_env(self):
        with patch.dict(os.environ, {"NVD_API_KEY": "env-key"}):
            s = PortScanner(api_key="explicit-key")
        assert s.api_key == "explicit-key"


class TestServicePorts:
    def test_known_ports(self):
        assert SERVICE_PORTS[22] == "SSH"
        assert SERVICE_PORTS[80] == "HTTP"
        assert SERVICE_PORTS[443] == "HTTPS"
        assert SERVICE_PORTS[3306] == "MySQL"
        assert SERVICE_PORTS[6379] == "Redis"

    def test_unknown_port_not_present(self):
        assert 9999 not in SERVICE_PORTS


class TestNormalizeVersion:
    def test_strips_patch_letter(self):
        assert PortScanner._normalize_version("8.9p1") == "8.9"

    def test_strips_patch_with_dash(self):
        assert PortScanner._normalize_version("6.6.1p1") == "6.6"

    def test_keeps_major_minor(self):
        assert PortScanner._normalize_version("1.2.3") == "1.2"

    def test_already_short(self):
        assert PortScanner._normalize_version("1.0") == "1.0"

    def test_long_version(self):
        assert PortScanner._normalize_version("10.20.30.40") == "10.20"

    def test_empty_string(self):
        assert PortScanner._normalize_version("") == ""


class TestMain:
    def test_valid_target(self):
        with patch("portScanner.socket.gethostbyname", return_value="127.0.0.1"):
            with patch("portScanner._setup_logging"):
                with patch("portScanner.asyncio.run"):
                    from portScanner import main
                    with patch("sys.argv", ["portScanner", "127.0.0.1"]):
                        main()

    def test_invalid_hostname_logs_error(self):
        with patch("portScanner.socket.gethostbyname", side_effect=socket.gaierror):
            with patch("portScanner.logger.error") as mock_log:
                from portScanner import main
                with patch("sys.argv", ["portScanner", "invalid-host"]):
                    main()
                mock_log.assert_called_once_with("Invalid IP address or hostname")

    def test_keyboard_interrupt_caught(self):
        with patch("portScanner.socket.gethostbyname", return_value="127.0.0.1"):
            with patch("portScanner._setup_logging"):
                with patch("portScanner.asyncio.run", side_effect=KeyboardInterrupt):
                    with patch("portScanner.logger.warning") as mock_log:
                        from portScanner import main
                        with patch("sys.argv", ["portScanner", "127.0.0.1"]):
                            main()
                        mock_log.assert_called_once_with("Scan cancelled by user")


class TestFileOutput:
    @pytest.mark.asyncio
    async def test_file_handler_logs_scan_results(self, tmp_path, scanner):
        output_file = tmp_path / "results.txt"
        from portScanner import _setup_logging, logger
        original_handlers = list(logger.handlers)
        try:
            _setup_logging(str(output_file))

            mock_reader = AsyncMock()
            mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1 ")
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.wait_closed = AsyncMock()

            with patch.object(PortScanner, "_get_cve_text", return_value=""):
                with patch("portScanner.asyncio.open_connection") as mock_conn:
                    mock_conn.return_value = (mock_reader, mock_writer)
                    await scanner._scan_port("127.0.0.1", 22, 1, 0)

            content = output_file.read_text()
            assert "OPEN" in content
            assert "22" in content
            assert "OpenSSH" in content
        finally:
            logger.handlers = original_handlers


class TestIntegration:
    @patch.object(PortScanner, "_get_cve_text", return_value="")
    @pytest.mark.asyncio
    async def test_scan_local_server(self, mock_cve):
        server_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"

        async def handle_client(reader, writer):
            await reader.read(1024)
            writer.write(server_banner)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        async with server:
            scanner = PortScanner(api_key="test-key")
            await scanner.scan("127.0.0.1", port_start=addr[1], port_end=addr[1], timeout=2, threads=1, delay=0)

        assert addr[1] in scanner.open_ports
        mock_cve.assert_awaited_once_with("OpenSSH", "8.9p1")
