"""仓库级离线守门(2026-09-25 审阅 S7):任何测试都不得访问非 loopback 网络。

背景:本仓库的测试一律离线(假 provider / 假 WS),但守门之前只靠各处自觉注入替身 ——
worker 曾因 monkeypatch 打错目标,让一次真实 CLI 调用用假凭证去连了 Route C 端点
(握手即被拒,无计费);审阅还实测到:本机设了 `HTTP(S)_PROXY` 时,「拦截 getaddrinfo/
socket.connect」这类守门仍可能**经代理**出网。因此这里做三层自动守门:

1. **清除代理变量**:每个测试前删掉 `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY` 等
   (大小写都删),杜绝「经代理绕过本地拦截」;
2. **拦截地址解析与连接**:非 loopback 的 `socket.getaddrinfo` / `socket.connect` 一律
   `pytest.fail`,任何忘记注入假 provider 的测试当场红灯;
3. 允许的真实用途只有 loopback(127.0.0.0/8、::1、localhost)与 Unix domain socket
   (地址不是 (host, port) 元组的情况)。

只影响测试进程:fixture 用 monkeypatch,测试结束自动还原。
"""

from __future__ import annotations

import socket

import pytest

_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "FTP_PROXY",
    "ftp_proxy",
)

_LOOPBACK_HOSTS = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def _is_loopback(host: object) -> bool:
    """loopback 判定:只放行本机回环与 Unix socket(非 (host, port) 形态)。"""

    import ipaddress

    if host is None:
        return True
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii", "replace")
        except Exception:  # noqa: BLE001 —— 解不开的字节地址按不安全处理
            return False
    if not isinstance(host, str):
        return False
    name = host.strip().strip("[]").casefold()
    if name in _LOOPBACK_HOSTS or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _offline_network_guard(monkeypatch):
    """autouse:清代理 + 拦截非 loopback 的解析/连接(离线守门)。"""

    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _guard_address(address: object, action: str) -> None:
        # Unix domain socket:地址是路径字符串/bytes,不是 (host, port) 元组
        if isinstance(address, tuple) and address:
            host = address[0]
            if not _is_loopback(host):
                pytest.fail(
                    f"离线守门:测试试图{action}非 loopback 地址 {host!r}"
                    f"(address={address!r})。真实 provider 调用必须被替换成假实现。"
                )
            return
        if isinstance(address, str) and not address.startswith("/") and not address.startswith("\0"):
            # 极少数实现把 host 直接传成字符串
            if not _is_loopback(address):
                pytest.fail(f"离线守门:测试试图{action}非 loopback 主机 {address!r}")

    def guarded_connect(self, address, *args, **kwargs):
        _guard_address(address, "连接")
        return real_connect(self, address, *args, **kwargs)

    def guarded_connect_ex(self, address, *args, **kwargs):
        _guard_address(address, "连接")
        return real_connect_ex(self, address, *args, **kwargs)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if not _is_loopback(host):
            pytest.fail(
                f"离线守门:测试试图解析非 loopback 主机 {host!r}。"
                "真实 provider 调用必须被替换成假实现。"
            )
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    yield
