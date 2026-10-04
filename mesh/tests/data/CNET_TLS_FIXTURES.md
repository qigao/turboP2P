# CNet TLS 测试证书

`cnet-ca-cert.pem`、`cnet-server-cert.pem`、`cnet-server-key.pem` 复制自 [qigao/salts 的 CNet fixtures](https://github.com/qigao/salts/tree/82b558f5/cnet/tests/fixtures)，对应 `ip-test-root-cert.pem`、`ip-test-server-cert.pem`、`ip-test-server-key.pem`。这些公开测试密钥仅供回环 fixture 使用。

叶证书包含 DNS localhost 与 IP 127.0.0.1 SAN、critical CA:FALSE/Key Usage；独立 CA 包含 CA:TRUE。有效期为 2026-10-03 至 2036-09-30。客户端显式信任该 CA，继续验证证书与主机名。旧 localhost fixture 保留给 CoroNet 回归。
