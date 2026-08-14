# FlowMQ mTLS 测试证书

这些文件仅用于 MeshNodeIPC FlowMQ 集成测试。仓库公开包含其私钥，部署服务绝不能使用这些测试凭据。

夹具包含一个测试根 CA，以及 `meshd` server 和 `mesh-agent` client 各自独立的 current/next 叶证书与
私钥。server leaf 只有 `serverAuth` EKU 和 `localhost` SAN；client leaf 只有 `clientAuth` EKU。
`server-client-auth-only-*` 刻意组合有效的 `localhost` SAN 与错误 EKU，使负向测试能把证书用途校验
与 hostname 校验区分开。

CA 私钥与 CSR 刻意不提交。测试只使用固定 CA 证书、叶证书和叶私钥。生产证书签发、存储、轮换与
吊销仍由部署系统负责。
