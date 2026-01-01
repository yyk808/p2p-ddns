# 集成测试故障排除（Docker + Rust）

当前集成测试基于 Rust integration tests（`tests/docker_p2p.rs`）并使用 `testcontainers-rs`
以编程方式创建 Docker 网络与容器。

## 1) Docker/OrbStack 拉取镜像失败

常见报错（Docker Hub 连接/TLS）：

```
failed to resolve source metadata ... tls: first record does not look like a TLS handshake
```

建议：

- macOS + OrbStack：重启 OrbStack 后重试
- 检查是否能访问 Docker Hub：`curl -I https://registry-1.docker.io/v2/`
- 清理磁盘空间（镜像/层缓存过多）：`docker system prune -a`

## 2) Docker 权限/daemon 不可用

- 确认 `docker info` 可运行
- Linux：确认用户在 `docker` 组，或用 `sudo` 运行（按你的系统策略）

## 3) 残留的测试资源（容器/网络/卷）

默认会清理；但如果使用 `P2P_DDNS_IT_KEEP_DOCKER=1` 或中途 Ctrl+C，可能会残留。

```bash
# 删除残留容器（按名字前缀过滤）
docker rm -f $(docker ps -aq --filter 'name=p2pddns-it-') 2>/dev/null || true

# 删除残留网络（按名字前缀过滤）
docker network rm $(docker network ls -q --filter 'name=p2pddns-it-') 2>/dev/null || true
```

## 4) 如何定位某个用例失败

```bash
# 仅跑 smoke case，并保留 docker 现场（容器/网络）
P2P_DDNS_IT_KEEP_DOCKER=1 cargo test --test docker_p2p -- docker_p2p_smoke -- --nocapture

# 跑 matrix，但只跑某个 case
P2P_DDNS_IT_CASE=partition-recover P2P_DDNS_IT_KEEP_DOCKER=1 \
  cargo test --test docker_p2p -- docker_p2p_matrix -- --nocapture
```

运行时可以用 `docker ps -a` 查看测试创建的容器（前缀 `p2pddns-it-`），并用：

- `docker logs <container>`
- `docker exec -it <container> bash`

如果 Docker 连接问题持续存在：

### 1. 使用预构建镜像
```bash
# 如果有同事可以提供镜像文件
docker load -i p2p-ddns-images.tar
```

### 2. 本地构建缓存
```bash
# 确保之前有成功的构建
docker images | grep p2p-ddns

# 使用现有镜像进行测试
```

### 3. 模拟测试环境
如果完全无法使用 Docker，可以考虑：
- 编写单元测试
- 使用模拟网络环境
- 在本地直接运行 p2p-ddns 二进制文件

## 获取帮助

如果问题仍然存在：

1. **查看详细日志**
   ```bash
   P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke -- --nocapture 2>&1 | tee test.log
   ```

2. **检查系统环境**
   ```bash
   docker version
   docker info
   uname -a
   ```

3. **创建问题报告**
   包含以下信息：
   - 操作系统和版本
   - Docker 版本和类型 (Docker Desktop/OrbStack/其他)
   - 完整的错误日志
   - 重现步骤

## 预防措施

1. **定期更新 Docker**
   ```bash
   # 检查更新
   docker version
   ```

2. **维护良好的网络环境**
   - 稳定的互联网连接
   - 正确的代理设置（如果需要）

3. **定期清理**
   ```bash
   # 定期清理不需要的资源
   docker system prune
   ```
