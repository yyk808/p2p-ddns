# 集成测试故障排除（Docker Matrix）

当前集成测试使用 `scripts/p2p-matrix.sh` 按用例动态生成 docker compose，并为每个用例创建独立网络。

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

Matrix 默认会清理；但如果使用 `--keep` 或中途 Ctrl+C，可能会残留。

```bash
./test-integration.sh clean
# 或
cd tests/integration && ./quick-test.sh clean
```

## 4) 如何定位某个用例失败

```bash
cd tests/integration
./scripts/p2p-matrix.sh --case two-subnet-3x3 --keep
```

失败时脚本会输出 compose 项目名与 compose 文件路径；你可以用它们查看日志，例如：

```bash
docker compose -p <project> -f <compose.yml> logs --tail=200
docker compose -p <project> -f <compose.yml> exec -T primary-node bash -lc 'ls -la /app/logs && tail -n 120 /app/logs/*.log'
```

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
   ./quick-test.sh quick --debug 2>&1 | tee test.log
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
