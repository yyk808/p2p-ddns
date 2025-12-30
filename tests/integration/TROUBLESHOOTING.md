# 集成测试故障排除指南

## 常见问题

### 1. Docker 连接问题

#### 错误信息
```
ERROR: failed to solve: debian:bookworm-slim: failed to resolve source metadata for docker.io/library/debian:bookworm-slim: failed to do request: Head "https://registry-1.docker.io/v2/library/debian/manifests/bookworm-slim": tls: first record does not look like a TLS handshake
```

#### 解决方案

**方案A: 重启 OrbStack**
```bash
# 重启 OrbStack
# 在菜单栏点击 OrbStack 图标 -> Restart
```

**方案B: 检查网络连接**
```bash
# 检查能否访问 Docker Hub
curl -I https://registry-1.docker.io/v2/

# 如果失败，可能是网络代理或防火墙问题
```

**方案C: 重置 Docker 网络配置**
```bash
# 停止 OrbStack
# 重启网络服务
# 重新启动 OrbStack
```

**方案D: 使用本地镜像（如果可用）**
```bash
# 检查是否有可用的本地镜像
docker images

# 如果有基础镜像，可以修改构建脚本跳过网络拉取
```

### 2. 权限问题

#### 错误信息
```
permission denied: ./tests/integration/Makefile
```

#### 解决方案
```bash
# 修复脚本权限
chmod +x tests/integration/*.sh
chmod +x tests/integration/networks/*.sh
chmod +x tests/integration/quick-test.sh
chmod +x tests/integration/test-integration.sh

# 或者使用 make 进行设置
cd tests/integration
make setup
```

### 3. 容器启动失败

#### 错误信息
```
container cannot join network: not found
```

#### 解决方案
```bash
# 清理网络状态
cd tests/integration
./networks/cleanup-networks.sh force

# 重新创建网络
./networks/create-networks.sh create
```

### 4. 端口冲突

#### 错误信息
```
port is already allocated
```

#### 解决方案
```bash
# 检查端口占用
lsof -i :8080
lsof -i :8081
# 等等...

# 停止占用端口的进程
sudo kill -9 <PID>

# 或者修改 docker-compose.yml 中的端口映射
```

### 5. 内存不足

#### 错误信息
```
no space left on device
```

#### 解决方案
```bash
# 清理 Docker 资源
docker system prune -a
docker volume prune
docker network prune

# 检查磁盘空间
df -h
```

## 环境特定问题

### OrbStack 用户 (macOS)

OrbStack 有时会遇到网络连接问题：

1. **重启 OrbStack**
   - 点击菜单栏的 OrbStack 图标
   - 选择 "Restart"

2. **检查系统代理设置**
   - 系统偏好设置 -> 网络 -> 高级 -> 代理
   - 确保代理设置正确

3. **重置网络配置**
   ```bash
   # 重启 OrbStack 后尝试
   docker pull hello-world
   ```

### Docker Desktop 用户

1. **重启 Docker Desktop**
2. **检查 Docker Desktop 设置**
   - 确保有足够的内存分配
   - 检查网络设置

### Linux 用户

1. **检查 Docker 服务状态**
   ```bash
   sudo systemctl status docker
   sudo systemctl restart docker
   ```

2. **检查用户权限**
   ```bash
   sudo usermod -aG docker $USER
   # 注销并重新登录
   ```

## 调试技巧

### 1. 启用调试模式
```bash
# 启用详细日志
./quick-test.sh quick --debug

# 查看构建详情
docker build --no-cache --progress=plain .
```

### 2. 逐步调试
```bash
# 只构建镜像
./quick-test.sh build

# 只启动环境
./quick-test.sh start

# 查看状态
./quick-test.sh status
```

### 3. 检查日志
```bash
# 查看容器日志
./quick-test.sh logs

# 查看特定容器日志
docker-compose logs primary-node
```

### 4. 进入容器调试
```bash
# 进入容器
docker-compose exec primary-node /bin/bash

# 检查进程
docker-compose exec primary-node ps aux
```

## 替代方案

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