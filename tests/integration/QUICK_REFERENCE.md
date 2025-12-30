# p2p-ddns 测试快速参考

## 快速命令

### 从项目根目录运行

```bash
# 完整测试套件（推荐）
./test-integration.sh full

# 快速验证
./test-integration.sh quick

# 特定场景测试
./test-integration.sh scenario dns-synchronization
./test-integration.sh scenario basic-functionality
./test-integration.sh scenario fault-recovery

# 清理环境
./test-integration.sh clean
```

### 从 integration 目录运行

```bash
cd tests/integration

# 一键完整测试
./single-machine-test.sh full

# 快速验证
./single-machine-test.sh quick

# 特定场景
./single-machine-test.sh scenario network-topology

# 清理
./single-machine-test.sh cleanup
```

## 测试场景

| 场景 | 命令 | 描述 |
|-------|------|------|
| 基础功能 | `scenario basic-functionality` | 节点启动和通信 |
| 网络拓扑 | `scenario network-topology` | 多子网通信 |
| 故障恢复 | `scenario fault-recovery` | 节点故障和恢复 |
| DNS同步 | `scenario dns-synchronization` | DNS记录同步 |
| 端到端 | `scenario end-to-end` | 完整流程测试 |

## 容器网络

```
subnet-a (10.0.1.0/24)
├── primary-node  (10.0.1.10)
├── daemon-a1     (10.0.1.11)
├── daemon-a2     (10.0.1.12)
└── client-a1     (10.0.1.13)

subnet-b (10.0.2.0/24)
├── daemon-b1     (10.0.2.11)
├── daemon-b2     (10.0.2.12)
└── client-b1     (10.0.2.13)

public (10.0.0.0/24)
├── primary-node  (10.0.0.10)
├── daemon-b1     (10.0.0.11)
└── monitor       (10.0.0.20)
```

## 常用命令

### 查看容器状态
```bash
docker-compose ps
```

### 查看日志
```bash
# 所有容器
docker-compose logs -f

# 特定容器
docker-compose logs -f primary-node
docker-compose logs -f daemon-a1
docker-compose logs --tail=100 client-a1
```

### 进入容器
```bash
docker-compose exec primary-node /bin/bash
docker-compose exec daemon-a1 /bin/bash
```

### 测试连接
```bash
# 同子网
docker-compose exec daemon-a1 ping -c 3 primary-node

# 跨子网
docker-compose exec daemon-a1 ping -c 3 daemon-b1
```

### 检查DNS记录
```bash
docker-compose exec primary-node grep -A 20 "Address.*Name.*Last Seen" /app/logs/primary.log
```

## Make命令

```bash
cd tests/integration

make build      # 构建镜像
make test       # 快速测试
make status     # 查看状态
make logs       # 查看日志
make clean      # 清理环境
make help       # 查看所有命令
```

## 网络操作

```bash
# 隔离子网
./networks/network-control.sh isolate-network subnet-a
./networks/network-control.sh restore-network subnet-a

# 隔离容器
./networks/network-control.sh isolate-container primary-node
./networks/network-control.sh restore-container primary-node

# 清理网络规则
./networks/network-control.sh cleanup
```

## 预期结果

### 容器数量
- 总共 7 个容器
- 1 primary
- 4 daemons (a1, a2, b1, b2)
- 2 clients (a1, b1)

### 健康状态
- 所有容器应显示 "Up" 或 "healthy"
- primary 应显示 "healthy"

### DNS记录
- primary 节点: > 5 条记录
- daemon 节点: > 3 条记录
- client 节点: > 3 条记录

### 网络连接
- 同子网: 100% 连接成功
- 跨子网: > 80% 连接成功
- 延迟: < 10ms (同子网)

## 故障排除

### 容器无法启动
```bash
# 检查Docker
docker info

# 检查端口占用
lsof -i :8080-8086

# 查看详细日志
docker-compose logs --tail=50 <container>
```

### 网络连接失败
```bash
# 检查网络
docker network ls

# 检查容器网络配置
docker inspect <container> | grep -A 20 Networks

# 重建网络
./networks/cleanup-networks.sh normal
./networks/create-networks.sh create
```

### DNS记录未同步
```bash
# 等待更长时间 (最多3分钟)
# 查看是否有错误
docker-compose logs primary-node | grep -i error
docker-compose logs daemon-a1 | grep -i error

# 检查ticket生成
docker-compose logs primary-node | grep Ticket
```

## 测试报告位置

```
tests/integration/reports/
├── single-machine-test-YYYYMMDD-HHMMSS.txt
├── test-results-YYYYMMDD-HHMMSS.json
└── test-report-YYYYMMDD-HHMMSS.html
```

## 详细文档

- **单机测试指南**: `tests/integration/SINGLE_MACHINE_TEST_GUIDE.md`
- **集成测试文档**: `tests/integration/README.md`
- **使用说明**: `tests/integration/USAGE.md`

## 性能参考

| 指标 | 预期值 | 警告阈值 |
|-------|--------|---------|
| 容器启动 | < 60s | > 120s |
| 网络收敛 | < 120s | > 180s |
| CPU使用 | < 50% | > 80% |
| 内存使用 | < 200MB | > 512MB |
| 网络延迟 | < 10ms | > 50ms |

## 快速测试清单

- [ ] Docker运行中
- [ ] 镜像已构建
- [ ] 网络已创建
- [ ] 容器已启动
- [ ] 主节点健康
- [ ] 守护节点连接
- [ ] DNS记录同步
- [ ] 无严重错误
- [ ] 资源使用正常

## 联系和支持

- 📖 查看详细文档
- 🐛 提交问题到GitHub
- 💬 在讨论区提问
