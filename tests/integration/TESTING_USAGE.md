# p2p-ddns 测试代码改进 - 使用说明

## 概述

本次改进增强了 p2p-ddns 项目的集成测试框架，使其能够充分利用 Docker 的隔离网络环境，在单机上完整验证功能可用性。

## 新增文件

### 1. 核心测试脚本

- ✅ **tests/integration/scripts/test-scenarios-enhanced.sh**
  - 增强的测试场景实现
  - 包含 5 个完整的测试场景
  - 详细的验证逻辑

- ✅ **tests/integration/single-machine-test.sh**
  - 一键完整测试脚本
  - 自动化环境准备和清理
  - 生成详细测试报告

### 2. 文档

- ✅ **tests/integration/SINGLE_MACHINE_TEST_GUIDE.md**
  - 详细的单机测试指南
  - 包含故障排除和高级用法

- ✅ **tests/integration/QUICK_REFERENCE.md**
  - 快速参考卡
  - 命令速查表
  - 常见问题解答

- ✅ **tests/integration/IMPROVEMENTS_SUMMARY.md**
  - 改进总结文档
  - 测试覆盖范围说明

- ✅ **tests/integration/example-test.sh**
  - 测试示例脚本
  - 学习测试流程

## 快速开始

### 推荐方式：从项目根目录

```bash
# 方式1：使用更新后的 test-integration.sh（最简单）
./test-integration.sh full                    # 完整测试套件
./test-integration.sh quick                   # 快速验证
./test-integration.sh scenario dns-sync         # 特定场景

# 方式2：使用示例脚本
./tests/integration/example-test.sh

# 方式3：直接使用单机测试脚本
cd tests/integration
./single-machine-test.sh full
```

## 测试场景详解

### 1. 基础功能测试 (basic-functionality)

**验证内容**:
- ✅ Docker 隔离网络创建
- ✅ 所有节点（primary, daemons, clients）启动
- ✅ 容器健康状态检查
- ✅ 基础网络连接性
- ✅ p2p-ddns 进程运行验证
- ✅ Ticket 生成和传播
- ✅ 日志错误检查

**运行命令**:
```bash
./test-integration.sh scenario basic-functionality
# 或
cd tests/integration
./single-machine-test.sh scenario basic-functionality
```

### 2. 网络拓扑测试 (network-topology)

**验证内容**:
- ✅ 同子网节点通信（subnet-a 内部）
- ✅ 跨子网节点通信（subnet-a ↔ subnet-b）
- ✅ 网络发现机制
- ✅ Gossip 协议传播
- ✅ 网络路由配置

**运行命令**:
```bash
./test-integration.sh scenario network-topology
```

### 3. 故障恢复测试 (fault-recovery)

**验证内容**:
- ✅ 节点隔离模拟（网络分区）
- ✅ 节点停止和重启
- ✅ 故障期间网络持续运行
- ✅ 节点恢复后重新同步
- ✅ 系统弹性验证

**运行命令**:
```bash
./test-integration.sh scenario fault-recovery
```

### 4. DNS 同步测试 (dns-synchronization)

**验证内容**:
- ✅ 主节点 DNS 记录
- ✅ 守护节点 DNS 记录
- ✅ DNS 记录一致性
- ✅ 心跳机制
- ✅ DNS 表输出

**运行命令**:
```bash
./test-integration.sh scenario dns-synchronization
```

### 5. 端到端测试 (end-to-end)

**验证内容**:
- 🧹 清洁启动流程
- 🌐 网络环境创建
- 🔨 Docker 镜像构建
- 🚀 分阶段节点启动
- 🎫 Ticket 提取和传播
- 👥 完整网络收敛
- 💥 系统弹性测试
- 🩹 节点恢复验证
- ✅ 最终系统验证

**运行命令**:
```bash
./test-integration.sh scenario end-to-end
```

## 网络架构

测试环境模拟真实的校园网/企业网架构：

```
┌─────────────────────────────────────────────────────────┐
│                   Docker Host                       │
├─────────────────────────────────────────────────────────┤
│  Subnet A (10.0.1.0/24)  [教学楼 A]             │
│  ├── primary-node   (10.0.1.10)  [主节点]       │
│  ├── daemon-a1     (10.0.1.11)  [守护进程]      │
│  ├── daemon-a2     (10.0.1.12)  [守护进程]      │
│  └── client-a1     (10.0.1.13)  [客户端]         │
├─────────────────────────────────────────────────────────┤
│  Subnet B (10.0.2.0/24)  [教学楼 B]             │
│  ├── daemon-b1     (10.0.2.11)  [守护进程]      │
│  ├── daemon-b2     (10.0.2.12)  [守护进程]      │
│  └── client-b1     (10.0.2.13)  [客户端]         │
├─────────────────────────────────────────────────────────┤
│  Public (10.0.0.0/24)    [公共网络]              │
│  ├── primary-node   (10.0.0.10)                 │
│  ├── daemon-b1     (10.0.0.11)                 │
│  └── monitor       (10.0.0.20)  [监控节点]       │
└─────────────────────────────────────────────────────────┘
```

## 测试验证项

### 完整测试套件包括：

1. **网络连接性测试**（9个测试）
   - daemon-a1 → primary-node
   - daemon-a2 → primary-node
   - daemon-b1 → primary-node
   - daemon-b2 → primary-node
   - daemon-a1 → daemon-a2
   - daemon-a1 → daemon-b1
   - daemon-b1 → daemon-a1
   - daemon-a2 → daemon-b2
   - client-a1 → daemon-a1

2. **DNS 同步测试**（5个节点）
   - primary-node DNS 记录
   - daemon-a1 DNS 记录
   - daemon-a2 DNS 记录
   - daemon-b1 DNS 记录
   - daemon-b2 DNS 记录

3. **P2P 发现测试**（3个节点）
   - primary-node 发现活动
   - daemon-a1 发现活动
   - daemon-b1 发现活动

4. **错误日志检查**（4个节点）
   - primary-node 错误
   - daemon-a1 错误
   - daemon-b1 错误
   - client-a1 错误

5. **资源使用检查**（4个节点）
   - CPU 使用率（阈值：80%）
   - 内存使用（阈值：512MB）

## 测试报告

测试完成后，报告保存在：

```
tests/integration/reports/
├── single-machine-test-20240101-120000.txt    # 文本报告
├── test-results-20240101-120000.json        # JSON 报告
└── test-report-20240101-120000.html         # HTML 报告
```

报告包含：
- ✅ 测试日期和持续时间
- ✅ 总体测试结果
- ✅ 各场景详细结果
- ✅ 容器状态
- ✅ 资源使用情况
- ✅ 网络连接测试结果
- ✅ DNS 同步结果

## 常用命令

### 从项目根目录

```bash
# 完整测试（推荐）
./test-integration.sh full

# 快速验证
./test-integration.sh quick

# 特定场景
./test-integration.sh scenario basic-functionality
./test-integration.sh scenario network-topology
./test-integration.sh scenario fault-recovery
./test-integration.sh scenario dns-synchronization
./test-integration.sh scenario end-to-end

# 查看状态
./test-integration.sh status

# 查看日志
./test-integration.sh logs

# 清理环境
./test-integration.sh clean
```

### 从 integration 目录

```bash
cd tests/integration

# 完整测试
./single-machine-test.sh full

# 快速验证
./single-machine-test.sh quick

# 特定场景
./single-machine-test.sh scenario <name>

# 清理
./single-machine-test.sh cleanup
```

### Docker Compose 命令

```bash
cd tests/integration

# 查看容器状态
docker-compose ps

# 查看所有日志
docker-compose logs -f

# 查看特定容器日志
docker-compose logs -f primary-node

# 进入容器
docker-compose exec primary-node /bin/bash

# 测试连接
docker-compose exec daemon-a1 ping -c 3 primary-node
```

## 预期结果

### 成功标准

| 测试项 | 预期值 |
|-------|--------|
| 容器启动时间 | < 60秒 |
| 网络收敛时间 | < 120秒 |
| DNS 记录数 | > 5条/节点 |
| 网络连接成功率 | > 90% |
| CPU 使用率 | < 50% |
| 内存使用 | < 200MB |
| 无严重错误 | 0个 fatal/panic |

### 容器状态

所有 7 个容器应显示：
- Status: `Up` 或 `healthy`
- Primary 应显示 `healthy`
- 其他节点应显示 `Up` 或 `running`

## 故障排除

### 容器无法启动

```bash
# 检查 Docker 状态
docker info

# 检查端口占用
lsof -i :8080-8086

# 查看详细日志
docker-compose logs --tail=50 <container>
```

### 网络连接失败

```bash
# 检查网络
docker network ls | grep -E "(subnet-a|subnet-b|public)"

# 重建网络
./networks/cleanup-networks.sh normal
./networks/create-networks.sh create
```

### DNS 记录未同步

```bash
# 等待足够时间（最多3分钟）
# 查看 ticket 生成
docker-compose logs primary-node | grep Ticket

# 检查错误
docker-compose logs primary-node | grep -i error
```

## 向后兼容性

所有改进都保持向后兼容：

- ✅ 现有的 `quick-test.sh` 仍然可用
- ✅ 现有的 `test-integration.sh` 命令仍然有效
- ✅ Make 命令仍然可用
- ✅ Docker Compose 配置未改变

## 详细文档

- 📖 **单机测试指南**: `tests/integration/SINGLE_MACHINE_TEST_GUIDE.md`
- 🚀 **快速参考**: `tests/integration/QUICK_REFERENCE.md`
- 📊 **改进总结**: `tests/integration/IMPROVEMENTS_SUMMARY.md`
- 🏗️ **集成测试概述**: `tests/integration/README.md`
- 💡 **使用说明**: `tests/integration/USAGE.md`

## 支持和反馈

如遇问题：

1. 查看 `SINGLE_MACHINE_TEST_GUIDE.md` 的故障排除部分
2. 检查容器日志获取详细错误信息
3. 查看生成的测试报告
4. 在 GitHub 仓库提交 issue

## 许可证

MIT License - 详见项目根目录的 LICENCE 文件
