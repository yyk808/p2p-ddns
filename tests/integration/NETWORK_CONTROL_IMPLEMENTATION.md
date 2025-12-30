# 网络控制实现详解

## 🏗️ 实现架构

网络控制系统基于两个核心技术：
1. **Linux网络命名空间 (Network Namespaces)**
2. **iptables防火墙规则**

## 🔧 核心组件

### 1. 容器识别和进程管理

```bash
# 获取容器PID
get_container_pid() {
    local container_name=$1
    docker inspect "$container_name" --format "{{.State.Pid}}"
}

# 检查容器是否存在
container_exists() {
    local container_name=$1
    docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"
}
```

### 2. 网络命名空间隔离

#### 原理
每个Docker容器都有自己的网络命名空间，位于 `/proc/<PID>/ns/net`。通过创建到这个命名空间的符号链接，我们可以从宿主机操作容器的网络环境。

#### 实现
```bash
isolate_container() {
    local container_name=$1
    local container_pid=$(get_container_pid "$container_name")

    # 创建网络命名空间链接
    sudo ln -sf "/proc/$container_pid/ns/net" "/var/run/netns/test-${container_name}"

    # 添加防火墙规则阻止所有流量
    sudo iptables -I DOCKER-USER -s 0.0.0.0/0 -d 0.0.0.0/0 \
        -m comment --comment "isolate-${container_name}" -j DROP
}
```

#### 工作原理
1. **命名空间链接**: 将容器的网络命名空间链接到宿主机的 `/var/run/netns/`
2. **网络隔离**: 通过符号链接，可以在宿主机使用 `ip netns` 命令操作容器网络
3. **防火墙阻止**: 使用 `iptables` 规则阻止所有进出容器的网络流量

### 3. 网络恢复

```bash
restore_container() {
    local container_name=$1

    # 移除网络命名空间链接
    sudo rm -f "/var/run/netns/test-${container_name}"

    # 移除防火墙规则
    sudo iptables -D DOCKER-USER -m comment --comment "isolate-${container_name}" -j DROP
}
```

### 4. 精细化网络控制

#### 子网级别控制
```bash
isolate_network() {
    local network_name=$1

    # 获取该网络中的所有容器
    local containers=$(docker ps --format "{{.Names}}" | grep "$network_name")

    # 隔离每个容器
    echo "$containers" | while read -r container; do
        isolate_container "$container"
    done
}
```

#### 连接级别控制
```bash
block_container_connection() {
    local source_container=$1
    local target_container=$2

    # 获取容器IP地址
    local source_ip=$(docker inspect "$source_container" --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
    local target_ip=$(docker inspect "$target_container" --format "{{range .NetworkSettings.NetworkSettings.Networks}}{{.IPAddress}}{{end}}")

    # 添加特定的阻断规则
    sudo iptables -I DOCKER-USER -s "$source_ip" -d "$target_ip" -j DROP \
        -m comment --comment "block-${source_container}-to-${target_container}"
}
```

## 🎛️ 具体控制场景

### 场景1: 完全隔离容器
```bash
# 隔离单个容器
./network-control.sh isolate-container daemon-a1

# 隔离整个子网
./network-control.sh isolate-network subnet-a

# 恢复连接
./network-control.sh restore-container daemon-a1
./network-control.sh restore-network subnet-a
```

### 场景2: 精细化连接控制
```bash
# 阻断特定连接
./network-control.sh block-connection daemon-a1 daemon-b1

# 恢复特定连接
./network-control.sh restore-connection daemon-a1 daemon-b1
```

### 场景3: 网络分区模拟
```bash
# 模拟网络分区
./network-control.sh isolate-network subnet-a
sleep 30
./network-control.sh restore-network subnet-a
```

## 🔍 监控和验证

### 网络状态检查
```bash
show_network_status() {
    # 显示被隔离的容器
    sudo ip netns list | grep "test-" | sed 's/test-//'

    # 显示防火墙规则
    sudo iptables -L DOCKER-USER --line-numbers | grep -E "(isolate-|block-)"
}
```

### 容器连通性测试
```bash
# 在测试脚本中验证隔离效果
docker-compose exec daemon-a1 ping -c 1 daemon-b1
# 如果隔离成功，ping会失败
```

## 🛡️ 安全考虑

### 权限要求
网络控制需要 `sudo` 权限来：
- 创建/删除网络命名空间链接
- 修改 iptables 规则

### 规则管理
- 所有规则都有唯一的注释标识
- 使用 `DOCKER-USER` 链确保规则只影响Docker流量
- 提供完整的清理功能

### 风险控制
- 自动检测容器状态，避免操作不存在的容器
- 提供恢复机制，确保网络可以正常恢复
- 所有操作都有详细的日志记录

## 🚀 使用示例

### 基本网络控制
```bash
# 1. 启动测试环境
./quick-test.sh start

# 2. 隔离子网A
./network-control.sh isolate-network subnet-a

# 3. 测试网络分区
./scripts/test-scenarios.sh --scenario network-partition

# 4. 恢复网络
./network-control.sh restore-network subnet-a

# 5. 清理环境
./quick-test.sh clean
```

### 高级测试场景
```bash
#!/bin/bash

# 复杂网络故障模拟
echo "开始网络故障模拟测试..."

# 1. 正常运行
./quick-test.sh start
sleep 30

# 2. 隔离primary节点
./network-control.sh isolate-container primary-node
sleep 30

# 3. 验证故障恢复
./network-control.sh restore-container primary-node
sleep 30

# 4. 清理
./quick-test.sh clean
```

## 📊 技术细节

### 网络命名空间层次结构
```
宿主机网络命名空间
├── /var/run/netns/
│   ├── test-primary-node (链接到容器的网络命名空间)
│   ├── test-daemon-a1
│   └── test-daemon-a2
```

### iptables规则链
```
DOCKER-USER 链:
1. 隔离规则: -s 0.0.0.0/0 -d 0.0.0.0/0 -j DROP (isolate-container)
2. 阻断规则: -s 10.0.1.11 -d 10.0.1.12 -j DROP (block-daemon-a1-to-daemon-a2)
```

### 容器网络配置
```
容器网络配置:
├── NetworkSettings:
│   ├── Networks:
│   │   ├── bridge:
│   │   │   ├── IPAMConfig:
│   │   │   │   └── IPv4Address: 10.0.1.11
│   │   │   └── Gateway: 172.17.0.1
│   └── SandboxID: <sandbox-id>
```

## 🔧 故障排除

### 常见问题

1. **权限不足**
   ```bash
   # 检查是否有sudo权限
   sudo -v
   # 验证可以操作网络命名空间
   sudo ip netns list
   ```

2. **规则冲突**
   ```bash
   # 清理所有自定义规则
   ./network-control.sh cleanup
   ```

3. **容器不存在**
   ```bash
   # 检查容器状态
   docker ps -a | grep p2p-ddns
   ```

4. **网络命名空间异常**
   ```bash
   # 清理网络命名空间
   sudo find /var/run/netns -name "test-*" -delete
   ```

## 🎯 总结

网络控制系统通过巧妙利用Linux的命名空间和iptables机制，实现了强大的网络模拟能力，可以：

- ✅ 模拟真实网络环境中的各种故障情况
- ✅ 验证p2p-ddns在网络异常情况下的行为
- ✅ 提供可重复的测试环境
- ✅ 支持细粒度的网络控制

这个实现既保证了测试的真实性，又保持了操作的简单性和安全性。