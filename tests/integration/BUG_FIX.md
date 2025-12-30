# Bug Fix: COMMAND Variable Unbound Error

## 问题描述

在运行 `./quick-test.sh` 脚本时出现以下错误：

```
./quick-test.sh: line 360: COMMAND: unbound variable
```

## 问题原因

在 `main()` 函数中，我们在调用 `parse_args "$@"` 之前就引用了 `$COMMAND` 变量，但此时该变量还没有被初始化。

## 修复方案

将 `main()` 函数中的代码顺序调整，先解析参数，再显示信息：

### 修复前 (有问题)：
```bash
main() {
    header "p2p-ddns Quick Test Runner"
    echo "Command: $COMMAND"  # ← COMMAND 还未初始化
    echo "Timeout: ${TIMEOUT}s"
    echo "Debug: $DEBUG"
    echo

    parse_args "$@"  # ← 现在才解析参数
    # ...
}
```

### 修复后 (已修复)：
```bash
main() {
    parse_args "$@"  # ← 先解析参数

    header "p2p-ddns Quick Test Runner"
    echo "Command: $COMMAND"  # ← 现在 COMMAND 已正确初始化
    echo "Timeout: ${TIMEOUT}s"
    echo "Debug: $DEBUG"
    echo

    # ...
}
```

## 验证修复

修复后，脚本可以正常运行：

```bash
# 显示帮助信息
./quick-test.sh --help

# 运行测试（需要 Docker 运行）
./quick-test.sh quick

# 使用 Makefile
make help
make test
```

## 影响范围

此修复影响以下脚本：
- `tests/integration/quick-test.sh` (已修复)

其他脚本未受影响，可以正常使用。