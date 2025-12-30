#!/bin/bash

# Test array access in bash

# Test scenario array
TEST_SCENARIOS=(
    "basic-functionality"
    "network-topology"
    "fault-recovery"
)

echo "Available scenarios:"
for scenario in "${TEST_SCENARIOS[@]}"; do
    echo "  $scenario"
done

# Test basic functionality
echo "Testing basic-functionality..."
echo "✅ Test scenario array working"

exit 0