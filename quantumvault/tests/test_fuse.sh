#!/bin/bash

# QuantumVault FUSE Integration Test Script
# Tests: Create, Write, Read, Append, Truncate, Permissions, Delete, Cleanup

MOUNT_DIR="/tmp/qv_test_mount"
BINARY="./target/debug/quantumvault-mount"
PASS=0
FAIL=0

function check_pass() {
    echo "✅ PASS: $1"
    ((PASS++))
}

function check_fail() {
    echo "❌ FAIL: $1"
    ((FAIL++))
}

echo "=== Starting QuantumVault FUSE Integration Tests ==="

# 1. Setup
mkdir -p $MOUNT_DIR
echo "Mounting FUSE filesystem at $MOUNT_DIR..."
$BINARY $MOUNT_DIR &
MOUNT_PID=$!
sleep 2 # Wait for mount to initialize

# Check if mount was successful
if ! mount | grep -q $MOUNT_DIR; then
    echo "❌ FATAL: FUSE failed to mount."
    exit 1
fi

# 2. Create and Write
echo "Testing: Create and Write..."
echo "Hello QuantumVault" > $MOUNT_DIR/test.txt
if [ "$(cat $MOUNT_DIR/test.txt)" == "Hello QuantumVault" ]; then
    check_pass "Create and Write"
else
    check_fail "Create and Write"
fi

# 3. Append (O_APPEND)
echo "Testing: Append..."
echo "Second Line" >> $MOUNT_DIR/test.txt
EXPECTED_APPEND=$'Hello QuantumVault\nSecond Line'
if [ "$(cat $MOUNT_DIR/test.txt)" == "$EXPECTED_APPEND" ]; then
    check_pass "Append"
else
    check_fail "Append"
fi

# 4. Truncate (O_TRUNC)
echo "Testing: Truncate..."
echo "New Content" > $MOUNT_DIR/test.txt
if [ "$(cat $MOUNT_DIR/test.txt)" == "New Content" ]; then
    check_pass "Truncate"
else
    check_fail "Truncate"
fi

# 5. Permissions
echo "Testing: Permissions..."
chmod 700 $MOUNT_DIR/test.txt
PERMS=$(stat -c "%a" $MOUNT_DIR/test.txt)
if [ "$PERMS" == "700" ]; then
    check_pass "Permissions (chmod 700)"
else
    check_fail "Permissions (Got $PERMS, expected 700)"
fi

# 6. Delete
echo "Testing: Delete..."
rm $MOUNT_DIR/test.txt
if [ ! -f $MOUNT_DIR/test.txt ]; then
    check_pass "Delete"
else
    check_fail "Delete"
fi

# 7. Unmount and Cleanup
echo "Unmounting..."
fusermount -u $MOUNT_DIR
wait $MOUNT_PID 2>/dev/null
rmdir $MOUNT_DIR

if [ ! -d "$MOUNT_DIR" ] && ! mount | grep -q $MOUNT_DIR; then
    check_pass "Unmount and Cleanup"
else
    check_fail "Unmount and Cleanup"
fi

# Summary
echo "=================================================="
echo "Test Summary: $PASS Passed, $FAIL Failed"
echo "=================================================="

if [ $FAIL -eq 0 ]; then
    exit 0
else
    exit 1
fi
