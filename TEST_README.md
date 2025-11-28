# DNS Test Suite Documentation

## Overview

Comprehensive test suite for the DNS server/client implementation with edge case coverage and network packet transfer validation.

## Test Categories

### 1. **Unit Tests** (Always Run)
- DNS packet creation and parsing
- Empty/malformed packet handling
- Long domain names (253 chars)
- Invalid domain characters
- Multiple answer records
- DNS flags validation
- Packet size limits (min 12 bytes, max 512 bytes)
- Checksum calculation

### 2. **Network Tests** (Optional)
- Valid UDP DNS query to server
- Response validation
- TCP connection test
- Transaction ID matching
- Actual packet transfer verification

## Building and Running Tests

### Compile All Targets
```bash
make clean
make all
```

### Run Unit Tests Only
```bash
make test
```

This runs all unit tests without requiring a running server.

### Run Network Tests
```bash
# Terminal 1: Start the DNS server
sudo make run_server

# Terminal 2: Run tests with network validation
make test_network
```

The `--network` flag enables tests that:
- Send actual UDP packets to the server
- Verify responses are received
- Validate packet structure
- Test TCP listener functionality

## Test Results

Tests output in real-time with ✓ (pass) or ✗ (fail) indicators:

```
========================================
   DNS Server/Client Test Suite
========================================

[TEST] Basic DNS Query Creation and Parsing
  ✓ Query packet created
  ✓ Question count is 1
  ✓ QR flag is 0 (query)
  ✓ RD flag is 1
  ✓ Packet serialized to wire format
  ...

========================================
Tests Passed: 28
Tests Failed: 0
Total Tests:  28
========================================
```

## Edge Cases Tested

### 1. **Empty Packets**
- DNS header with all zeros
- Truncated packets (< 12 bytes)
- Validates parser doesn't crash

### 2. **Long Domain Names**
- 253 character domain (maximum valid length)
- Ensures buffer overflow protection

### 3. **Invalid Domains**
- Double dots (`example..com`)
- Leading dots (`.example.com`)
- Spaces in domain names
- Tests robustness against malformed input

### 4. **Multiple Answers**
- Response with 5+ answer records
- Serialization/deserialization preservation
- Answer count validation

### 5. **Packet Size Limits**
- Minimum: 12-byte DNS header
- Maximum: 512-byte UDP DNS packet
- Boundary condition testing

### 6. **DNS Flags**
- QR (Query/Response)
- AA (Authoritative Answer)
- TC (Truncation)
- RD (Recursion Desired)
- RA (Recursion Available)
- All combinations tested

## Network Test Requirements

For network tests to succeed:

1. **Server must be running**:
   ```bash
   sudo ./ex2_server
   ```

2. **Correct IP configuration**:
   - Server IP: `192.168.1.201`
   - Test queries: `www.attacker.cybercourse.example.com`

3. **Network connectivity**:
   - UDP port 53 accessible
   - TCP port 12345 accessible (for port exchange)

## Network Test Details

### Valid UDP Query Test
1. Creates DNS query for attacker domain
2. Sends to server via UDP
3. Waits for response (5-second timeout)
4. Validates:
   - Response received
   - QR flag = 1 (response)
   - Transaction ID matches
   - Packet parseable

### TCP Connection Test
1. Establishes TCP connection to port 12345
2. Tests port information exchange
3. Validates data reception

## Expected Output Examples

### All Tests Pass
```
[TEST] Network: Send Valid UDP DNS Query
  ✓ UDP socket created
  ✓ Query serialized to wire
  ✓ Query sent to server
  ✓ Response received from server
  ✓ Response parsed successfully
  ✓ Response QR flag set
  ✓ Transaction IDs match
```

### Server Not Running
```
[TEST] Network: Send Valid UDP DNS Query
  ✓ UDP socket created
  ✓ Query serialized to wire
  ✓ Query sent to server
  ✗ FAILED: No response received (timeout or server not running)
```

## Debugging Failed Tests

### Unit Test Failures
- Check ldns library installation
- Verify compilation flags
- Review test assertions in code

### Network Test Failures
1. **No response received**:
   - Verify server is running
   - Check firewall settings
   - Confirm IP addresses match

2. **Connection refused**:
   - Server not listening on expected port
   - Network routing issues
   - Firewall blocking

3. **Invalid response**:
   - Server bug in response generation
   - Packet corruption
   - MTU issues

## Integration with CI/CD

Unit tests can run in CI without network:
```bash
make test
```

Network tests require actual server deployment:
```bash
# Start server in background
sudo ./ex2_server &
SERVER_PID=$!

# Run network tests
make test_network

# Cleanup
kill $SERVER_PID
```

## Adding New Tests

Template for new test function:

```c
void test_my_feature(void) {
    TEST_START("Description of Test");
    
    // Setup
    // ...
    
    // Test condition
    TEST_ASSERT(condition, "What is being tested");
    
    // Cleanup
    // ...
}
```

Add to `main()`:
```c
test_my_feature();
```

## Checklist Before Submission

- [ ] All unit tests pass
- [ ] Network tests pass with server running
- [ ] No memory leaks (run with `valgrind ./test_dns`)
- [ ] Code compiles without warnings
- [ ] Documentation updated

## Troubleshooting

**Test hangs on network tests**:
- Increase `TEST_TIMEOUT` constant
- Check server responsiveness

**Segmentation fault**:
- Run with `gdb ./test_dns`
- Check for NULL pointer dereferences

**Memory leaks**:
```bash
valgrind --leak-check=full ./test_dns
```

## Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed
