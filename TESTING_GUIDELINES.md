# Raw Parser Testing Guidelines

## Overview
The raw parser module (`src/net/parser/raw/`) is critical for handling unknown or fallback network protocols. This document outlines testing best practices to prevent regressions.

## Common Bug Patterns to Test For

### 1. **Field Assignment Bugs**
**Problem**: Constructor parameters in wrong order
**Test**: Always verify src/dst port assignments match expected values
```rust
// ❌ Bad
assert_eq!(header.src_port, dst_value); // Wrong!

// ✅ Good  
assert_eq!(header.src_port, expected_src_port);
assert_eq!(header.dst_port, expected_dst_port);
```

### 2. **Packet Length Validation**
**Problem**: Tests using incorrect packet lengths for protocols
**Test**: Use protocol-specific minimum/exact lengths
```rust
// ❌ Bad
let packet = vec![0x01, 0x00]; // Too short

// ✅ Good
let mut packet = vec![0x01, 0x00, 0x00, 0x00];
packet.extend(vec![0u8; REQUIRED_LENGTH - 4]); // Proper padding
```

### 3. **Version Field Handling**
**Problem**: Version not properly extracted or assigned
**Test**: Verify version field is correctly set
```rust
let header = parser.parse(...);
assert_eq!(header.version, Some(expected_version));
```

### 4. **Protocol Number Preservation**
**Problem**: Protocol numbers get corrupted during parsing
**Test**: Always verify protocol field matches input
```rust
assert_eq!(header.protocol, expected_protocol_number);
```

## Testing Checklist for New Parsers

When adding a new protocol parser to `/raw`, verify:

- [ ] **Constructor field order** - src_port, dst_port in correct positions
- [ ] **Minimum packet length** - Parser handles undersized packets gracefully
- [ ] **Maximum packet length** - Parser handles oversized packets without panic
- [ ] **Protocol number preservation** - Input protocol == output protocol
- [ ] **Version field extraction** - If applicable, version is correctly parsed
- [ ] **IP address extraction** - Source/destination IPs correctly assigned
- [ ] **Checksum validation** - If parser validates checksums, test both valid/invalid
- [ ] **Edge cases** - Zero-length payloads, malformed headers, boundary conditions

## Required Tests for Each Parser

### 1. **Happy Path Test**
```rust
#[test]
fn test_[protocol]_parse_valid() {
    let payload = create_valid_[protocol]_packet();
    let result = [Protocol]Parser::parse_packet(&payload, [Protocol]Parser::protocol_number());
    assert!(result.is_some());
    
    let header = result.unwrap();
    assert_eq!(header.src_port, EXPECTED_SRC);
    assert_eq!(header.dst_port, EXPECTED_DST);
    assert_eq!(header.protocol, [Protocol]Parser::protocol_number());
}
```

### 2. **Invalid Length Test**
```rust
#[test]
fn test_[protocol]_parse_insufficient_length() {
    let payload = vec![0u8; MIN_LENGTH - 1]; // Too short
    let result = [Protocol]Parser::parse_packet(&payload, [Protocol]Parser::protocol_number());
    assert!(result.is_none());
}
```

### 3. **Field Assignment Regression Test**
```rust
#[test]
fn test_[protocol]_field_assignment_regression() {
    let payload = create_packet_with_known_values(src: A, dst: B);
    let header = [Protocol]Parser::parse_packet(&payload, protocol).unwrap();
    
    // Verify no field swapping
    assert_eq!(header.src_port, A, "Source should be A, not B");
    assert_eq!(header.dst_port, B, "Destination should be B, not A");
}
```

## CI/CD Integration

### Pre-commit Hooks
- Run `cargo test raw --lib` before each commit
- Ensure all raw parser tests pass

### Pull Request Requirements
- New protocol parsers must include all required tests
- Changes to existing parsers must not break regression tests
- Test coverage for edge cases must be demonstrated

## Performance Considerations

### Avoid in Tests
- Creating massive test packets (>10KB) unless testing specific large-packet scenarios
- Excessive heap allocations in tight test loops
- Complex packet generation that slows down test execution

### Prefer in Tests  
- Small, focused test packets that verify specific behavior
- Stack-allocated arrays for simple test cases
- Parameterized tests for testing multiple scenarios efficiently

## Documentation Standards

Each test should include:
- **Purpose comment** - What specific behavior is being tested
- **Regression note** - If fixing a specific bug, reference the original issue
- **Edge case description** - For boundary condition tests, explain the scenario

```rust
/// Regression test for IPX port swap bug (Issue #123)
/// 
/// Verifies that source and destination ports are correctly assigned
/// and not swapped during header construction.
#[test]
fn test_ipx_port_assignment_regression() {
    // Test implementation...
}
```

## Maintenance Schedule

- **Weekly**: Run full raw parser test suite with `cargo test raw`
- **Monthly**: Review test coverage and add tests for any uncovered edge cases
- **Quarterly**: Performance review of test execution time
- **Release**: Full regression testing against real-world packet captures

## Emergency Response

If raw parser issues are discovered in production:

1. **Immediate**: Add failing test case that reproduces the issue
2. **Fix**: Implement the minimal fix to resolve the issue  
3. **Validate**: Ensure fix doesn't break existing functionality
4. **Document**: Update this guide with new patterns to test for

---

*This document should be updated whenever new bug patterns are discovered or new testing strategies are developed.* 