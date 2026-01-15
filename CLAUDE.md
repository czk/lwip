# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

lwIP is a lightweight TCP/IP stack implementation designed for embedded systems with limited RAM (tens of kilobytes) and ROM (around 40 kilobytes). It provides a full-scale TCP/IP implementation with minimal resource usage.

**Version**: 2.2.2 (development)

## Build System

lwIP uses CMake as its primary build system, with Makefile support maintained as a secondary option.

### Building the Example Application

```bash
# Copy the configuration file first
cp contrib/examples/example_app/lwipcfg.h.example contrib/examples/example_app/lwipcfg.h

# Build with CMake (recommended)
mkdir build
cd build
cmake ..
cmake --build .

# Or build with Make (Unix/Linux)
make -C contrib/ports/unix/example_app
```

### Running Unit Tests

```bash
# Build and run unit tests with Make
make -C contrib/ports/unix/check
make -C contrib/ports/unix/check check

# Or use the shortcut from test/unit/
cd test/unit
make check
```

**Note**: Unit tests require the `check` library to be installed (`libcheck` package on most Linux distributions).

### Building Documentation

```bash
cd build
cmake --build . --target lwipdocs
```

Requires `doxygen` to be installed.

## Code Architecture

### Directory Structure

- **`src/`** - Core lwIP implementation
  - **`src/core/`** - Core protocol implementations (TCP, UDP, IP, DNS, memory management)
    - `src/core/ipv4/` - IPv4-specific implementations (DHCP, ARP, ICMP, IP fragmentation)
    - `src/core/ipv6/` - IPv6-specific implementations (DHCPv6, ICMPv6, ND6, MLD)
  - **`src/api/`** - High-level APIs (sockets, netconn, sequential API)
  - **`src/netif/`** - Network interface implementations (Ethernet, PPP, 6LoWPAN, SLIP)
  - **`src/apps/`** - Application protocols (HTTP, MQTT, SNMP, TFTP, mDNS, etc.)
  - **`src/include/lwip/`** - Public header files
  - `src/Filelists.cmake` - CMake file lists defining `lwipcore` and `lwipallapps` libraries

- **`contrib/`** - Platform ports and example applications
  - **`contrib/ports/`** - OS/platform-specific ports (Unix, Windows, FreeRTOS)
  - **`contrib/examples/`** - Example applications and configurations
  - **`contrib/apps/`** - Additional application implementations
  - **`contrib/addons/`** - Optional add-ons (TCP MD5, DHCP extra options, etc.)

- **`test/`** - Test suites
  - `test/unit/` - Unit tests organized by module (tcp, udp, dhcp, api, etc.)
  - `test/fuzz/` - Fuzzing tests
  - `test/sockets/` - Socket API tests

### Core Architecture Concepts

1. **Configuration via lwipopts.h**: lwIP is highly configurable through compile-time options defined in `lwipopts.h`. This file must be provided by the user and included in the include path. See `src/include/lwip/opt.h` for all available options and their defaults.

2. **Two Operating Modes**:
   - **NO_SYS=0** (default): Full OS support with threads, semaphores, and mailboxes. Enables the sequential API (sockets, netconn).
   - **NO_SYS=1**: No OS support, callback-based raw API only. Suitable for bare-metal or simple RTOS environments.

3. **Memory Management**: lwIP provides multiple memory allocation strategies:
   - **Heap memory** (`mem.c`) - Dynamic allocation
   - **Memory pools** (`memp.c`) - Pre-allocated fixed-size pools for protocol control blocks
   - **Packet buffers** (`pbuf.c`) - Specialized buffer management for network packets

4. **Network Interfaces** (`netif.c`): All network traffic flows through network interface structures. Each netif has input/output functions and can support multiple IP addresses.

5. **Protocol Layering**:
   - Application layer (apps/) → Transport layer (TCP/UDP) → Network layer (IP) → Link layer (netif/)
   - **altcp** provides an abstraction layer for TCP that enables TLS support transparently

6. **Threading Model** (when NO_SYS=0):
   - Main lwIP thread runs in `tcpip_thread` (see `src/api/tcpip.c`)
   - Application threads communicate with lwIP via message passing
   - APIs in `src/api/` provide thread-safe wrappers

## Development Guidelines

### Code Style (from doc/contrib.txt)

- **No tabs** - use 2 spaces for indentation
- One space between keyword and opening bracket
- No space between function name and opening bracket
- One space before opening curly brace
- Spaces around assignments and comparisons
- Don't initialize static/global variables to zero

### Documentation Style

- Use Doxygen-compatible JavaDoc style comments
- Document functions in `.c` files, not `.h` files
- Keep documentation synchronized with implementation

### Testing Changes

When modifying core protocol code:

1. Run unit tests: `make -C contrib/ports/unix/check check`
2. Build example app: `make -C contrib/ports/unix/example_app`
3. Test option combinations: `cd contrib/ports/unix/example_app && ./iteropts.sh`
4. 使用 fail_unless 接口的时候请记住，这个接口已经不支持带字符串参数了，请只传入条件表达式做参数
5. 用例失败的时候，可以通过增加打印的方式来定位问题。注意用例是用check跑的，所以打印需要输出到stderr才能看得到

### Working with Ports

Platform-specific code belongs in `contrib/ports/`. The core lwIP code in `src/` should remain platform-independent. Ports must provide:

- `sys_arch.h` and `sys_arch.c` - OS abstraction layer
- `lwipopts.h` - Configuration options for the platform
- Network interface drivers (optional)

## Common Patterns

### Adding a New Protocol Feature

1. Add protocol implementation to appropriate `src/core/` subdirectory
2. Add public API to `src/include/lwip/`
3. Add configuration options to `src/include/lwip/opt.h`
4. Update `src/Filelists.cmake` and `src/Filelists.mk`
5. Add unit tests to `test/unit/`

### Debugging

Enable debug output by defining debug flags in `lwipopts.h`:
- `LWIP_DEBUG` - Master debug enable
- Module-specific flags: `TCP_DEBUG`, `UDP_DEBUG`, `IP_DEBUG`, `DHCP_DEBUG`, etc.
- See `src/include/lwip/debug.h` for debug levels

### Key Files to Understand

- `src/include/lwip/opt.h` - All configuration options with documentation
- `src/core/init.c` - Initialization and version information
- `src/core/netif.c` - Network interface management
- `src/core/pbuf.c` - Packet buffer management
- `src/core/tcp.c`, `tcp_in.c`, `tcp_out.c` - TCP implementation
- `src/api/tcpip.c` - Main thread and message passing for threaded mode

## HTTP Frontend Development

### Modifying Web Pages

The HTTP server's frontend pages are located in `contrib/examples/httpd/examples_fs/`. After modifying any HTML/SHTML files, you **must** regenerate the C source file.

### Compiling HTML to C Code

**IMPORTANT**: After modifying any files in `examples_fs/`, run the following command to regenerate `examples_fsdata.c`:

```bash
cd contrib/examples/httpd
/workspaces/lwip/build/contrib/ports/unix/example_app/makefsdata examples_fs -f:examples_fsdata.c -11 -svr:lwIP
```

Or if using the Makefile-built version:
```bash
cd contrib/examples/httpd
/workspaces/lwip/contrib/ports/unix/example_app/makefsdata examples_fs -f:examples_fsdata.c -11 -svr:lwIP
```

### makefsdata Options

- `-f:<filename>` - Output filename (default: fsdata.c)
- `-11` - Use HTTP 1.1 headers (recommended)
- `-svr:<name>` - Server identifier in HTTP response
- `-s` - Toggle subdirectory processing
- `-m` - Include Last-Modified header

### Frontend Files

- `examples_fs/ssi.shtml` - Dashboard page
- `examples_fs/config.shtml` - Network configuration page
- SSI tags like `<!--#tag_name-->` are processed server-side

## CI/CD

The project uses GitHub Actions for continuous integration (`.github/workflows/ci-linux.yml`):
- Builds with both GCC and Clang
- Runs unit tests
- Builds documentation
- Validates option combinations
- Tests example applications
