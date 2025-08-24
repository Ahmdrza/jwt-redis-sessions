# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-08-24

### 🚀 Package Size Optimization & Code Quality Improvements

This release focuses on significantly reducing package size while improving code organization and maintainability.

### ✨ Enhancements

#### Package Size Reduction (-30% smaller)

- **README Documentation Split** - Moved comprehensive guides to separate docs/ folder
- **File Consolidation** - Consolidated 4 utility files into single utils.js
- **Dead Code Removal** - Removed unused utility functions
- **Result**: Package size reduced from 16.4 kB to **11.7 kB** (-30%)

#### Code Quality Improvements

- **Eliminated Code Duplication** - Centralized common patterns and utilities
- **Better Organization** - Created structured docs/ folder with specialized guides
- **Improved Maintainability** - Consolidated utilities for easier maintenance
- **Enhanced Documentation** - Better organized with focused README and detailed guides

#### Documentation Structure

- **README.md** - Essential installation and quick start (focused, concise)
- **docs/examples.md** - Complete working code examples
- **docs/api-reference.md** - Detailed API documentation
- **docs/troubleshooting.md** - Common issues and solutions
- **docs/security.md** - Production security best practices

### 🔧 Internal Changes

- Consolidated `jwt.util.js`, `time.util.js`, `response.util.js`, `redis.keys.js` → `utils.js`
- Removed unused functions: `getFutureUnixTimestamp`, `isTimestampExpired`, `calculateTTL`, `validateTokenType`
- Updated all imports to use consolidated utilities
- Maintained 100% backward compatibility

### 📦 Package Stats

- **Package size**: 11.7 kB (was 16.4 kB) - 30% reduction
- **Unpacked size**: 39.4 kB (was 56.0 kB) - 30% reduction
- **Total files**: 17 (was 20) - 15% reduction
- **Tests**: 137/137 passing ✅
- **Zero breaking changes** - All APIs remain identical

## [1.0.0] - 2024-12-24

### 🎉 Initial stable release

This is the first stable release of jwt-redis-sessions, a secure, production-ready JWT authentication and session management library for Node.js with Redis backend.

### ✨ Features

#### Core Authentication

- **JWT Token Generation** - Generate secure access and refresh tokens with configurable expiration
- **Token Verification** - Verify tokens with blacklist checking and session validation
- **Token Refresh** - Automatic refresh token rotation for enhanced security
- **Token Revocation** - Logout functionality with immediate token blacklisting
- **Session Management** - Redis-based session storage with automatic cleanup

#### Security Features

- **Token Blacklisting** - Immediate token revocation and blacklist management
- **Constant-Time Comparison** - Protection against timing attacks
- **Algorithm Enforcement** - Explicit JWT algorithm validation (HS256 only)
- **Rate Limiting** - Built-in middleware to prevent brute force attacks
- **Input Validation** - Comprehensive validation with custom error classes

#### Developer Experience

- **Express Integration** - Ready-to-use middleware for authentication
- **TypeScript Support** - Complete type definitions included
- **Comprehensive Testing** - 137+ tests covering all functionality
- **Production Ready** - Enterprise-grade security and error handling
- **Configurable** - Extensive configuration via environment variables

#### Middleware & Handlers

- `auth` - Main authentication middleware
- `optionalAuth` - Optional authentication (doesn't fail if no token)
- `rateLimit` - Rate limiting middleware with memory management
- `logout` - Single session logout handler
- `logoutAll` - All sessions logout handler
- `refresh` - Token refresh handler

### 🔧 Technical Specifications

- **Node.js**: >=14.0.0
- **Dependencies**: jsonwebtoken@9.x, redis@4.x, dotenv@16.x
- **TypeScript**: Full type definitions included
- **Testing**: Jest with comprehensive test suite
- **Security**: No known vulnerabilities

### 📦 Package Information

- **Size**: 15.0 kB (52.9 kB unpacked)
- **Files**: 16 essential files only
- **License**: MIT
- **Author**: Ahmad Raza

### 🚀 Getting Started

```bash
npm install jwt-redis-sessions
```

See [README.md](README.md) for complete documentation and examples.

### 🔐 Security Features Implemented

- JWT secret validation (minimum 32 characters)
- Token blacklisting for immediate revocation
- Constant-time string comparison
- Redis SCAN instead of KEYS for production safety
- Memory leak prevention in rate limiting
- Algorithm confusion attack prevention
- Session hijacking protection
- Input validation and sanitization

---

_This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format._
