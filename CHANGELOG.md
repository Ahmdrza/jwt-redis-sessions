# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2025-01-25

### 📦 Package Optimization

This release focuses on reducing package size while maintaining full functionality and developer experience.

#### ✨ Optimizations

- **Documentation streamlining** - Optimized JSDoc comments across all files
- **TypeScript definitions** - Condensed verbose documentation while preserving all type information
- **Package size reduction** - Reduced unpacked size by 11.7% (51.5kB → 45.5kB)
- **File size improvements**:
  - `jwt.service.js`: 12.8kB → 10.5kB (-18%)
  - `index.d.ts`: 8.3kB → 4.6kB (-45%)

#### 🎯 Benefits

- **Faster installs** - Smaller download size
- **Better performance** - Reduced memory footprint
- **Same functionality** - Zero breaking changes
- **Maintained DX** - All TypeScript definitions preserved

#### ✅ Quality Assurance

- All 102 tests passing
- Zero functional changes
- Complete API compatibility
- Full TypeScript support maintained

---

## [2.0.0] - 2025-01-25

### 🚨 BREAKING CHANGES

This is a major release with significant architectural improvements that require migration.

#### Removed Features

- **Removed `optionalAuth` middleware** - Use regular `auth` middleware and handle optional logic in your application
- **Removed handler functions** - Use core functions directly:
  - `logout()` → Use `revokeToken()`
  - `logoutAll()` → Use `revokeAllUserTokens()`
  - `refresh()` → Use `refreshToken()`
- **Removed `utils` export** - Internal utilities are no longer exposed
- **Removed request object modifications** - No more `req.jrs` or similar data attached to requests

#### Parameter Changes

- **`revokeAllUserTokens(userId)` → `revokeAllUserTokens(userIdentifier)`**
- **`getUserSessions(userId)` → `getUserSessions(userIdentifier)`**

### ✨ What's New

#### Improved API Design

- **Cleaner API surface** - Removed redundant wrapper functions
- **Better parameter naming** - `userIdentifier` clearly indicates it accepts userId, id, or email
- **No request pollution** - Library no longer modifies Express request objects

#### Enhanced TypeScript Support

- **Fixed missing parameters** - Added `maxMapSize` parameter to `rateLimit` function signature
- **Comprehensive JSDoc** - Detailed documentation in TypeScript definitions
- **Better type safety** - More precise parameter and return types

### 🔧 Migration Guide

#### 1. Replace Handler Functions

```javascript
// Before v2.0.0
const { logout, logoutAll, refresh } = require('jwt-redis-sessions')
await logout(req, res)
await logoutAll(req, res)
const newTokens = await refresh(req, res)

// v2.0.0+
const {
  revokeToken,
  revokeAllUserTokens,
  refreshToken,
  verifyToken,
} = require('jwt-redis-sessions')
const token = req.headers.authorization?.split(' ')[1]
await revokeToken(token)
const result = await verifyToken(token)
await revokeAllUserTokens(result.decoded.userId)
const newTokens = await refreshToken(refreshTokenValue)
```

#### 2. Handle Auth Data Manually

```javascript
// Before v2.0.0
app.get('/profile', auth, (req, res) => {
  const userData = req.jrs.user
  const sessionData = req.jrs.session
})

// v2.0.0+
app.get('/profile', auth, async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]
  const result = await verifyToken(token)
  const userData = result.decoded
  const sessionData = result.session
})
```

#### 3. Replace Optional Auth

```javascript
// Before v2.0.0
app.get('/public', optionalAuth, (req, res) => {
  if (req.jrs) {
    // User is authenticated
  }
})

// v2.0.0+
app.get('/public', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]
    if (token) {
      const result = await verifyToken(token)
      // User is authenticated - use result.decoded
    }
  } catch (error) {
    // No valid token - handle as guest user
  }
})
```

#### 4. Update Parameter Names

```javascript
// Before v2.0.0
await revokeAllUserTokens(userId)
const sessions = await getUserSessions(userId)

// v2.0.0+
await revokeAllUserTokens(userIdentifier) // userId, id, or email
const sessions = await getUserSessions(userIdentifier) // userId, id, or email
```

### 📦 Package Improvements

- **Additional size reduction** - 14.7kB compressed (30% smaller than v1.0.1)
- **Cleaner codebase** - Removed redundant handler functions
- **Better maintainability** - Simplified architecture with focused responsibilities
- **Node.js requirement** - Updated minimum version from 14.0.0 → 16.0.0 (14.x is EOL)

### 🐛 Bug Fixes

- Fixed variable name shadowing in documentation examples
- Fixed missing TypeScript parameter definitions
- Fixed inconsistent parameter names across codebase
- Fixed outdated documentation references

### 📚 Documentation

- Updated API reference with correct function signatures
- Added comprehensive migration guide
- Updated all examples to use direct function calls
- Improved JSDoc comments in TypeScript definitions

---

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

- **Node.js**: >=16.0.0
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
