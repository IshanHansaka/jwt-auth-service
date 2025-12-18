<p align="center">
  <img src="https://img.shields.io/badge/Spring%20Boot-3.5.7-brightgreen?style=for-the-badge&logo=springboot" alt="Spring Boot"/>
  <img src="https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=openjdk" alt="Java 21"/>
  <img src="https://img.shields.io/badge/JWT-0.13.0-blue?style=for-the-badge&logo=jsonwebtokens" alt="JWT"/>
  <img src="https://img.shields.io/badge/PostgreSQL-Latest-336791?style=for-the-badge&logo=postgresql" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🔐 JWT Authentication Service</h1>

<p align="center">
  A production-ready, secure, and reusable Spring Boot template for JWT-based authentication with role-based authorization, email verification, and PostgreSQL integration.
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Configuration](#environment-configuration)
- [API Documentation](#-api-documentation)
  - [Authentication Endpoints](#authentication-endpoints)
  - [Request/Response Examples](#requestresponse-examples)
- [Security Features](#-security-features)
- [Database Schema](#-database-schema)
- [Configuration](#-configuration)
- [Testing](#-testing)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Core Authentication

- ✅ **User Registration** with email validation
- ✅ **User Login** with JWT access & refresh tokens
- ✅ **Token Refresh** mechanism with rotation
- ✅ **Secure Logout** with token invalidation
- ✅ **Email Verification** with secure token links
- ✅ **Password Reset** via email with time-limited tokens
- ✅ **Resend Verification Email** with cooldown protection

### Security

- 🔒 **BCrypt Password Hashing** (strength 12)
- 🔒 **HttpOnly Cookies** for refresh tokens
- 🔒 **CSRF Protection** for sensitive endpoints
- 🔒 **Role-Based Access Control** (RBAC)
- 🔒 **Stateless JWT Authentication**
- 🔒 **Token Expiration & Rotation**
- 🔒 **Rate Limiting** on email operations
- 🔒 **Input Validation** with Bean Validation
- 🔒 **Secure Token Hashing** for database storage

### Developer Experience

- 📖 **OpenAPI/Swagger UI** documentation
- 🧪 **Comprehensive Test Suite** (Unit & Integration)
- 📧 **HTML Email Templates** with Thymeleaf
- 🔧 **Environment-based Configuration**
- 📦 **Clean Architecture** with separation of concerns

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Application                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    JWT Authentication Filter                     │
│              (Validates Bearer token on each request)            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Security Filter Chain                       │
│         (CORS, CSRF, Authorization Rules, Exception Handling)   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         REST Controllers                         │
│                    (AuthController, etc.)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Service Layer                            │
│    (AuthService, JwtService, EmailService, etc.)                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Repository Layer                           │
│              (Spring Data JPA Repositories)                      │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        PostgreSQL Database                       │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
┌──────┐                    ┌──────────┐                 ┌────────┐
│Client│                    │API Server│                 │Database│
└──┬───┘                    └────┬─────┘                 └───┬────┘
   │                             │                           │
   │  1. POST /auth/register     │                           │
   │────────────────────────────>│                           │
   │                             │  Save user (unverified)   │
   │                             │──────────────────────────>│
   │                             │  Send verification email  │
   │  201 Created + user info    │                           │
   │<────────────────────────────│                           │
   │                             │                           │
   │  2. GET /auth/verify-email  │                           │
   │────────────────────────────>│                           │
   │                             │  Mark email verified      │
   │  200 OK                     │──────────────────────────>│
   │<────────────────────────────│                           │
   │                             │                           │
   │  3. POST /auth/login        │                           │
   │────────────────────────────>│                           │
   │                             │  Validate credentials     │
   │                             │──────────────────────────>│
   │  200 OK + accessToken       │                           │
   │  + refreshToken (cookie)    │                           │
   │<────────────────────────────│                           │
   │                             │                           │
   │  4. GET /protected          │                           │
   │  Authorization: Bearer xxx  │                           │
   │────────────────────────────>│                           │
   │                             │  Validate JWT             │
   │  200 OK + data              │                           │
   │<────────────────────────────│                           │
   │                             │                           │
   │  5. POST /auth/refresh      │                           │
   │  Cookie: refreshToken=xxx   │                           │
   │────────────────────────────>│                           │
   │                             │  Rotate refresh token     │
   │  200 OK + new accessToken   │──────────────────────────>│
   │  + new refreshToken         │                           │
   │<────────────────────────────│                           │
└──┴───┘                    └────┴─────┘                 └───┴────┘
```

---

## 🛠 Tech Stack

| Technology            | Version  | Purpose               |
| --------------------- | -------- | --------------------- |
| **Java**              | 21 (LTS) | Programming language  |
| **Spring Boot**       | 3.5.7    | Application framework |
| **Spring Security**   | 6.x      | Security framework    |
| **Spring Data JPA**   | 3.x      | Data persistence      |
| **PostgreSQL**        | Latest   | Relational database   |
| **JJWT**              | 0.13.0   | JWT token handling    |
| **Lombok**            | Latest   | Boilerplate reduction |
| **Thymeleaf**         | 3.x      | Email templates       |
| **SpringDoc OpenAPI** | 2.8.13   | API documentation     |
| **Maven**             | 3.x      | Build tool            |
| **JUnit 5**           | 5.x      | Testing framework     |

---

## 📁 Project Structure

```
jwt-auth-service/
├── src/
│   ├── main/
│   │   ├── java/com/ishan/security/jwt_auth_service/
│   │   │   ├── config/                    # Configuration classes
│   │   │   │   ├── SecurityConfig.java    # Spring Security configuration
│   │   │   │   ├── SwaggerConfig.java     # OpenAPI documentation
│   │   │   │   └── SchedulingConfig.java  # Scheduled tasks config
│   │   │   │
│   │   │   ├── controller/                # REST API endpoints
│   │   │   │   ├── AuthController.java    # Authentication endpoints
│   │   │   │   └── HealthCheckController.java
│   │   │   │
│   │   │   ├── dto/                       # Data Transfer Objects
│   │   │   │   ├── request/               # Request DTOs
│   │   │   │   │   ├── ForgotPasswordRequestDTO.java
│   │   │   │   │   ├── ResendEmailRequestDTO.java
│   │   │   │   │   └── ResetPasswordRequestDTO.java
│   │   │   │   ├── response/              # Response DTOs
│   │   │   │   │   ├── ApiResponseDTO.java
│   │   │   │   │   ├── JwtTokensDTO.java
│   │   │   │   │   ├── LoginResponseDTO.java
│   │   │   │   │   └── RegisterResponseDTO.java
│   │   │   │   └── user/                  # User DTOs
│   │   │   │       ├── UserLoginDTO.java
│   │   │   │       └── UserRegisterDTO.java
│   │   │   │
│   │   │   ├── enums/                     # Enumeration types
│   │   │   │   └── UserRole.java          # ROLE_USER, ROLE_ADMIN
│   │   │   │
│   │   │   ├── exception/                 # Custom exceptions
│   │   │   │   ├── EmailAlreadyExistsException.java
│   │   │   │   ├── EmailNotVerifiedException.java
│   │   │   │   ├── GlobalExceptionHandler.java
│   │   │   │   └── ...
│   │   │   │
│   │   │   ├── filter/                    # Security filters
│   │   │   │   └── JwtAuthenticationFilter.java
│   │   │   │
│   │   │   ├── job/                       # Scheduled jobs
│   │   │   │
│   │   │   ├── model/                     # Entity classes
│   │   │   │   ├── User.java
│   │   │   │   ├── UserPrincipal.java
│   │   │   │   ├── RefreshToken.java
│   │   │   │   ├── EmailVerificationToken.java
│   │   │   │   └── PasswordResetToken.java
│   │   │   │
│   │   │   ├── repository/                # Data access layer
│   │   │   │   ├── UserRepository.java
│   │   │   │   ├── RefreshTokenRepository.java
│   │   │   │   ├── EmailVerificationTokenRepository.java
│   │   │   │   └── PasswordResetTokenRepository.java
│   │   │   │
│   │   │   ├── service/                   # Business logic
│   │   │   │   ├── AuthService.java
│   │   │   │   ├── JwtService.java
│   │   │   │   ├── EmailService.java
│   │   │   │   ├── EmailVerificationService.java
│   │   │   │   ├── PasswordResetService.java
│   │   │   │   └── CustomUserDetailsService.java
│   │   │   │
│   │   │   ├── util/                      # Utility classes
│   │   │   │
│   │   │   └── JwtAuthServiceApplication.java
│   │   │
│   │   └── resources/
│   │       ├── application.properties     # Application configuration
│   │       ├── templates/                 # Email templates
│   │       │   ├── verification-email.html
│   │       │   └── password-reset-email.html
│   │       └── static/
│   │
│   └── test/                              # Test classes
│
├── .env.example                           # Environment template
├── pom.xml                                # Maven configuration
└── README.md                              # This file
```

---

## 🚀 Getting Started

### Prerequisites

- **Java 21** or higher ([Download](https://adoptium.net/))
- **Maven 3.8+** ([Download](https://maven.apache.org/download.cgi))
- **PostgreSQL 14+** ([Download](https://www.postgresql.org/download/))
- **SMTP Server** (Gmail, SendGrid, or any SMTP provider)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/jwt-auth-service.git
   cd jwt-auth-service
   ```

2. **Create PostgreSQL database**

   ```sql
   CREATE DATABASE jwt_auth_db;
   ```

3. **Configure environment variables**

   ```bash
   cp .env.example .env
   # Edit .env with your configurations
   ```

4. **Build the project**

   ```bash
   ./mvnw clean install
   ```

5. **Run the application**

   ```bash
   ./mvnw spring-boot:run
   ```

6. **Access the API**
   - Application: `http://localhost:8080`
   - Swagger UI: `http://localhost:8080/swagger-ui.html`

### Environment Configuration

Create a `.env` file in the root directory:

```properties
# Database Configuration
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/jwt_auth_db
SPRING_DATASOURCE_USERNAME=your_db_username
SPRING_DATASOURCE_PASSWORD=your_db_password

# JWT Secret Key (Generate a secure 256-bit key)
# Use: openssl rand -base64 64
JWT_SECRET=your-super-secret-key-minimum-256-bits-base64-encoded

# Email Configuration (Gmail example)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
```

#### Generating a Secure JWT Secret

```bash
# Using OpenSSL
openssl rand -base64 64

# Using Java
java -e "import java.security.SecureRandom; import java.util.Base64; byte[] key = new byte[64]; new SecureRandom().nextBytes(key); System.out.println(Base64.getEncoder().encodeToString(key));"
```

---

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint                               | Description            | Auth Required     |
| ------ | -------------------------------------- | ---------------------- | ----------------- |
| `POST` | `/api/v1/auth/register`                | Register new user      | ❌                |
| `POST` | `/api/v1/auth/login`                   | Authenticate user      | ❌                |
| `POST` | `/api/v1/auth/refresh`                 | Refresh access token   | 🍪 Refresh Cookie |
| `POST` | `/api/v1/auth/logout`                  | Logout user            | 🍪 Refresh Cookie |
| `GET`  | `/api/v1/auth/verify-email`            | Verify email address   | ❌                |
| `POST` | `/api/v1/auth/resend-email`            | Resend verification    | ❌                |
| `POST` | `/api/v1/auth/forgot-password`         | Request password reset | ❌                |
| `POST` | `/api/v1/auth/reset-password`          | Reset password         | ❌                |
| `GET`  | `/api/v1/auth/reset-password/validate` | Validate reset token   | ❌                |

### Request/Response Examples

#### Register User

**Request:**

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "SecureP@ss123"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "User registered successfully! Please verify your email to activate your account.",
  "path": "/api/v1/auth/register",
  "data": {
    "email": "user@example.com",
    "name": "John Doe"
  },
  "timestamp": "2025-12-18T10:30:00Z"
}
```

#### Login

**Request:**

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Login successful",
  "path": "/api/v1/auth/login",
  "data": {
    "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
  },
  "timestamp": "2025-12-18T10:30:00Z"
}
```

**Headers:**

```http
Set-Cookie: refreshToken=eyJ...; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
```

#### Access Protected Resource

**Request:**

```http
GET /api/v1/protected/resource
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

#### Refresh Token

**Request:**

```http
POST /api/v1/auth/refresh
Cookie: refreshToken=eyJ...
```

**Response:**

```json
{
  "status": "success",
  "message": "Access token refreshed successfully",
  "path": "/api/v1/auth/refresh",
  "data": {
    "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
  },
  "timestamp": "2025-12-18T10:35:00Z"
}
```

#### Password Validation Rules

| Rule              | Requirement                  |
| ----------------- | ---------------------------- |
| Minimum Length    | 8 characters                 |
| Uppercase         | At least 1 uppercase letter  |
| Lowercase         | At least 1 lowercase letter  |
| Number            | At least 1 digit             |
| Special Character | At least 1 special character |

---

## 🔒 Security Features

### JWT Token Structure

**Access Token Claims:**

```json
{
  "sub": "user@example.com",
  "role": "USER",
  "token_type": "access",
  "iat": 1702900200,
  "exp": 1702901100,
  "jti": "unique-token-id",
  "iss": "jwt-auth-service"
}
```

**Token Configuration:**
| Token Type | Expiration | Storage |
|------------|------------|---------|
| Access Token | 15 minutes | Client memory |
| Refresh Token | 7 days | HttpOnly Cookie |

### Security Best Practices Implemented

1. **Password Security**

   - BCrypt hashing with strength factor 12
   - Strong password policy enforcement
   - Password never logged or exposed

2. **Token Security**

   - Refresh token rotation on each use
   - Secure HttpOnly cookies for refresh tokens
   - Token hashing before database storage
   - Short-lived access tokens

3. **Session Security**

   - Stateless JWT authentication
   - No server-side session storage
   - CSRF protection on sensitive endpoints

4. **API Security**

   - CORS configuration
   - Input validation on all endpoints
   - Consistent error responses (no information leakage)
   - Rate limiting on email operations

5. **Database Security**
   - Parameterized queries (JPA)
   - Minimal data exposure in responses
   - Secure token storage with hashing

### Role-Based Access Control

This template uses a single-role-per-user model for simplicity:

```java
public enum UserRole {
    ROLE_USER,   // Standard user access
    ROLE_ADMIN   // Administrative access
}
```

**Authorization Examples:**

```java
// Public endpoints
.requestMatchers("/api/v1/auth/**", "/api/v1/public/**").permitAll()

// Admin-only endpoints
.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

// Authenticated users
.anyRequest().authenticated()
```

The design can be extended to multi-role or permission-based systems if required.

---

## 🗄 Database Schema

### Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                            users                                 │
├─────────────────────────────────────────────────────────────────┤
│ PK │ user_id                    BIGINT AUTO_INCREMENT           │
│    │ email                      VARCHAR(150) UNIQUE NOT NULL    │
│    │ name                       VARCHAR(100) NOT NULL           │
│    │ password                   VARCHAR(255) NOT NULL           │
│    │ role                       VARCHAR(30) NOT NULL            │
│    │ email_verified             BOOLEAN DEFAULT FALSE           │
│    │ created_at                 TIMESTAMP                       │
│    │ last_login                 TIMESTAMP                       │
│    │ last_verification_email_sent TIMESTAMP                     │
│    │ last_password_reset_email_sent TIMESTAMP                   │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
│  refresh_tokens   │  │email_verification │  │password_reset     │
│                   │  │     _tokens       │  │    _tokens        │
├───────────────────┤  ├───────────────────┤  ├───────────────────┤
│ PK │ id           │  │ PK │ id           │  │ PK │ id           │
│ FK │ user_id      │  │ FK │ user_id      │  │ FK │ user_id      │
│    │ token_hash   │  │    │ token_hash   │  │    │ token_hash   │
│    │ expires_at   │  │    │ expires_at   │  │    │ expires_at   │
│    │ revoked      │  │    │ used         │  │    │ used         │
│    │ created_at   │  │    │ created_at   │  │    │ created_at   │
└───────────────────┘  └───────────────────┘  └───────────────────┘
```

---

## ⚙ Configuration

### Application Properties

```properties
# Application
spring.application.name=JWT Auth Service

# URLs
app.frontend-url=http://localhost:3000
app.backend-url=http://localhost:8080

# Token Expiration
app.security.token.expiry-minutes=15           # Email/reset tokens
app.security.resend-email-cooldown-minutes=5   # Rate limiting

# JWT Configuration
jwt.secret=${JWT_SECRET}
jwt.access.expiration=900000                   # 15 minutes (ms)
jwt.refresh.expiration=604800000               # 7 days (ms)

# Database
spring.datasource.url=${SPRING_DATASOURCE_URL}
spring.datasource.username=${SPRING_DATASOURCE_USERNAME}
spring.datasource.password=${SPRING_DATASOURCE_PASSWORD}
spring.jpa.hibernate.ddl-auto=update           # Use 'validate' in production
spring.jpa.open-in-view=false                  # Best practice

# Email (Gmail SMTP)
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=${MAIL_USERNAME}
spring.mail.password=${MAIL_PASSWORD}
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```

### Production Recommendations

| Setting                         | Development   | Production                |
| ------------------------------- | ------------- | ------------------------- |
| `spring.jpa.hibernate.ddl-auto` | `update`      | `validate`                |
| `spring.jpa.show-sql`           | `true`        | `false`                   |
| Cookie `secure` flag            | `false`       | `true`                    |
| CORS origins                    | `localhost:*` | Specific domains          |
| JWT expiration                  | 15min/7days   | Adjust per security needs |

---

## 🧪 Testing

### Run All Tests

```bash
./mvnw test
```

### Run Specific Test Class

```bash
./mvnw test -Dtest=AuthControllerTest
```

### Test Coverage

```bash
./mvnw test jacoco:report
# Report: target/site/jacoco/index.html
```

### Test Categories

| Category          | Description             | Location                                |
| ----------------- | ----------------------- | --------------------------------------- |
| Unit Tests        | Service layer testing   | `src/test/java/.../service/`            |
| Integration Tests | Controller + DB testing | `src/test/java/.../controller/*IT.java` |

---

## 🚢 Deployment

### Docker Deployment

**Dockerfile:**

```dockerfile
FROM eclipse-temurin:21-jdk-alpine as build
WORKDIR /app
COPY . .
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**docker-compose.yml:**

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - '8080:8080'
    environment:
      - SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/jwt_auth_db
      - SPRING_DATASOURCE_USERNAME=postgres
      - SPRING_DATASOURCE_PASSWORD=postgres
      - JWT_SECRET=${JWT_SECRET}
      - MAIL_USERNAME=${MAIL_USERNAME}
      - MAIL_PASSWORD=${MAIL_PASSWORD}
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=jwt_auth_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - '5432:5432'

volumes:
  postgres_data:
```

### Production Checklist

- [ ] Use `validate` for `hibernate.ddl-auto`
- [ ] Disable SQL logging
- [ ] Enable HTTPS/TLS
- [ ] Set secure cookie flags
- [ ] Configure production CORS origins
- [ ] Use strong, unique JWT secret
- [ ] Set up database backups
- [ ] Configure rate limiting
- [ ] Enable access logging
- [ ] Set up monitoring/alerting

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Code Standards

- Follow [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
- Write unit tests for new features
- Update documentation as needed
- Keep commits atomic and well-described

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)
- [JJWT Library](https://github.com/jwtk/jjwt)
- [OWASP Security Guidelines](https://owasp.org/)

---

<p align="center">
  Made with ❤️ for the developer community
</p>

<p align="center">
  <a href="https://github.com/yourusername/jwt-auth-service/issues">Report Bug</a>
  ·
  <a href="https://github.com/yourusername/jwt-auth-service/issues">Request Feature</a>
</p>
