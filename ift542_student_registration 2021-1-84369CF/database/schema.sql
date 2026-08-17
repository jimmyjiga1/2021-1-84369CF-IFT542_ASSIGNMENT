-- IFT542 Student Registration Web Application
-- Database schema (MySQL 8+)
-- All tables use InnoDB with foreign keys for referential integrity.

CREATE DATABASE IF NOT EXISTS student_registration
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE student_registration;

-- ---------------------------------------------------------------
-- users: students and admins. Passwords are NEVER stored in plain
-- text or reversible form -- only as Argon2id hashes.
-- ---------------------------------------------------------------
CREATE TABLE users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    matric_no       VARCHAR(20)  NOT NULL UNIQUE,
    email           VARCHAR(190) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(120) NOT NULL,
    bio             VARCHAR(500) NULL,               -- deliberately rendered on profile page (XSS target)
    role            ENUM('student','admin') NOT NULL DEFAULT 'student',
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- login_attempts: append-only audit trail used for rate limiting
-- and lockout decisions. Never stores the submitted password.
-- ---------------------------------------------------------------
CREATE TABLE login_attempts (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    identifier      VARCHAR(190) NOT NULL,   -- email/matric as submitted, lower-cased
    ip_address      VARCHAR(45)  NOT NULL,
    success         TINYINT(1)   NOT NULL,
    attempted_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_time (identifier, attempted_at),
    INDEX idx_ip_time (ip_address, attempted_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- account_lockouts: temporary lockout state per user.
-- ---------------------------------------------------------------
CREATE TABLE account_lockouts (
    user_id         INT UNSIGNED PRIMARY KEY,
    locked_until    DATETIME NOT NULL,
    reason          VARCHAR(100) NOT NULL DEFAULT 'too_many_failed_attempts',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- password_resets: single-use, time-limited, hashed tokens only.
-- The raw token is emailed/shown once and never stored.
-- ---------------------------------------------------------------
CREATE TABLE password_resets (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED NOT NULL,
    token_hash      CHAR(64) NOT NULL,        -- sha256 hex of the raw token
    expires_at      DATETIME NOT NULL,
    used_at         DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- courses
-- ---------------------------------------------------------------
CREATE TABLE courses (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code            VARCHAR(20) NOT NULL UNIQUE,
    title           VARCHAR(150) NOT NULL,
    credit_units    TINYINT UNSIGNED NOT NULL DEFAULT 3,
    capacity        SMALLINT UNSIGNED NOT NULL DEFAULT 60,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- enrolments
-- ---------------------------------------------------------------
CREATE TABLE enrolments (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    student_id      INT UNSIGNED NOT NULL,
    course_id       INT UNSIGNED NOT NULL,
    status          ENUM('active','dropped') NOT NULL DEFAULT 'active',
    enrolled_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_student_course (student_id, course_id),
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- documents: uploaded student documents (metadata only; files
-- live outside the web root in storage/uploads).
-- ---------------------------------------------------------------
CREATE TABLE documents (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    student_id      INT UNSIGNED NOT NULL,
    original_name   VARCHAR(255) NOT NULL,
    stored_name     VARCHAR(255) NOT NULL UNIQUE, -- random name on disk, prevents path traversal / overwrite
    mime_type       VARCHAR(100) NOT NULL,
    size_bytes      INT UNSIGNED NOT NULL,
    uploaded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- security_events: structured application-level audit log mirror
-- (also written to storage/logs/security.log as JSON lines).
-- Kept in DB so the "Database evidence" submission item has a
-- queryable table, separate from the users table.
-- ---------------------------------------------------------------
CREATE TABLE security_events (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type      VARCHAR(60) NOT NULL,   -- e.g. login_failed, auth_denied, validation_rejected
    subject         VARCHAR(190) NULL,      -- matric/email/identifier, never a password
    ip_address      VARCHAR(45) NOT NULL,
    detail          VARCHAR(255) NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type_time (event_type, created_at)
) ENGINE=InnoDB;
