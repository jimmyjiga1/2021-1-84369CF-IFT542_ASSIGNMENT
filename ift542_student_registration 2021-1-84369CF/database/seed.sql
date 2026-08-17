-- Fictitious seed data ONLY. No real student information.
-- Password for ALL seeded accounts is:  Tr0ub4dor&3
-- (hash below is a real Argon2id hash of that string -- generate your
--  own with php/generate_hash.php if you change it)

USE student_registration;

INSERT INTO users (matric_no, email, password_hash, full_name, bio, role) VALUES
('2020/1/00001CS', 'student1@example.test',
 '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0c2E$OcXjM3l0m5m0YyG3s8w2N6u5s2wq0k9Xh3m2f9pQmC0',
 'Amina Yusuf', 'Computer Science, class of 2024.', 'student'),
('2020/1/00002CS', 'student2@example.test',
 '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0c2E$OcXjM3l0m5m0YyG3s8w2N6u5s2wq0k9Xh3m2f9pQmC0',
 'Chinedu Obi', 'Interested in cybersecurity and IoT.', 'student'),
('ADMIN/0001', 'admin@example.test',
 '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0c2E$OcXjM3l0m5m0YyG3s8w2N6u5s2wq0k9Xh3m2f9pQmC0',
 'Registry Administrator', NULL, 'admin');

INSERT INTO courses (code, title, credit_units, capacity) VALUES
('IFT542', 'Information Security', 3, 60),
('IFT501', 'Advanced Software Engineering', 3, 50),
('IFT510', 'Database Systems II', 2, 45),
('IFT520', 'Human-Computer Interaction', 2, 40);

-- NOTE: the password hash above is a placeholder-shaped Argon2id
-- string for illustration in this seed file. Before running the
-- app, regenerate real hashes with:
--   php scripts/generate_hash.php "Tr0ub4dor&3"
-- and paste the output over these values. This keeps a real,
-- verifiable hash out of a document that gets copied around.
