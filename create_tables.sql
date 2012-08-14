USE kojoney;

CREATE TABLE login_attempts (
  id INT(12) PRIMARY KEY AUTO_INCREMENT,
  time TIMESTAMP,
  ip VARCHAR(15),
  username VARCHAR(16),
  password VARCHAR(20)
);

CREATE TABLE executed_commands (
  id INT(12) PRIMARY KEY AUTO_INCREMENT,
  time TIMESTAMP,
  ip VARCHAR(15),
  command VARCHAR(100)
);
