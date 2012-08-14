CREATE DATABASE IF NOT EXISTS kojoney;

USE kojoney;

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` INT(12) PRIMARY KEY AUTO_INCREMENT NOT NULL,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `username` VARCHAR(16),
  `password` VARCHAR(20),
  `ip_numeric` INT(10) UNSIGNED
);

CREATE TABLE IF NOT EXISTS `executed_commands` (
  `id` INT(12) PRIMARY KEY AUTO_INCREMENT NOT NULL,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `command` VARCHAR(100),
  `ip_numeric` INT(10) UNSIGNED
);
