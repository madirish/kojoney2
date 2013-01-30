-- This file is part of the Kojoney2 honeypot
--
-- Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
-- Last updated 28 January 2013

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

CREATE TABLE IF NOT EXISTS `downloads` (
	`id` INT(12) PRIMARY KEY AUTO_INCREMENT NOT NULL,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `ip_numeric` INT(10) UNSIGNED,
  `url` VARCHAR(100),
  `md5sum` VARCHAR(32),
  `filetype` VARCHAR(255),
  `clamsig` text
);