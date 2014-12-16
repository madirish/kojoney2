-- This file is part of the Kojoney2 honeypot
--
-- Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
-- Last updated 28 January 2013

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` INTEGER PRIMARY KEY,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `username` VARCHAR(16),
  `password` VARCHAR(20),
  `ip_numeric` INTEGER,
  `sensor_id` INTEGER
);

CREATE TABLE IF NOT EXISTS `executed_commands` (
  `id` INTEGER PRIMARY KEY,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `command` VARCHAR(100),
  `ip_numeric` INTEGER,
  `sensor_id` INTEGER
);

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` INTEGER PRIMARY KEY,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `ip_numeric` INTEGER,
  `url` VARCHAR(100),
  `md5sum` VARCHAR(32),
  `filetype` VARCHAR(255),
  `clamsig` TEXT,
  `sensor_id` INTEGER
  `file` LONGBLOB
);

-- nmap_scans table added by Josh Bauer <joshbauer3@gmail.com>
CREATE TABLE IF NOT EXISTS `nmap_scans` (
  `id` INTEGER PRIMARY KEY,
  `time` TIMESTAMP,
  `ip` VARCHAR(15),
  `ip_numeric` INTEGER,
  `sensor_id` INTEGER,
  `nmap_output` TEXT
);