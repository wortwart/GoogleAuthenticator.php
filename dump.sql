CREATE DATABASE IF NOT EXISTS `2factorauth` DEFAULT CHARACTER SET utf8;

USE `2factorauth`;
CREATE TABLE `users` (
  `id` int(8) unsigned NOT NULL AUTO_INCREMENT,
  `login` varchar(30) NOT NULL,
  `password` varchar(32) NOT NULL,
  `secret` varchar(16) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `login` (`login`)
);
