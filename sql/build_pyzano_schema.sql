DROP TABLE IF EXISTS `fingerprints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fingerprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file_name` varchar(255) NOT NULL,
  `file_fingerprint` varchar(255) NOT NULL,
  `last_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `file_location` varchar(255) NOT NULL,
  `bin_string` longtext,
  `host_name` tinytext,
  PRIMARY KEY (`id`),
  UNIQUE KEY `file_fingerprint` (`file_fingerprint`),
  KEY `file_name` (`file_name`)
) ENGINE=InnoDB AUTO_INCREMENT=1199 DEFAULT CHARSET=latin1;
