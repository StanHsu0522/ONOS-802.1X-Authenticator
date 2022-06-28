-- MySQL dump 10.13  Distrib 5.7.38, for Linux (x86_64)
--
-- Host: localhost    Database: SDN1X
-- ------------------------------------------------------
-- Server version	5.7.38-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `activeDevice`
--

DROP TABLE IF EXISTS `activeDevice`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `activeDevice` (
  `mac` varchar(255) NOT NULL,
  `switch_id` int(11) DEFAULT NULL,
  `switch_port` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `err_ctr` int(11) DEFAULT '0',
  `blked` bit(1) DEFAULT b'0',
  `err_exp_time` datetime DEFAULT NULL,
  `blk_exp_time` datetime DEFAULT NULL,
  PRIMARY KEY (`mac`),
  KEY `switch_id` (`switch_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `activeDevice_ibfk_1` FOREIGN KEY (`switch_id`) REFERENCES `switch` (`switch_id`) ON DELETE NO ACTION,
  CONSTRAINT `activeDevice_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`) ON DELETE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `activeDevice`
--

LOCK TABLES `activeDevice` WRITE;
/*!40000 ALTER TABLE `activeDevice` DISABLE KEYS */;
/*!40000 ALTER TABLE `activeDevice` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authenLog`
--

DROP TABLE IF EXISTS `authenLog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authenLog` (
  `log_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `mac` varchar(255) DEFAULT NULL,
  `ip` varchar(255) DEFAULT NULL,
  `switch_id` int(11) DEFAULT NULL,
  `switch_port` int(255) DEFAULT NULL,
  `auth_state` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`log_id`),
  KEY `user_id` (`user_id`),
  KEY `authenLog_ibfk_2` (`switch_id`),
  CONSTRAINT `authenLog_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`) ON DELETE NO ACTION,
  CONSTRAINT `authenLog_ibfk_2` FOREIGN KEY (`switch_id`) REFERENCES `switch` (`switch_id`) ON DELETE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authenLog`
--

LOCK TABLES `authenLog` WRITE;
/*!40000 ALTER TABLE `authenLog` DISABLE KEYS */;
INSERT INTO `authenLog` VALUES (1,2,'9C:FC:E8:C9:E9:1A',NULL,4,3,'AUTHORIZED_STATE','2022-06-28 15:48:59'),(2,2,'9C:FC:E8:C9:E9:1A','192.168.44.170',4,3,'NET_ACCESS','2022-06-28 15:49:00'),(3,2,'9C:FC:E8:C9:E9:1A',NULL,4,3,'AUTHORIZED_STATE','2022-06-28 15:51:01');
/*!40000 ALTER TABLE `authenLog` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authorizedDevice`
--

DROP TABLE IF EXISTS `authorizedDevice`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authorizedDevice` (
  `mac` varchar(255) NOT NULL,
  `switch_id` int(11) DEFAULT NULL,
  `switch_port` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `ip` varchar(255) DEFAULT NULL,
  `rule_installed` bit(1) DEFAULT NULL,
  `auth_exp_time` datetime DEFAULT NULL,
  PRIMARY KEY (`mac`),
  KEY `switch_id` (`switch_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `authorizedDevice_ibfk_1` FOREIGN KEY (`switch_id`) REFERENCES `switch` (`switch_id`) ON DELETE NO ACTION,
  CONSTRAINT `authorizedDevice_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`) ON DELETE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authorizedDevice`
--

LOCK TABLES `authorizedDevice` WRITE;
/*!40000 ALTER TABLE `authorizedDevice` DISABLE KEYS */;
INSERT INTO `authorizedDevice` VALUES ('9C:FC:E8:C9:E9:1A',4,3,2,3,'192.168.44.170',_binary '','2022-06-28 15:58:59');
/*!40000 ALTER TABLE `authorizedDevice` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blackList`
--

DROP TABLE IF EXISTS `blackList`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blackList` (
  `mac` varchar(255) NOT NULL,
  `timestamp` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`mac`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blackList`
--

LOCK TABLES `blackList` WRITE;
/*!40000 ALTER TABLE `blackList` DISABLE KEYS */;
/*!40000 ALTER TABLE `blackList` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `group`
--

DROP TABLE IF EXISTS `group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `group` (
  `group_id` int(11) NOT NULL,
  `group_name` varchar(255) DEFAULT NULL,
  `login_timeout` int(11) DEFAULT NULL,
  `dscp` tinyint(4) DEFAULT NULL,
  `traffic_rate` int(11) DEFAULT NULL,
  PRIMARY KEY (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `group`
--

LOCK TABLES `group` WRITE;
/*!40000 ALTER TABLE `group` DISABLE KEYS */;
INSERT INTO `group` VALUES (1,'faculty',600,60,40960),(2,'staff',600,61,30720),(3,'student',600,62,20480),(4,'guest',600,63,10240);
/*!40000 ALTER TABLE `group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `groupACL`
--

DROP TABLE IF EXISTS `groupACL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `groupACL` (
  `acl_id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) DEFAULT NULL,
  `dst_domain` varchar(255) DEFAULT NULL,
  `dst_ip` varchar(255) DEFAULT NULL,
  `dst_port` int(11) DEFAULT NULL,
  `protocol` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`acl_id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `groupACL_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `group` (`group_id`) ON DELETE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `groupACL`
--

LOCK TABLES `groupACL` WRITE;
/*!40000 ALTER TABLE `groupACL` DISABLE KEYS */;
INSERT INTO `groupACL` VALUES (1,2,'','140.113.194.235',NULL,NULL),(2,3,'','140.113.40.34',NULL,NULL),(3,4,'','140.113.40.34',NULL,NULL),(4,4,'','140.113.41.24',NULL,NULL),(5,4,'e3.nycu.edu.tw','',NULL,NULL),(6,4,'www.nycu.edu.tw','',NULL,NULL);
/*!40000 ALTER TABLE `groupACL` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `switch`
--

DROP TABLE IF EXISTS `switch`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `switch` (
  `switch_id` int(11) NOT NULL,
  `switch_uri` varchar(255) NOT NULL,
  `building` varchar(255) DEFAULT NULL,
  `room` varchar(255) DEFAULT NULL,
  `wireless_port` int(11) DEFAULT NULL,
  PRIMARY KEY (`switch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `switch`
--

LOCK TABLES `switch` WRITE;
/*!40000 ALTER TABLE `switch` DISABLE KEYS */;
INSERT INTO `switch` VALUES (1,'of:000078321bdf4000','MISRC','816',NULL),(2,'of:000078321bdf7000','MISRC','816',NULL),(3,'of:000078321bdf4200','MISRC','816',NULL),(4,'of:0000903cb3b16d83','MISRC','816',3);
/*!40000 ALTER TABLE `switch` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) DEFAULT NULL,
  `user_name` varchar(255) NOT NULL,
  PRIMARY KEY (`user_id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `user_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `group` (`group_id`) ON DELETE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,1,'cctseng'),(2,3,'stan'),(3,2,'jeremy'),(4,4,'guest');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-06-28 17:11:53
