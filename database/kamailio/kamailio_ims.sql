/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.6.23-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: pcscf
-- ------------------------------------------------------
-- Server version	10.6.23-MariaDB-0ubuntu0.22.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `pcscf`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `pcscf` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

USE `pcscf`;

--
-- Table structure for table `dialog_in`
--

DROP TABLE IF EXISTS `dialog_in`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_in` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `hash_entry` int(10) unsigned NOT NULL,
  `hash_id` int(10) unsigned NOT NULL,
  `did` varchar(45) NOT NULL,
  `callid` varchar(255) NOT NULL,
  `from_uri` varchar(128) NOT NULL,
  `from_tag` varchar(64) NOT NULL,
  `caller_original_cseq` varchar(20) NOT NULL,
  `req_uri` varchar(128) NOT NULL,
  `caller_route_set` varchar(512) DEFAULT NULL,
  `caller_contact` varchar(128) NOT NULL,
  `caller_sock` varchar(64) NOT NULL,
  `state` int(10) unsigned NOT NULL,
  `start_time` int(10) unsigned NOT NULL,
  `timeout` int(10) unsigned NOT NULL DEFAULT 0,
  `sflags` int(10) unsigned NOT NULL DEFAULT 0,
  `toroute_name` varchar(32) DEFAULT NULL,
  `toroute_index` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `hash_idx` (`hash_entry`,`hash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_in`
--

LOCK TABLES `dialog_in` WRITE;
/*!40000 ALTER TABLE `dialog_in` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_in` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dialog_out`
--

DROP TABLE IF EXISTS `dialog_out`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_out` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hash_entry` int(11) NOT NULL,
  `hash_id` int(11) NOT NULL,
  `did` varchar(45) NOT NULL,
  `to_uri` varchar(128) NOT NULL,
  `to_tag` varchar(64) NOT NULL,
  `caller_cseq` varchar(20) NOT NULL,
  `callee_cseq` varchar(20) NOT NULL,
  `callee_contact` varchar(128) NOT NULL,
  `callee_route_set` varchar(512) DEFAULT NULL,
  `callee_sock` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_out`
--

LOCK TABLES `dialog_out` WRITE;
/*!40000 ALTER TABLE `dialog_out` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_out` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dialog_vars`
--

DROP TABLE IF EXISTS `dialog_vars`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_vars` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `hash_entry` int(10) unsigned NOT NULL,
  `hash_id` int(10) unsigned NOT NULL,
  `dialog_key` varchar(128) NOT NULL,
  `dialog_value` varchar(512) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `hash_idx` (`hash_entry`,`hash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_vars`
--

LOCK TABLES `dialog_vars` WRITE;
/*!40000 ALTER TABLE `dialog_vars` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_vars` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `location`
--

DROP TABLE IF EXISTS `location`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `location` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(64) NOT NULL,
  `aor` varchar(255) NOT NULL,
  `host` varchar(100) NOT NULL,
  `port` int(10) NOT NULL,
  `received` varchar(128) DEFAULT NULL,
  `received_port` int(10) unsigned DEFAULT NULL,
  `received_proto` int(10) unsigned DEFAULT NULL,
  `path` varchar(512) DEFAULT NULL,
  `rinstance` varchar(255) DEFAULT NULL,
  `rx_session_id` varchar(256) DEFAULT NULL,
  `reg_state` tinyint(4) DEFAULT NULL,
  `expires` datetime DEFAULT '2030-05-28 21:32:15',
  `service_routes` varchar(2048) DEFAULT NULL,
  `socket` varchar(64) DEFAULT NULL,
  `public_ids` varchar(2048) DEFAULT NULL,
  `security_type` int(11) DEFAULT NULL,
  `protocol` char(5) DEFAULT NULL,
  `mode` char(10) DEFAULT NULL,
  `ck` varchar(100) DEFAULT NULL,
  `ik` varchar(100) DEFAULT NULL,
  `ealg` char(20) DEFAULT NULL,
  `ialg` char(20) DEFAULT NULL,
  `port_pc` int(11) unsigned DEFAULT NULL,
  `port_ps` int(11) unsigned DEFAULT NULL,
  `port_uc` int(11) unsigned DEFAULT NULL,
  `port_us` int(11) unsigned DEFAULT NULL,
  `spi_pc` int(11) unsigned DEFAULT NULL,
  `spi_ps` int(11) unsigned DEFAULT NULL,
  `spi_uc` int(11) unsigned DEFAULT NULL,
  `spi_us` int(11) unsigned DEFAULT NULL,
  `t_security_type` int(11) DEFAULT NULL,
  `t_port_pc` int(11) unsigned DEFAULT NULL,
  `t_port_ps` int(11) unsigned DEFAULT NULL,
  `t_port_uc` int(11) unsigned DEFAULT NULL,
  `t_port_us` int(11) unsigned DEFAULT NULL,
  `t_spi_pc` int(11) unsigned DEFAULT NULL,
  `t_spi_ps` int(11) unsigned DEFAULT NULL,
  `t_spi_uc` int(11) unsigned DEFAULT NULL,
  `t_spi_us` int(11) unsigned DEFAULT NULL,
  `t_protocol` char(5) DEFAULT NULL,
  `t_mode` char(10) DEFAULT NULL,
  `t_ck` varchar(100) DEFAULT NULL,
  `t_ik` varchar(100) DEFAULT NULL,
  `t_ealg` char(20) DEFAULT NULL,
  `t_ialg` char(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `aor` (`aor`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `location`
--

LOCK TABLES `location` WRITE;
/*!40000 ALTER TABLE `location` DISABLE KEYS */;
INSERT INTO `location` VALUES (28,'location','sip:001010000000001@10.46.0.100:5060;transport=udp','10.46.0.100',5060,'10.46.0.100',5060,1,NULL,NULL,NULL,0,'2026-03-28 01:52:41','',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,40003,50000,5060,5060,106,107,10001,20001,'esp','trans','c691cbd22509ab13efe8d68e8c77d411','0dea0849dce6ff6df3b0ad2ef03a8310','','');
/*!40000 ALTER TABLE `location` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `version`
--

DROP TABLE IF EXISTS `version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `version` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `table_name` varchar(32) NOT NULL,
  `table_version` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `table_name_idx` (`table_name`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `version`
--

LOCK TABLES `version` WRITE;
/*!40000 ALTER TABLE `version` DISABLE KEYS */;
INSERT INTO `version` VALUES (1,'version',1),(2,'dialog_in',7),(3,'dialog_out',7),(4,'dialog_vars',7),(5,'location',7);
/*!40000 ALTER TABLE `version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Current Database: `icscf`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `icscf` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

USE `icscf`;

--
-- Table structure for table `nds_trusted_domains`
--

DROP TABLE IF EXISTS `nds_trusted_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `nds_trusted_domains` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `trusted_domain` varchar(83) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nds_trusted_domains`
--

LOCK TABLES `nds_trusted_domains` WRITE;
/*!40000 ALTER TABLE `nds_trusted_domains` DISABLE KEYS */;
INSERT INTO `nds_trusted_domains` VALUES (1,'localdomain');
/*!40000 ALTER TABLE `nds_trusted_domains` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `s_cscf`
--

DROP TABLE IF EXISTS `s_cscf`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `s_cscf` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(83) NOT NULL DEFAULT '',
  `s_cscf_uri` varchar(83) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `s_cscf`
--

LOCK TABLES `s_cscf` WRITE;
/*!40000 ALTER TABLE `s_cscf` DISABLE KEYS */;
INSERT INTO `s_cscf` VALUES (1,'scscf1','sip:scscf.localdomain:5062');
/*!40000 ALTER TABLE `s_cscf` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `s_cscf_capabilities`
--

DROP TABLE IF EXISTS `s_cscf_capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `s_cscf_capabilities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `id_s_cscf` int(11) NOT NULL DEFAULT 0,
  `capability` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_capability` (`capability`),
  KEY `idx_id_s_cscf` (`id_s_cscf`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `s_cscf_capabilities`
--

LOCK TABLES `s_cscf_capabilities` WRITE;
/*!40000 ALTER TABLE `s_cscf_capabilities` DISABLE KEYS */;
/*!40000 ALTER TABLE `s_cscf_capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `version`
--

DROP TABLE IF EXISTS `version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `version` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `table_name` varchar(32) NOT NULL,
  `table_version` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `table_name_idx` (`table_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `version`
--

LOCK TABLES `version` WRITE;
/*!40000 ALTER TABLE `version` DISABLE KEYS */;
INSERT INTO `version` VALUES (1,'version',1);
/*!40000 ALTER TABLE `version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Current Database: `scscf`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `scscf` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

USE `scscf`;

--
-- Table structure for table `active_watchers`
--

DROP TABLE IF EXISTS `active_watchers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `active_watchers` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `presentity_uri` varchar(255) NOT NULL,
  `watcher_username` varchar(64) NOT NULL,
  `watcher_domain` varchar(64) NOT NULL,
  `to_user` varchar(64) NOT NULL,
  `to_domain` varchar(64) NOT NULL,
  `event` varchar(64) NOT NULL DEFAULT 'presence',
  `event_id` varchar(64) DEFAULT NULL,
  `to_tag` varchar(128) NOT NULL,
  `from_tag` varchar(128) NOT NULL,
  `callid` varchar(255) NOT NULL,
  `local_cseq` int(11) NOT NULL,
  `remote_cseq` int(11) NOT NULL,
  `contact` varchar(255) NOT NULL,
  `record_route` text DEFAULT NULL,
  `expires` int(11) NOT NULL,
  `status` int(11) NOT NULL DEFAULT 2,
  `reason` varchar(64) DEFAULT NULL,
  `version` int(11) NOT NULL DEFAULT 0,
  `socket_info` varchar(64) NOT NULL,
  `local_contact` varchar(255) NOT NULL,
  `from_user` varchar(64) NOT NULL,
  `from_domain` varchar(64) NOT NULL,
  `updated` int(11) NOT NULL,
  `updated_winfo` int(11) NOT NULL,
  `flags` int(11) NOT NULL DEFAULT 0,
  `user_agent` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `active_watchers_idx` (`callid`,`to_tag`,`from_tag`),
  KEY `active_watchers_expires` (`expires`),
  KEY `active_watchers_pres` (`presentity_uri`,`event`),
  KEY `updated_idx` (`updated`),
  KEY `updated_winfo_idx` (`updated_winfo`,`presentity_uri`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `active_watchers`
--

LOCK TABLES `active_watchers` WRITE;
/*!40000 ALTER TABLE `active_watchers` DISABLE KEYS */;
/*!40000 ALTER TABLE `active_watchers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `contact`
--

DROP TABLE IF EXISTS `contact`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `contact` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `contact` char(255) NOT NULL,
  `params` varchar(255) DEFAULT NULL,
  `path` varchar(255) DEFAULT NULL,
  `received` varchar(255) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `callid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `contact` (`contact`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `contact`
--

LOCK TABLES `contact` WRITE;
/*!40000 ALTER TABLE `contact` DISABLE KEYS */;
/*!40000 ALTER TABLE `contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dialog_in`
--

DROP TABLE IF EXISTS `dialog_in`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_in` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `hash_entry` int(10) unsigned NOT NULL,
  `hash_id` int(10) unsigned NOT NULL,
  `did` varchar(45) NOT NULL,
  `callid` varchar(255) NOT NULL,
  `from_uri` varchar(128) NOT NULL,
  `from_tag` varchar(64) NOT NULL,
  `caller_original_cseq` varchar(20) NOT NULL,
  `req_uri` varchar(128) NOT NULL,
  `caller_route_set` varchar(512) DEFAULT NULL,
  `caller_contact` varchar(128) NOT NULL,
  `caller_sock` varchar(64) NOT NULL,
  `state` int(10) unsigned NOT NULL,
  `start_time` int(10) unsigned NOT NULL,
  `timeout` int(10) unsigned NOT NULL DEFAULT 0,
  `sflags` int(10) unsigned NOT NULL DEFAULT 0,
  `toroute_name` varchar(32) DEFAULT NULL,
  `toroute_index` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `hash_idx` (`hash_entry`,`hash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_in`
--

LOCK TABLES `dialog_in` WRITE;
/*!40000 ALTER TABLE `dialog_in` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_in` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dialog_out`
--

DROP TABLE IF EXISTS `dialog_out`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_out` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hash_entry` int(11) NOT NULL,
  `hash_id` int(11) NOT NULL,
  `did` varchar(45) NOT NULL,
  `to_uri` varchar(128) NOT NULL,
  `to_tag` varchar(64) NOT NULL,
  `caller_cseq` varchar(20) NOT NULL,
  `callee_cseq` varchar(20) NOT NULL,
  `callee_contact` varchar(128) NOT NULL,
  `callee_route_set` varchar(512) DEFAULT NULL,
  `callee_sock` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_out`
--

LOCK TABLES `dialog_out` WRITE;
/*!40000 ALTER TABLE `dialog_out` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_out` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dialog_vars`
--

DROP TABLE IF EXISTS `dialog_vars`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dialog_vars` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `hash_entry` int(10) unsigned NOT NULL,
  `hash_id` int(10) unsigned NOT NULL,
  `dialog_key` varchar(128) NOT NULL,
  `dialog_value` varchar(512) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `hash_idx` (`hash_entry`,`hash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dialog_vars`
--

LOCK TABLES `dialog_vars` WRITE;
/*!40000 ALTER TABLE `dialog_vars` DISABLE KEYS */;
/*!40000 ALTER TABLE `dialog_vars` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `impu`
--

DROP TABLE IF EXISTS `impu`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `impu` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `impu` char(64) NOT NULL,
  `barring` int(1) DEFAULT 0,
  `reg_state` int(11) DEFAULT 0,
  `ccf1` char(64) DEFAULT NULL,
  `ccf2` char(64) DEFAULT NULL,
  `ecf1` char(64) DEFAULT NULL,
  `ecf2` char(64) DEFAULT NULL,
  `ims_subscription_data` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `impu` (`impu`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `impu`
--

LOCK TABLES `impu` WRITE;
/*!40000 ALTER TABLE `impu` DISABLE KEYS */;
/*!40000 ALTER TABLE `impu` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `impu_contact`
--

DROP TABLE IF EXISTS `impu_contact`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `impu_contact` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `impu_id` int(11) NOT NULL,
  `contact_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `impu_id` (`impu_id`,`contact_id`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `impu_contact`
--

LOCK TABLES `impu_contact` WRITE;
/*!40000 ALTER TABLE `impu_contact` DISABLE KEYS */;
/*!40000 ALTER TABLE `impu_contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `impu_subscriber`
--

DROP TABLE IF EXISTS `impu_subscriber`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `impu_subscriber` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `impu_id` int(11) NOT NULL,
  `subscriber_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `impu_id` (`impu_id`,`subscriber_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `impu_subscriber`
--

LOCK TABLES `impu_subscriber` WRITE;
/*!40000 ALTER TABLE `impu_subscriber` DISABLE KEYS */;
/*!40000 ALTER TABLE `impu_subscriber` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `presentity`
--

DROP TABLE IF EXISTS `presentity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `presentity` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `domain` varchar(64) NOT NULL,
  `event` varchar(64) NOT NULL,
  `etag` varchar(128) NOT NULL,
  `expires` int(11) NOT NULL,
  `received_time` int(11) NOT NULL,
  `body` blob NOT NULL,
  `sender` varchar(255) NOT NULL,
  `priority` int(11) NOT NULL DEFAULT 0,
  `ruid` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `presentity_idx` (`username`,`domain`,`event`,`etag`),
  UNIQUE KEY `ruid_idx` (`ruid`),
  KEY `presentity_expires` (`expires`),
  KEY `account_idx` (`username`,`domain`,`event`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `presentity`
--

LOCK TABLES `presentity` WRITE;
/*!40000 ALTER TABLE `presentity` DISABLE KEYS */;
/*!40000 ALTER TABLE `presentity` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pua`
--

DROP TABLE IF EXISTS `pua`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pua` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `pres_uri` varchar(255) NOT NULL,
  `pres_id` varchar(255) NOT NULL,
  `event` int(11) NOT NULL,
  `expires` int(11) NOT NULL,
  `desired_expires` int(11) NOT NULL,
  `flag` int(11) NOT NULL,
  `etag` varchar(128) NOT NULL,
  `tuple_id` varchar(64) DEFAULT NULL,
  `watcher_uri` varchar(255) NOT NULL,
  `call_id` varchar(255) NOT NULL,
  `to_tag` varchar(128) NOT NULL,
  `from_tag` varchar(128) NOT NULL,
  `cseq` int(11) NOT NULL,
  `record_route` text DEFAULT NULL,
  `contact` varchar(255) NOT NULL,
  `remote_contact` varchar(255) NOT NULL,
  `version` int(11) NOT NULL,
  `extra_headers` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `pua_idx` (`etag`,`tuple_id`,`call_id`,`from_tag`),
  KEY `expires_idx` (`expires`),
  KEY `dialog1_idx` (`pres_id`,`pres_uri`),
  KEY `dialog2_idx` (`call_id`,`from_tag`),
  KEY `record_idx` (`pres_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pua`
--

LOCK TABLES `pua` WRITE;
/*!40000 ALTER TABLE `pua` DISABLE KEYS */;
/*!40000 ALTER TABLE `pua` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `subscriber`
--

DROP TABLE IF EXISTS `subscriber`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `subscriber` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `watcher_uri` varchar(100) NOT NULL,
  `watcher_contact` varchar(100) NOT NULL,
  `presentity_uri` varchar(100) NOT NULL,
  `event` int(11) NOT NULL,
  `expires` datetime NOT NULL,
  `version` int(11) NOT NULL,
  `local_cseq` int(11) NOT NULL,
  `call_id` varchar(50) NOT NULL,
  `from_tag` varchar(50) NOT NULL,
  `to_tag` varchar(50) NOT NULL,
  `record_route` varchar(50) NOT NULL,
  `sockinfo_str` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `watcher_uri` (`event`,`watcher_contact`,`presentity_uri`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `subscriber`
--

LOCK TABLES `subscriber` WRITE;
/*!40000 ALTER TABLE `subscriber` DISABLE KEYS */;
/*!40000 ALTER TABLE `subscriber` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `version`
--

DROP TABLE IF EXISTS `version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `version` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `table_name` varchar(32) NOT NULL,
  `table_version` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `table_name_idx` (`table_name`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `version`
--

LOCK TABLES `version` WRITE;
/*!40000 ALTER TABLE `version` DISABLE KEYS */;
INSERT INTO `version` VALUES (1,'version',1),(2,'dialog_in',7),(3,'dialog_out',7),(4,'dialog_vars',7),(5,'contact',6),(6,'impu',6),(7,'impu_contact',6),(8,'subscriber',6),(9,'impu_subscriber',6),(10,'presentity',5),(11,'active_watchers',12),(12,'watchers',3),(13,'xcap',4),(14,'pua',7);
/*!40000 ALTER TABLE `version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `watchers`
--

DROP TABLE IF EXISTS `watchers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `watchers` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `presentity_uri` varchar(255) NOT NULL,
  `watcher_username` varchar(64) NOT NULL,
  `watcher_domain` varchar(64) NOT NULL,
  `event` varchar(64) NOT NULL DEFAULT 'presence',
  `status` int(11) NOT NULL,
  `reason` varchar(64) DEFAULT NULL,
  `inserted_time` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `watcher_idx` (`presentity_uri`,`watcher_username`,`watcher_domain`,`event`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `watchers`
--

LOCK TABLES `watchers` WRITE;
/*!40000 ALTER TABLE `watchers` DISABLE KEYS */;
/*!40000 ALTER TABLE `watchers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `xcap`
--

DROP TABLE IF EXISTS `xcap`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `xcap` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `domain` varchar(64) NOT NULL,
  `doc` mediumblob NOT NULL,
  `doc_type` int(11) NOT NULL,
  `etag` varchar(128) NOT NULL,
  `source` int(11) NOT NULL,
  `doc_uri` varchar(255) NOT NULL,
  `port` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `doc_uri_idx` (`doc_uri`),
  KEY `account_doc_type_idx` (`username`,`domain`,`doc_type`),
  KEY `account_doc_type_uri_idx` (`username`,`domain`,`doc_type`,`doc_uri`),
  KEY `account_doc_uri_idx` (`username`,`domain`,`doc_uri`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `xcap`
--

LOCK TABLES `xcap` WRITE;
/*!40000 ALTER TABLE `xcap` DISABLE KEYS */;
/*!40000 ALTER TABLE `xcap` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-03-28  2:31:53
