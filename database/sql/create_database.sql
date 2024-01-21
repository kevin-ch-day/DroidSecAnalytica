SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

-- Database: `droidsecanalytica`

-- Table structure for table `android_permissions`
CREATE TABLE `android_permissions` (
  `permission_id` int(11) NOT NULL,
  `permission_name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `protection_level` varchar(100) DEFAULT NULL,
  `added_in_api_level` int(11) DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `permission_group` varchar(100) DEFAULT NULL,
  `default_status` enum('granted','denied','prompt') DEFAULT 'prompt',
  `risk_level` enum('low','medium','high') DEFAULT 'low',
  `required_by_default` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `apk_samples`
CREATE TABLE `apk_samples` (
  `sample_id` int(11) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_size` bigint(20) DEFAULT NULL,
  `md5` varchar(32) DEFAULT NULL,
  `sha1` varchar(40) DEFAULT NULL,
  `sha256` varchar(64) DEFAULT NULL,
  `source` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `droidsec_users`
CREATE TABLE `droidsec_users` (
  `user_id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_admin` tinyint(1) DEFAULT 0,
  `account_disabled` tinyint(1) DEFAULT 0,
  `account_creation_date` timestamp NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Table structure for table `hybrid_analysis`
CREATE TABLE `hybrid_analysis` (
  `sample_id` int(11) NOT NULL,
  `HybridAnalysis_Label` varchar(80) DEFAULT NULL,
  `HybridAnalysis_AV_Detection` varchar(20) DEFAULT NULL,
  `Entropy` double DEFAULT NULL,
  `threat_score` int(11) DEFAULT NULL,
  `verdict` varchar(50) DEFAULT NULL,
  `file_type` varchar(50) DEFAULT NULL,
  `analysis_date` date DEFAULT NULL,
  `number_of_indicators` int(11) DEFAULT NULL,
  `file_size` bigint(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `malware_hashes`
CREATE TABLE `malware_hashes` (
  `id` int(11) NOT NULL,
  `name_1` varchar(255) DEFAULT NULL,
  `name_2` varchar(250) DEFAULT NULL,
  `md5` varchar(250) DEFAULT NULL,
  `sha1` varchar(250) DEFAULT NULL,
  `sha256` varchar(250) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `month` varchar(100) DEFAULT NULL,
  `year` varchar(10) DEFAULT NULL,
  `no_virustotal_match` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `mobfs_analysis`
CREATE TABLE `mobfs_analysis` (
  `sample_id` int(11) NOT NULL,
  `security_score` varchar(20) DEFAULT NULL,
  `trackers_detections` varchar(50) DEFAULT NULL,
  `grade` varchar(10) DEFAULT NULL,
  `high_risks` int(11) DEFAULT NULL,
  `medium_risks` int(11) DEFAULT NULL,
  `low_risks` int(11) DEFAULT NULL,
  `info` int(11) DEFAULT NULL,
  `secure` int(11) DEFAULT NULL,
  `hotspot` int(11) DEFAULT NULL,
  `code_issues` int(11) DEFAULT NULL,
  `manifest_issues` int(11) DEFAULT NULL,
  `network_security_issues` int(11) DEFAULT NULL,
  `data_storage_issues` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Table structure for table `vt_activities`
CREATE TABLE `vt_activities` (
  `ActivityID` int(11) NOT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_applications`
CREATE TABLE `vt_applications` (
  `AppID` int(11) NOT NULL,
  `PackageName` varchar(255) DEFAULT NULL,
  `MainActivity` varchar(255) DEFAULT NULL,
  `TargetSdkVersion` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_certificates`
CREATE TABLE `vt_certificates` (
  `CertificateID` int(11) NOT NULL,
  `Subject` text DEFAULT NULL,
  `Issuer` text DEFAULT NULL,
  `ValidFrom` date DEFAULT NULL,
  `ValidTo` date DEFAULT NULL,
  `Thumbprint` varchar(255) DEFAULT NULL,
  `SerialNumber` varchar(255) DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_intent_filters`
CREATE TABLE `vt_intent_filters` (
  `FilterID` int(11) NOT NULL,
  `Type` varchar(50) DEFAULT NULL,
  `TypeID` int(11) DEFAULT NULL,
  `Action` varchar(255) DEFAULT NULL,
  `Category` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_libraries`
CREATE TABLE `vt_libraries` (
  `LibraryID` int(11) NOT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_permissions`
CREATE TABLE `vt_permissions` (
  `PermissionID` int(11) NOT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `Description` text DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_receivers`
CREATE TABLE `vt_receivers` (
  `ReceiverID` int(11) NOT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_scan_analysis`
CREATE TABLE `vt_scan_analysis` (
  `analysis_id` int(11) NOT NULL,
  `sample_id` int(11) DEFAULT NULL,
  `total_scans` int(11) DEFAULT NULL,
  `positive_scans` int(11) DEFAULT NULL,
  `report_link` varchar(255) DEFAULT NULL,
  `APEX` varchar(200) DEFAULT NULL,
  `AVG` varchar(200) DEFAULT NULL,
  `Acronis` varchar(200) DEFAULT NULL,
  `AhnLab_V3` varchar(200) DEFAULT NULL,
  `Alibaba` varchar(200) DEFAULT NULL,
  `Antiy_AVL` varchar(200) DEFAULT NULL,
  `Arcabit` varchar(200) DEFAULT NULL,
  `Avast` varchar(200) DEFAULT NULL,
  `Avast_Mobile` varchar(200) DEFAULT NULL,
  `Avira` varchar(200) DEFAULT NULL,
  `Baidu` varchar(200) DEFAULT NULL,
  `BitDefender` varchar(200) DEFAULT NULL,
  `BitDefenderFalx` varchar(200) DEFAULT NULL,
  `BitDefenderTheta` varchar(200) DEFAULT NULL,
  `Bkav` varchar(200) DEFAULT NULL,
  `CAT_QuickHeal` varchar(200) DEFAULT NULL,
  `CMC` varchar(200) DEFAULT NULL,
  `ClamAV` varchar(200) DEFAULT NULL,
  `CrowdStrike` varchar(200) DEFAULT NULL,
  `Cybereason` varchar(200) DEFAULT NULL,
  `Cylance` varchar(200) DEFAULT NULL,
  `Cynet` varchar(200) DEFAULT NULL,
  `DeepInstinct` varchar(200) DEFAULT NULL,
  `DrWeb` varchar(200) DEFAULT NULL,
  `ESET_NOD32` varchar(200) DEFAULT NULL,
  `Elastic` varchar(200) DEFAULT NULL,
  `Emsisoft` varchar(200) DEFAULT NULL,
  `F_Secure` varchar(200) DEFAULT NULL,
  `Fortinet` varchar(200) DEFAULT NULL,
  `GData` varchar(200) DEFAULT NULL,
  `Google` varchar(200) DEFAULT NULL,
  `Gridinsoft` varchar(200) DEFAULT NULL,
  `Ikarus` varchar(200) DEFAULT NULL,
  `Jiangmin` varchar(200) DEFAULT NULL,
  `K7AntiVirus` varchar(200) DEFAULT NULL,
  `K7GW` varchar(200) DEFAULT NULL,
  `Kaspersky` varchar(200) DEFAULT NULL,
  `Kingsoft` varchar(200) DEFAULT NULL,
  `Lionic` varchar(200) DEFAULT NULL,
  `MAX` varchar(200) DEFAULT NULL,
  `Malwarebytes` varchar(200) DEFAULT NULL,
  `MaxSecure` varchar(200) DEFAULT NULL,
  `McAfee` varchar(200) DEFAULT NULL,
  `MicroWorld_eScan` varchar(200) DEFAULT NULL,
  `Microsoft` varchar(200) DEFAULT NULL,
  `NANO_Antivirus` varchar(200) DEFAULT NULL,
  `Paloalto` varchar(200) DEFAULT NULL,
  `Panda` varchar(200) DEFAULT NULL,
  `Rising` varchar(200) DEFAULT NULL,
  `SUPERAntiSpyware` varchar(200) DEFAULT NULL,
  `Sangfor` varchar(200) DEFAULT NULL,
  `SentinelOne` varchar(200) DEFAULT NULL,
  `Skyhigh` varchar(200) DEFAULT NULL,
  `Sophos` varchar(200) DEFAULT NULL,
  `Symantec` varchar(200) DEFAULT NULL,
  `SymantecMobileInsight` varchar(200) DEFAULT NULL,
  `TACHYON` varchar(200) DEFAULT NULL,
  `Tencent` varchar(200) DEFAULT NULL,
  `TrendMicro` varchar(200) DEFAULT NULL,
  `TrendMicro_HouseCall` varchar(200) DEFAULT NULL,
  `Trustlook` varchar(200) DEFAULT NULL,
  `VIPRE` varchar(200) DEFAULT NULL,
  `Varist` varchar(200) DEFAULT NULL,
  `ViRobot` varchar(200) DEFAULT NULL,
  `VirIT` varchar(200) DEFAULT NULL,
  `Webroot` varchar(200) DEFAULT NULL,
  `Xcitium` varchar(200) DEFAULT NULL,
  `Yandex` varchar(200) DEFAULT NULL,
  `Zillya` varchar(200) DEFAULT NULL,
  `ZoneAlarm` varchar(200) DEFAULT NULL,
  `Zoner` varchar(200) DEFAULT NULL,
  `tehtris` varchar(200) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `vt_services`
CREATE TABLE `vt_services` (
  `ServiceID` int(11) NOT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `AppID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Indexes for table `android_permissions`
ALTER TABLE `android_permissions`
  ADD PRIMARY KEY (`permission_id`),
  ADD UNIQUE KEY `permission_name` (`permission_name`);


-- Indexes for table `apk_samples`
ALTER TABLE `apk_samples`
  ADD PRIMARY KEY (`sample_id`);

-- Indexes for table `droidsec_users`
ALTER TABLE `droidsec_users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`);

-- Indexes for table `malware_hashes`
ALTER TABLE `malware_hashes`
  ADD PRIMARY KEY (`id`);

-- Indexes for table `mobfs_analysis`
ALTER TABLE `mobfs_analysis`
  ADD KEY `sample_id` (`sample_id`);

-- Indexes for table `vt_activities`
ALTER TABLE `vt_activities`
  ADD PRIMARY KEY (`ActivityID`),
  ADD KEY `AppID` (`AppID`);

-- Indexes for table `vt_applications`
ALTER TABLE `vt_applications`
  ADD PRIMARY KEY (`AppID`);

-- Indexes for table `vt_certificates`
ALTER TABLE `vt_certificates`
  ADD PRIMARY KEY (`CertificateID`),
  ADD KEY `AppID` (`AppID`);

-- Indexes for table `vt_intent_filters`
ALTER TABLE `vt_intent_filters`
  ADD PRIMARY KEY (`FilterID`),
  ADD KEY `TypeID` (`TypeID`);

-- Indexes for table `vt_libraries`
ALTER TABLE `vt_libraries`
  ADD PRIMARY KEY (`LibraryID`),
  ADD KEY `AppID` (`AppID`);

-- Indexes for table `vt_permissions`
ALTER TABLE `vt_permissions`
  ADD PRIMARY KEY (`PermissionID`),
  ADD KEY `AppID` (`AppID`);

-- Indexes for table `vt_receivers`
ALTER TABLE `vt_receivers`
  ADD PRIMARY KEY (`ReceiverID`),
  ADD KEY `AppID` (`AppID`);

-- Indexes for table `vt_scan_analysis`
ALTER TABLE `vt_scan_analysis`
  ADD PRIMARY KEY (`analysis_id`),
  ADD KEY `sample_id` (`sample_id`);

-- Indexes for table `vt_services`
ALTER TABLE `vt_services`
  ADD PRIMARY KEY (`ServiceID`),
  ADD KEY `AppID` (`AppID`);


-- AUTO_INCREMENT for table `android_permissions`
ALTER TABLE `android_permissions`
  MODIFY `permission_id` int(11) NOT NULL AUTO_INCREMENT;

-- AUTO_INCREMENT for table `apk_samples`
ALTER TABLE `apk_samples`
  MODIFY `sample_id` int(11) NOT NULL AUTO_INCREMENT;

-- AUTO_INCREMENT for table `droidsec_users`
ALTER TABLE `droidsec_users`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `malware_hashes`
--
ALTER TABLE `malware_hashes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=587;

--
-- AUTO_INCREMENT for table `vt_scan_analysis`
--
ALTER TABLE `vt_scan_analysis`
  MODIFY `analysis_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `mobfs_analysis`
--
ALTER TABLE `mobfs_analysis`
  ADD CONSTRAINT `mobfs_analysis_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `apk_samples` (`sample_id`);

--
-- Constraints for table `vt_activities`
--
ALTER TABLE `vt_activities`
  ADD CONSTRAINT `vt_activities_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);

--
-- Constraints for table `vt_certificates`
--
ALTER TABLE `vt_certificates`
  ADD CONSTRAINT `vt_certificates_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);

--
-- Constraints for table `vt_intent_filters`
--
ALTER TABLE `vt_intent_filters`
  ADD CONSTRAINT `vt_intent_filters_ibfk_1` FOREIGN KEY (`TypeID`) REFERENCES `vt_activities` (`ActivityID`),
  ADD CONSTRAINT `vt_intent_filters_ibfk_2` FOREIGN KEY (`TypeID`) REFERENCES `vt_services` (`ServiceID`),
  ADD CONSTRAINT `vt_intent_filters_ibfk_3` FOREIGN KEY (`TypeID`) REFERENCES `vt_receivers` (`ReceiverID`);

--
-- Constraints for table `vt_libraries`
--
ALTER TABLE `vt_libraries`
  ADD CONSTRAINT `vt_libraries_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);

--
-- Constraints for table `vt_permissions`
--
ALTER TABLE `vt_permissions`
  ADD CONSTRAINT `vt_permissions_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);

--
-- Constraints for table `vt_receivers`
--
ALTER TABLE `vt_receivers`
  ADD CONSTRAINT `vt_receivers_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);

--
-- Constraints for table `vt_scan_analysis`
--
ALTER TABLE `vt_scan_analysis`
  ADD CONSTRAINT `vt_scan_analysis_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `apk_samples` (`sample_id`);

--
-- Constraints for table `vt_services`
--
ALTER TABLE `vt_services`
  ADD CONSTRAINT `vt_services_ibfk_1` FOREIGN KEY (`AppID`) REFERENCES `vt_applications` (`AppID`);
COMMIT;