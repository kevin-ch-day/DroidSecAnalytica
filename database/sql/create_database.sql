CREATE TABLE `android_malware_hashes` (
  `id` int NOT NULL,
  `malware_name_1` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `malware_name_2` varchar(250) DEFAULT NULL,
  `md5` varchar(250) DEFAULT NULL,
  `sha1` varchar(250) DEFAULT NULL,
  `sha256` varchar(250) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `month` varchar(100) DEFAULT NULL,
  `year` varchar(10) DEFAULT NULL,
  `no_virustotal_match` tinyint(1) DEFAULT NULL
);

CREATE TABLE `android_permissions` (
  `permission_id` int NOT NULL,
  `permission_name` varchar(255) NOT NULL,
  `description` text,
  `protection_level` varchar(100) DEFAULT NULL,
  `added_in_api_level` int DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `permission_group` varchar(100) DEFAULT NULL,
  `default_status` enum('granted','denied','prompt') DEFAULT 'prompt',
  `risk_level` enum('low','medium','high') DEFAULT 'low',
  `required_by_default` tinyint(1) DEFAULT '0'
);

CREATE TABLE `apk_samples` (
  `sample_id` int NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_size` bigint DEFAULT NULL,
  `md5` varchar(32) DEFAULT NULL,
  `sha1` varchar(40) DEFAULT NULL,
  `sha256` varchar(64) DEFAULT NULL,
  `source` varchar(100) DEFAULT NULL
);

CREATE TABLE `hybrid_analysis` (
  `sample_id` int NOT NULL,
  `HybridAnalysis_Label` varchar(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `HybridAnalysis_AV_Detection` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Entropy` double DEFAULT NULL,
  `threat_score` int DEFAULT NULL,
  `verdict` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `file_type` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `analysis_date` date DEFAULT NULL,
  `number_of_indicators` int DEFAULT NULL,
  `file_size` bigint DEFAULT NULL
);

CREATE TABLE `mobfs_analysis` (
  `sample_id` int NOT NULL,
  `security_score` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `trackers_detections` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `grade` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `high_risks` int DEFAULT NULL,
  `medium_risks` int DEFAULT NULL,
  `low_risks` int DEFAULT NULL,
  `info` int DEFAULT NULL,
  `secure` int DEFAULT NULL,
  `hotspot` int DEFAULT NULL,
  `code_issues` int DEFAULT NULL,
  `manifest_issues` int DEFAULT NULL,
  `network_security_issues` int DEFAULT NULL,
  `data_storage_issues` int DEFAULT NULL
);

CREATE TABLE `users` (
  `user_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_admin` tinyint(1) DEFAULT '0',
  `account_disabled` tinyint(1) DEFAULT '0',
  `account_creation_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL
);

CREATE TABLE `virustotal_analysis` (
  `analysis_id` int NOT NULL,
  `sample_id` int DEFAULT NULL,
  `total_scans` int DEFAULT NULL,
  `positive_scans` int DEFAULT NULL,
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
);

--
-- Indexes for tables
--

ALTER TABLE `android_malware_hashes`
  ADD PRIMARY KEY (`id`);
 
ALTER TABLE `android_permissions`
  ADD PRIMARY KEY (`permission_id`),
  ADD UNIQUE KEY `permission_name` (`permission_name`);

ALTER TABLE `apk_samples`
  ADD PRIMARY KEY (`sample_id`);

ALTER TABLE `mobfs_analysis`
  ADD KEY `sample_id` (`sample_id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`);

ALTER TABLE `virustotal_analysis`
  ADD PRIMARY KEY (`analysis_id`),
  ADD KEY `sample_id` (`sample_id`);

--
-- AUTO_INCREMENT for dumped tables
--

ALTER TABLE `android_malware_hashes`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=0;

--
-- AUTO_INCREMENT for table `android_permissions`
--
ALTER TABLE `android_permissions`
  MODIFY `permission_id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=0;

--
-- AUTO_INCREMENT for table `apk_samples`
--
ALTER TABLE `apk_samples`
  MODIFY `sample_id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=0;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `virustotal_analysis`
--
ALTER TABLE `virustotal_analysis`
  MODIFY `analysis_id` int NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

ALTER TABLE `mobfs_analysis`
  ADD CONSTRAINT `mobfs_analysis_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `apk_samples` (`sample_id`);

ALTER TABLE `virustotal_analysis`
  ADD CONSTRAINT `virustotal_analysis_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `apk_samples` (`sample_id`);
COMMIT;
