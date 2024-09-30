--
-- Table structure for table `analysis_metadata`
--

CREATE TABLE `analysis_metadata` (
  `analysis_id` int(11) NOT NULL,
  `analysis_status` enum('Pending','InProgress','Completed','Failed','Paused','Cancelled') DEFAULT NULL,
  `sample_classification` varchar(100) DEFAULT NULL,
  `sha256` varchar(64) DEFAULT NULL,
  `package_name` varchar(255) DEFAULT NULL,
  `main_activity` varchar(255) DEFAULT NULL,
  `target_min_version` int(11) DEFAULT NULL,
  `target_sdk_version` int(11) DEFAULT NULL,
  `receivers` int(11) DEFAULT NULL,
  `activities` int(11) DEFAULT NULL,
  `services` int(11) DEFAULT NULL,
  `providers` int(11) DEFAULT NULL,
  `libraries` int(11) DEFAULT NULL,
  `permissions` int(11) DEFAULT NULL,
  `analysis_timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `sample_type` enum('Hash','Apk') DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_api_calls`
--

CREATE TABLE `android_api_calls` (
  `ApiCallID` int(11) NOT NULL,
  `ApiMethodName` varchar(255) NOT NULL,
  `Description` text DEFAULT NULL,
  `Category` varchar(100) DEFAULT NULL,
  `RiskLevel` varchar(50) DEFAULT NULL,
  `IsMalwareProne` tinyint(1) DEFAULT NULL,
  `CommonUseCases` text DEFAULT NULL,
  `MalwareExploits` text DEFAULT NULL,
  `LastUpdated` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_intent_filters`
--

CREATE TABLE `android_intent_filters` (
  `IntentID` int(11) NOT NULL,
  `IntentName` varchar(255) NOT NULL,
  `Description` text DEFAULT NULL,
  `Category` varchar(255) DEFAULT NULL,
  `RiskLevel` varchar(50) DEFAULT NULL,
  `IsUnusual` tinyint(1) DEFAULT 0,
  `CommonUseCases` text DEFAULT NULL,
  `AssociatedMalwareTypes` text DEFAULT NULL,
  `LastUpdated` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_manufacturer_permissions`
--

CREATE TABLE `android_manufacturer_permissions` (
  `permission_id` int(11) NOT NULL,
  `constant_value` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `note` text DEFAULT NULL,
  `protection_level` varchar(100) DEFAULT NULL,
  `category` int(11) DEFAULT NULL,
  `vendor` varchar(100) DEFAULT NULL,
  `andro_short_desc` varchar(100) DEFAULT NULL,
  `andro_long_desc` text DEFAULT NULL,
  `andro_type` varchar(100) DEFAULT NULL,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_permissions`
--

CREATE TABLE `android_permissions` (
  `permission_id` int(11) NOT NULL,
  `permission_name` varchar(255) NOT NULL,
  `constant_value` varchar(100) DEFAULT NULL,
  `alternatively` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `note` text DEFAULT NULL,
  `protection_level` varchar(100) DEFAULT NULL,
  `added_in_api` int(11) DEFAULT NULL,
  `deprecated_in_api` int(11) DEFAULT NULL,
  `no_longer_supported` tinyint(4) DEFAULT NULL,
  `no_third_party_apps` tinyint(1) DEFAULT NULL,
  `category` int(11) DEFAULT NULL,
  `use_instead` varchar(200) DEFAULT NULL,
  `vendor` varchar(100) DEFAULT NULL,
  `andro_short_desc` varchar(100) DEFAULT NULL,
  `andro_long_desc` text DEFAULT NULL,
  `andro_type` varchar(100) DEFAULT NULL,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_permissions_unknown`
--

CREATE TABLE `android_permissions_unknown` (
  `permission_id` int(11) NOT NULL,
  `constant_value` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `note` text DEFAULT NULL,
  `protection_level` varchar(100) DEFAULT NULL,
  `category` int(11) DEFAULT NULL,
  `andro_short_desc` varchar(100) DEFAULT NULL,
  `andro_long_desc` text DEFAULT NULL,
  `andro_type` varchar(100) DEFAULT NULL,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_permission_categories`
--

CREATE TABLE `android_permission_categories` (
  `category_id` int(11) NOT NULL,
  `category_name` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `risk_level` enum('Low','Medium','High','Critical') DEFAULT 'Low',
  `common_usage` text DEFAULT NULL,
  `potential_misuse` text DEFAULT NULL,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `android_sdk_versions`
--

CREATE TABLE `android_sdk_versions` (
  `id` int(11) NOT NULL,
  `api_level` int(11) NOT NULL,
  `version_number` varchar(10) DEFAULT NULL,
  `version_name` varchar(255) DEFAULT NULL,
  `release_date` date DEFAULT NULL,
  `key_features` text DEFAULT NULL,
  `security_enhancements` text DEFAULT NULL,
  `permission_changes` text DEFAULT NULL,
  `system_changes` text DEFAULT NULL,
  `remarks` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `hash_data_ioc`
--

CREATE TABLE `hash_data_ioc` (
  `id` int(11) NOT NULL,
  `md5` varchar(32) DEFAULT NULL,
  `sha1` varchar(40) DEFAULT NULL,
  `sha256` varchar(64) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `hybrid_analysis`
--

CREATE TABLE `hybrid_analysis` (
  `sample_id` int(11) NOT NULL,
  `Label` varchar(80) DEFAULT NULL,
  `AV_Detection` varchar(20) DEFAULT NULL,
  `Entropy` double DEFAULT NULL,
  `NoResults` tinyint(1) DEFAULT NULL,
  `link` varchar(200) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `malware_project_mapping`
--

CREATE TABLE `malware_project_mapping` (
  `malware_id` int(11) NOT NULL,
  `report_id` int(11) NOT NULL,
  `droidsecanalytica_label` varchar(100) DEFAULT NULL,
  `droidsecanalytica_classification` varchar(500) DEFAULT NULL,
  `family` varchar(50) DEFAULT NULL,
  `md5` varchar(33) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `malware_samples`
--

CREATE TABLE `malware_samples` (
  `id` int(11) NOT NULL,
  `name_1` varchar(255) DEFAULT NULL,
  `name_2` varchar(250) DEFAULT NULL,
  `Type` enum('Dropper','Payload','','') DEFAULT NULL,
  `virustotal_label` varchar(200) DEFAULT NULL,
  `md5` varchar(250) DEFAULT NULL,
  `sha1` varchar(250) DEFAULT NULL,
  `sha256` varchar(250) DEFAULT NULL,
  `sample_size` bigint(20) DEFAULT NULL,
  `formatted_sample_size` varchar(20) DEFAULT NULL,
  `vt_first_seen_wild` date DEFAULT NULL,
  `vt_first_submission` date DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `month` varchar(100) DEFAULT NULL,
  `year` varchar(10) DEFAULT NULL,
  `no_virustotal_data` tinyint(1) DEFAULT NULL,
  `no_vt_androguard_data` tinyint(1) DEFAULT NULL,
  `virustotal_url` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `mobsf_analysis`
--

CREATE TABLE `mobsf_analysis` (
  `apk_id` int(11) NOT NULL,
  `app_name` varchar(250) DEFAULT NULL,
  `security_score` varchar(20) DEFAULT NULL,
  `trackers_detections` varchar(50) DEFAULT NULL,
  `activities` int(11) DEFAULT NULL,
  `services` int(11) DEFAULT NULL,
  `receivers` int(11) DEFAULT NULL,
  `providers` int(11) DEFAULT NULL,
  `grade` varchar(10) DEFAULT NULL,
  `high_risks` int(11) DEFAULT NULL,
  `medium_risks` int(11) DEFAULT NULL,
  `info` int(11) DEFAULT NULL,
  `secure` int(11) DEFAULT NULL,
  `hotspot` int(11) DEFAULT NULL,
  `failed` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
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

-- --------------------------------------------------------

--
-- Table structure for table `vendor_details`
--

CREATE TABLE `vendor_details` (
  `id` int(11) NOT NULL,
  `prefix` varchar(50) DEFAULT NULL,
  `vendor` varchar(100) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `industry` varchar(100) DEFAULT NULL,
  `founded` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_activities`
--

CREATE TABLE `vt_activities` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) NOT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `activity_name` varchar(255) NOT NULL,
  `record_note` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_api_keys`
--

CREATE TABLE `vt_api_keys` (
  `id` int(11) NOT NULL,
  `api_key` varchar(64) NOT NULL,
  `api_type` enum('free','premium') DEFAULT 'free',
  `max_requests_per_day` int(11) NOT NULL DEFAULT 500,
  `current_requests` int(11) DEFAULT 0,
  `last_used` timestamp NULL DEFAULT NULL,
  `last_reset` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_certificates`
--

CREATE TABLE `vt_certificates` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) DEFAULT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `certificate_id` int(11) NOT NULL,
  `subject` text DEFAULT NULL,
  `issuer` text DEFAULT NULL,
  `valid_from` date DEFAULT NULL,
  `valid_to` date DEFAULT NULL,
  `thumbprint` varchar(255) DEFAULT NULL,
  `serial_number` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_intent_filters`
--

CREATE TABLE `vt_intent_filters` (
  `FilterID` int(11) NOT NULL,
  `Type` varchar(50) NOT NULL COMMENT 'Type of the Intent Filter (e.g., Activity, Service, Receiver)',
  `TypeID` int(11) NOT NULL COMMENT 'Reference ID to the specific type',
  `CreatedAt` timestamp NOT NULL DEFAULT current_timestamp(),
  `UpdatedAt` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Stores basic information about Intent Filters';

-- --------------------------------------------------------

--
-- Table structure for table `vt_intent_filters_actions`
--

CREATE TABLE `vt_intent_filters_actions` (
  `ActionID` int(11) NOT NULL,
  `FilterID` int(11) NOT NULL,
  `Action` varchar(255) NOT NULL COMMENT 'Action associated with the Intent Filter'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Stores actions associated with each Intent Filter';

-- --------------------------------------------------------

--
-- Table structure for table `vt_intent_filters_categories`
--

CREATE TABLE `vt_intent_filters_categories` (
  `CategoryID` int(11) NOT NULL,
  `FilterID` int(11) NOT NULL,
  `Category` varchar(255) NOT NULL COMMENT 'Category associated with the Intent Filter'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Stores categories associated with each Intent Filter';

-- --------------------------------------------------------

--
-- Table structure for table `vt_permissions`
--

CREATE TABLE `vt_permissions` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) NOT NULL COMMENT 'Analysis ID',
  `apk_id` int(11) NOT NULL COMMENT 'APK ID',
  `known_permission_id` int(11) DEFAULT NULL COMMENT 'Detected Known \r\nPermission',
  `unknown_permission_id` int(11) DEFAULT NULL COMMENT 'Detected Unknown Permission',
  `manufacturer_permission_id` int(11) DEFAULT NULL COMMENT 'Detected manufacturer permission'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_providers`
--

CREATE TABLE `vt_providers` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) NOT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `provider_name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_receivers`
--

CREATE TABLE `vt_receivers` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) NOT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `receiver_name` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_scan_analysis`
--

CREATE TABLE `vt_scan_analysis` (
  `analysis_id` int(11) NOT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `malicious` int(11) DEFAULT NULL,
  `suspicious` int(11) DEFAULT NULL,
  `undetected` int(11) DEFAULT NULL,
  `harmless` int(11) DEFAULT NULL,
  `timeout` int(11) DEFAULT NULL,
  `confirmed_timeout` int(11) DEFAULT NULL,
  `failure` int(11) DEFAULT NULL,
  `type_unsupported` int(11) DEFAULT NULL,
  `CTX` varchar(100) DEFAULT NULL,
  `huorong` varchar(100) DEFAULT NULL,
  `McAfeeD` varchar(100) DEFAULT NULL,
  `CyrenCloud` varchar(100) DEFAULT NULL,
  `TotalDefense` varchar(100) DEFAULT NULL,
  `Invincea` varchar(100) DEFAULT NULL,
  `Endgame` varchar(100) DEFAULT NULL,
  `alibabacloud` varchar(100) DEFAULT NULL,
  `eGambit` varchar(100) DEFAULT NULL,
  `VBA32` varchar(100) DEFAULT NULL,
  `Trapmine` varchar(100) DEFAULT NULL,
  `ALYac` varchar(100) DEFAULT NULL,
  `Ad_Aware` varchar(100) DEFAULT NULL,
  `APEX` varchar(100) DEFAULT NULL,
  `AVG` varchar(100) DEFAULT NULL,
  `Acronis` varchar(100) DEFAULT NULL,
  `AhnLab_V3` varchar(100) DEFAULT NULL,
  `Alibaba` varchar(100) DEFAULT NULL,
  `Antiy_AVL` varchar(100) DEFAULT NULL,
  `Arcabit` varchar(100) DEFAULT NULL,
  `Avast` varchar(100) DEFAULT NULL,
  `Avast_Mobile` varchar(100) DEFAULT NULL,
  `Avira` varchar(100) DEFAULT NULL,
  `Baidu` varchar(100) DEFAULT NULL,
  `BitDefender` varchar(100) DEFAULT NULL,
  `BitDefenderFalx` varchar(100) DEFAULT NULL,
  `BitDefenderTheta` varchar(100) DEFAULT NULL,
  `Bkav` varchar(100) DEFAULT NULL,
  `CAT_QuickHeal` varchar(100) DEFAULT NULL,
  `CMC` varchar(100) DEFAULT NULL,
  `ClamAV` varchar(100) DEFAULT NULL,
  `Comodo` varchar(100) DEFAULT NULL,
  `CrowdStrike` varchar(100) DEFAULT NULL,
  `Cybereason` varchar(100) DEFAULT NULL,
  `Cylance` varchar(100) DEFAULT NULL,
  `Cynet` varchar(100) DEFAULT NULL,
  `Cyren` varchar(100) DEFAULT NULL,
  `DeepInstinct` varchar(100) DEFAULT NULL,
  `DrWeb` varchar(100) DEFAULT NULL,
  `ESET_NOD32` varchar(100) DEFAULT NULL,
  `Elastic` varchar(100) DEFAULT NULL,
  `Emsisoft` varchar(100) DEFAULT NULL,
  `F_Prot` varchar(100) DEFAULT NULL,
  `F_Secure` varchar(100) DEFAULT NULL,
  `FireEye` varchar(100) DEFAULT NULL,
  `Fortinet` varchar(100) DEFAULT NULL,
  `GData` varchar(100) DEFAULT NULL,
  `Google` varchar(100) DEFAULT NULL,
  `Gridinsoft` varchar(100) DEFAULT NULL,
  `Ikarus` varchar(100) DEFAULT NULL,
  `Jiangmin` varchar(100) DEFAULT NULL,
  `K7AntiVirus` varchar(100) DEFAULT NULL,
  `K7GW` varchar(100) DEFAULT NULL,
  `Kaspersky` varchar(100) DEFAULT NULL,
  `Kaspersky_not_a_virus` tinyint(1) DEFAULT 0,
  `Kingsoft` varchar(100) DEFAULT NULL,
  `Lionic` varchar(100) DEFAULT NULL,
  `MAX` varchar(100) DEFAULT NULL,
  `Malwarebytes` varchar(100) DEFAULT NULL,
  `MaxSecure` varchar(100) DEFAULT NULL,
  `McAfee` varchar(100) DEFAULT NULL,
  `McAfee_GW_Edition` varchar(100) DEFAULT NULL,
  `MicroWorld_eScan` varchar(100) DEFAULT NULL,
  `Microsoft` varchar(100) DEFAULT NULL,
  `NANO_Antivirus` varchar(100) DEFAULT NULL,
  `Paloalto` varchar(100) DEFAULT NULL,
  `Panda` varchar(100) DEFAULT NULL,
  `Qihoo_360` varchar(100) DEFAULT NULL,
  `Rising` varchar(100) DEFAULT NULL,
  `SUPERAntiSpyware` varchar(100) DEFAULT NULL,
  `Sangfor` varchar(100) DEFAULT NULL,
  `SentinelOne` varchar(100) DEFAULT NULL,
  `Skyhigh` varchar(100) DEFAULT NULL,
  `Sophos` varchar(100) DEFAULT NULL,
  `Symantec` varchar(100) DEFAULT NULL,
  `SymantecMobileInsight` varchar(100) DEFAULT NULL,
  `TACHYON` varchar(100) DEFAULT NULL,
  `Tencent` varchar(100) DEFAULT NULL,
  `TrendMicro` varchar(100) DEFAULT NULL,
  `TrendMicro_HouseCall` varchar(100) DEFAULT NULL,
  `Trustlook` varchar(100) DEFAULT NULL,
  `VIPRE` varchar(100) DEFAULT NULL,
  `Varist` varchar(100) DEFAULT NULL,
  `ViRobot` varchar(100) DEFAULT NULL,
  `VirIT` varchar(100) DEFAULT NULL,
  `Webroot` varchar(100) DEFAULT NULL,
  `Xcitium` varchar(100) DEFAULT NULL,
  `Yandex` varchar(100) DEFAULT NULL,
  `Zillya` varchar(100) DEFAULT NULL,
  `ZoneAlarm` varchar(100) DEFAULT NULL,
  `ZoneAlarm_not_a_virus` tinyint(1) DEFAULT 0,
  `Zoner` varchar(100) DEFAULT NULL,
  `tehtris` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `vt_services`
--

CREATE TABLE `vt_services` (
  `record_id` int(11) NOT NULL,
  `analysis_id` int(11) NOT NULL,
  `apk_id` int(11) DEFAULT NULL,
  `service_name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `analysis_metadata`
--
ALTER TABLE `analysis_metadata`
  ADD PRIMARY KEY (`analysis_id`);

--
-- Indexes for table `android_api_calls`
--
ALTER TABLE `android_api_calls`
  ADD PRIMARY KEY (`ApiCallID`),
  ADD UNIQUE KEY `ApiMethodName` (`ApiMethodName`);

--
-- Indexes for table `android_intent_filters`
--
ALTER TABLE `android_intent_filters`
  ADD PRIMARY KEY (`IntentID`),
  ADD UNIQUE KEY `IntentName` (`IntentName`);

--
-- Indexes for table `android_manufacturer_permissions`
--
ALTER TABLE `android_manufacturer_permissions`
  ADD PRIMARY KEY (`permission_id`,`constant_value`);

--
-- Indexes for table `android_permissions`
--
ALTER TABLE `android_permissions`
  ADD PRIMARY KEY (`permission_id`);

--
-- Indexes for table `android_permissions_unknown`
--
ALTER TABLE `android_permissions_unknown`
  ADD PRIMARY KEY (`permission_id`);

--
-- Indexes for table `android_permission_categories`
--
ALTER TABLE `android_permission_categories`
  ADD PRIMARY KEY (`category_id`),
  ADD UNIQUE KEY `category_name` (`category_name`);

--
-- Indexes for table `android_sdk_versions`
--
ALTER TABLE `android_sdk_versions`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `hash_data_ioc`
--
ALTER TABLE `hash_data_ioc`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `hybrid_analysis`
--
ALTER TABLE `hybrid_analysis`
  ADD PRIMARY KEY (`sample_id`);

--
-- Indexes for table `malware_project_mapping`
--
ALTER TABLE `malware_project_mapping`
  ADD PRIMARY KEY (`report_id`),
  ADD UNIQUE KEY `malware_id` (`malware_id`);

--
-- Indexes for table `malware_samples`
--
ALTER TABLE `malware_samples`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mobsf_analysis`
--
ALTER TABLE `mobsf_analysis`
  ADD PRIMARY KEY (`apk_id`),
  ADD KEY `sample_id` (`apk_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `vendor_details`
--
ALTER TABLE `vendor_details`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `vt_activities`
--
ALTER TABLE `vt_activities`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `vt_api_keys`
--
ALTER TABLE `vt_api_keys`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `vt_certificates`
--
ALTER TABLE `vt_certificates`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `vt_intent_filters`
--
ALTER TABLE `vt_intent_filters`
  ADD PRIMARY KEY (`FilterID`),
  ADD KEY `idx_type` (`Type`);

--
-- Indexes for table `vt_intent_filters_actions`
--
ALTER TABLE `vt_intent_filters_actions`
  ADD PRIMARY KEY (`ActionID`),
  ADD KEY `idx_filter_action` (`FilterID`,`Action`);

--
-- Indexes for table `vt_intent_filters_categories`
--
ALTER TABLE `vt_intent_filters_categories`
  ADD PRIMARY KEY (`CategoryID`),
  ADD KEY `idx_filter_category` (`FilterID`,`Category`);

--
-- Indexes for table `vt_permissions`
--
ALTER TABLE `vt_permissions`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `vt_providers`
--
ALTER TABLE `vt_providers`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `vt_receivers`
--
ALTER TABLE `vt_receivers`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `vt_scan_analysis`
--
ALTER TABLE `vt_scan_analysis`
  ADD PRIMARY KEY (`analysis_id`);

--
-- Indexes for table `vt_services`
--
ALTER TABLE `vt_services`
  ADD PRIMARY KEY (`record_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `android_api_calls`
--
ALTER TABLE `android_api_calls`
  MODIFY `ApiCallID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `android_intent_filters`
--
ALTER TABLE `android_intent_filters`
  MODIFY `IntentID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `android_manufacturer_permissions`
--
ALTER TABLE `android_manufacturer_permissions`
  MODIFY `permission_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `android_permissions`
--
ALTER TABLE `android_permissions`
  MODIFY `permission_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `android_permission_categories`
--
ALTER TABLE `android_permission_categories`
  MODIFY `category_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `android_sdk_versions`
--
ALTER TABLE `android_sdk_versions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `hash_data_ioc`
--
ALTER TABLE `hash_data_ioc`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `malware_samples`
--
ALTER TABLE `malware_samples`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vendor_details`
--
ALTER TABLE `vendor_details`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_activities`
--
ALTER TABLE `vt_activities`
  MODIFY `record_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_api_keys`
--
ALTER TABLE `vt_api_keys`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_intent_filters`
--
ALTER TABLE `vt_intent_filters`
  MODIFY `FilterID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_intent_filters_actions`
--
ALTER TABLE `vt_intent_filters_actions`
  MODIFY `ActionID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_intent_filters_categories`
--
ALTER TABLE `vt_intent_filters_categories`
  MODIFY `CategoryID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_permissions`
--
ALTER TABLE `vt_permissions`
  MODIFY `record_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_providers`
--
ALTER TABLE `vt_providers`
  MODIFY `record_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_receivers`
--
ALTER TABLE `vt_receivers`
  MODIFY `record_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vt_services`
--
ALTER TABLE `vt_services`
  MODIFY `record_id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;