--
-- Dumping data for table `android_sdk_versions`
--

INSERT INTO `android_sdk_versions` (`id`, `api_level`, `version_number`, `version_name`, `release_date`, `key_features`, `security_enhancements`, `permission_changes`, `system_changes`, `remarks`) VALUES
(1, 21, '5.0', 'Lollipop', '2014-11-12', 'Material design, Notifications on the lock screen, Battery saver feature', 'SELinux enforcing for all apps, encrypted data on disk by default', 'New runtime permissions model introduced', 'ART (Android Runtime) replaces Dalvik to improve application performance and responsiveness', 'Introduced material design.'),
(2, 22, '5.1', 'Lollipop', '2015-03-09', 'Improvements to the notifications, Device protection against stolen devices', NULL, NULL, 'Support for multiple SIM cards, HD voice calls, and Device Protection feature', NULL),
(3, 23, '6.0', 'Marshmallow', '2015-10-05', 'Doze mode for battery, App Standby, Runtime permissions', 'Verified Boot ensures device integrity', 'Runtime permissions model giving users more control over app permissions', 'Doze and App Standby improve battery life', 'Introduced runtime permissions.'),
(4, 24, '7.0', 'Nougat', '2016-08-22', 'Multi-window support, Direct Reply notifications, Quick switch between apps', NULL, 'Direct boot', 'JIT compiler improves runtime device performance', NULL),
(5, 25, '7.1', 'Nougat', '2016-10-04', 'App shortcuts, Round icon resources', NULL, NULL, 'Support for image keyboards and GIFs', NULL),
(6, 26, '8.0', 'Oreo', '2017-08-21', 'Picture-in-picture mode, Notification channels, Autofill API', 'Google Play Protect, stronger app sandbox', 'Background execution limits, Background location limits', 'Project Treble for faster OS updates', 'Introduced Project Treble for modular architecture.'),
(7, 27, '8.1', 'Oreo', '2017-12-05', 'Neural Networks API, Shared memory API', NULL, NULL, 'Minor updates and optimizations over 8.0', NULL),
(8, 28, '9', 'Pie', '2018-08-06', 'Adaptive Battery, Gesture Navigation, App Actions & Slices', 'Biometric prompt, Android Protected Confirmation', NULL, 'Improved security features for apps, DNS over TLS support', 'Introduced Adaptive Battery.'),
(9, 29, '10', 'Android 10', '2019-09-03', 'Dark theme, Smart reply, Live Caption', 'Scoped storage, Project Mainline', NULL, 'Support for foldable phones and 5G', 'First version released as \"Android 10\" without a dessert name.'),
(10, 30, '11', 'Android 11', '2020-09-08', 'Conversations and Bubbles, Device Controls, Media Controls', 'One-time permission, Permissions auto-reset', NULL, 'Enhanced 5G support, Improved call screening', NULL),
(11, 31, '12', 'Android 12', '2021-10-04', 'Material You design, Privacy dashboard, Stretch overscroll effect', 'Approximate location permissions, Microphone and camera toggles', NULL, 'Game Mode API, Haptic feedback experiences', 'Introduced Material You design system.'),
(12, 32, '12L', 'Android 12L', '2022-03-07', 'Optimizations for tablets, foldables, and large screens', NULL, NULL, 'Refined multitasking interface, new taskbar', 'Special version for large screens.'),
(13, 33, '13', 'Android 13', '2022-08-15', 'Per-app language settings, Improved privacy features, Themed app icons', NULL, NULL, 'Increased control over notifications, Better clipboard management', 'Focus on privacy and user personalization.');
