--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `username`, `first_name`, `last_name`, `password`, `is_admin`, `account_disabled`, `account_creation_date`, `last_login`) VALUES
(1, 'kingjonsnow', 'Jon', 'Snow', 'snow123', 1, 0, '2024-01-20 00:09:33', NULL),
(2, 'motherofdragons', 'Daenerys', 'Targaryen', 'dragons123', 0, 0, '2024-01-20 00:09:33', NULL),
(3, 'imp_tyrion', 'Tyrion', 'Lannister', 'tyrion123', 0, 0, '2024-01-20 00:09:33', NULL),
(4, 'arya_stark', 'Arya', 'Stark', 'arya123', 0, 1, '2024-01-20 00:09:33', NULL),
(5, 'sansa_stark', 'Sansa', 'Stark', 'sansa123', 0, 0, '2024-01-20 00:09:33', NULL);