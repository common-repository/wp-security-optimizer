<?php

/* Block direct access */
if (!defined('ABSPATH')) {
	die('Direct access not allowed!');
}



global $wpdb;

$charset_collate = $wpdb->get_charset_collate();



//References to recent attacks
$table_name_attacker = $wpdb->prefix . SEC_OPT_ATTACKER;


$sql_query_attacker = "CREATE TABLE $table_name_attacker (
  id BIGINT NOT NULL AUTO_INCREMENT,
  IP_attacker varchar(39) NOT NULL DEFAULT '0',
  last_seen_timestamp timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  type_attack varchar(256) DEFAULT '' NOT NULL,
  fail_log_counter int NOT NULL DEFAULT '1',
  PRIMARY KEY  (id)
) $charset_collate;";




//Counters of received attacks
$table_name_general_counter = $wpdb->prefix . SEC_OPT_GENERAL_COUNTER;


$sql_query_general_counter = "CREATE TABLE $table_name_general_counter (
  id int NOT NULL AUTO_INCREMENT,
  total_xmlrpc_attack int NOT NULL DEFAULT '0',
  total_bruteforce_attack int NOT NULL DEFAULT '0',
  total_wpscan_attack int NOT NULL DEFAULT '0',
  total_badbot_attack int NOT NULL DEFAULT '0',
  PRIMARY KEY  (id)
) $charset_collate;";




//Cyber attacks statistics
$table_name_attack_history = $wpdb->prefix . SEC_OPT_ATTACK_HISTORY;

$sql_query_attack_history = "CREATE TABLE $table_name_attack_history (
  id int NOT NULL AUTO_INCREMENT,
  IP_attacker varchar(39) NOT NULL DEFAULT '0',
  last_seen_timestamp timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  useragent varchar(256) DEFAULT '' NOT NULL,
  type_attack varchar(256) DEFAULT '' NOT NULL,
  PRIMARY KEY  (id)
) $charset_collate;";




?>
