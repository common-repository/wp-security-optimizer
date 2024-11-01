<?php

/* Block direct access */
if (!defined('ABSPATH')) {
        die('Direct access not allowed!');
}

 // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }

?>

<style type="text/css">

div.box
{
width: 360px;
padding: 10px;
border: 1px solid #d0c9c9;
border-radius: 10px;
-moz-border-radius: 10px;
}


div.bigbox
{
width: 50%;
padding: 10px;
border: 1px solid #d0c9c9;
border-radius: 10px;
-moz-border-radius: 10px;
}



#parent {
overflow: hidden;
border: 0px solid red
}
.right {
float: left;
width: 360px;
height: 150px;
margin: 1px 5px;
display: inline;
overflow-x: auto;

}
.left {
float: left;
overflow-x: auto;
width: 360px;
height: 150px;
margin: 1px 5px;
display: inline;
}

.right_down {
float: left;
width: 360px;
height: 280px;
margin: 1px 5px;
display: inline;
overflow-x: auto;

}
.left_down {
float: left;
overflow-x: auto;
width: 360px;
height: 280px;
margin: 1px 5px;
display: inline;
}
.center_down {
float: left;
width: 50%;
height: 130px;
margin: 1px 5px;
display: inline;
overflow-x: auto;
}

.center_down2 {
float: left;
width: 50%;
height: 600px;
margin: 1px 5px;
display: inline;
overflow-x: auto;
}



</style>


<div id="parent">



<div style="background-color:#0073aa; width:50%; padding: 10px; color: white;">

<?php
$image_logo = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/logo.png";
echo '<img src="' . $image_logo . '" />';
?>


</div>

<br />

<?php if ( isset( $_GET['message'] ) && ( $_GET['message'] == '4' )) { ?>
<div id='message' style='width:120px;' class='updated fade'><p><strong>Scan Completed</strong></p></div>
<br />
<?php } ?>


<div id="parent">


<div id="sec_opt_xmlrpc" class="center_down bigbox">

<h2>File Integrity Check</h2>
File Integrity Check (FIC) is a critical functionality for Wordpress security, inasmuch ensure that PHP files stored in "wp-admin" and "wp-include" folders are not corrupted and infected. Furthermore WP Security Optimizer will find PHP scripts in the uploads folder, designed for media files and used by hacker to publish data injected with malware
<br />

</div>
</div>

<br />



<div id="sec_opt_fic" class="center_down2">

<?php

if(defined('WP_CONTENT_DIR') && !defined('WP_INCLUDE_DIR')){
   define('WP_INCLUDE_DIR', str_replace('wp-content', 'wp-includes', WP_CONTENT_DIR));
}

define ('WP_SEC_OPT_WPADMIN', ABSPATH . "wp-admin");


require (plugin_dir_path( __FILE__ ) . '../lib/hash.php');

$wp_sec_opt_scan_dir = array(
WP_INCLUDE_DIR,
WP_SEC_OPT_WPADMIN
);


global $wp_version;


require (plugin_dir_path( __FILE__ ) . '../lib/hash_vers.php');

$cx=0;

foreach ($supported_versions as $versione){
if (strcmp($versione, $wp_version) == 0)
$cx++;
}

if ($cx == 0) {
echo "This feature is not supported in your Wordpress version. If you've just installed/upgraded to the latest stable version, the plugin update will be released within a few hours";
return;
}

$hash_check=0;
$total_file_infected=0;
$just_print=1;

foreach ($wp_sec_opt_scan_dir as $scan_dir) {

$objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scan_dir));
        $objects->setMaxDepth(32);

  foreach($objects as $name => $object){


 if (stristr($name,".php") != FALSE)
                        {

 $cur_file_hash = md5_file($name);

 foreach ($data_hash as $hash_to_check){	
if ( $hash_to_check == $cur_file_hash ) $hash_check++; 
}

if ($hash_check == 0){

if ($just_print){
$just_print=0; 
echo "<span style=\"color: red;  font-size: 15px;\">WP Security Optimizer has detected a data corruption in the following files:</span><br />";
echo "<span style=\"color: red;  font-size: 12px;\">(Please continue investigation if you doesn't manually change those files)</span><br /><br />";
}

echo "<span style=\"color: black; font-size: 13px;\"> $name </span><br />";
$total_file_infected++;
}

}

$hash_check=0;

}

}


$upload_dir = WP_CONTENT_DIR . "/uploads/";
$just_print_uploads=1;

$objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($upload_dir));
$objects->setMaxDepth(32);

  foreach($objects as $name => $object){


 if ( (stristr($name,".php") != FALSE) && (md5_file($name) != "d41d8cd98f00b204e9800998ecf8427e") )
                        {

if ($just_print_uploads){
$just_print_uploads=0;
echo "<br /><span style=\"color: red;  font-size: 15px;\">WP Security Optimizer has detected the following PHP files into \"uploads\" directory:</span><br />";
echo "<span style=\"color: red;  font-size: 12px;\">(Please continue investigation if you doesn't manually uploaded those files)</span><br /><br />";
}

echo "<span style=\"color: black; font-size: 13px;\"> $name </span><br />";
$total_file_infected++;


}
}

if ($total_file_infected == 0){
$image_clean = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/clean.png";
echo "<br /><img src=\"$image_clean\" />";
}

?>
<form method="post" action="admin-post.php">
<input type="hidden" name="action" value="process_sec_opt_fic" />
<?php wp_nonce_field( 'sec_opt' ); ?> 
<br />
<br />
<input type="submit" style="width:150px; height:40px; font-size: 17px; font-family:arial;font-size:14px;font-weight:bold;" value="Rescan" class="button-primary"/>
</form>
<?php


?>



</div>


</div>
