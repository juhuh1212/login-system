<?php
$servername = "localhost";
$username = "root"; // default XAMPP user
$password = "";     // default XAMPP password is empty
$dbname = "login_db";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
