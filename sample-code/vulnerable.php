<?php
// Triggers: insecure-sql-php
$conn = mysqli_connect("localhost", "root", "", "test");
mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id']);
?>
