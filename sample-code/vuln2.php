<?php
// SQLi via $_POST
$conn = mysqli_connect("localhost", "root", "", "test");
$sql = "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'";
$result = mysqli_query($conn, $sql);
?>
