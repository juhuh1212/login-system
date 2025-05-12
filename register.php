<?php
require_once "config.php";

$username = $email = $password = $confirm_password = "";
$username_err = $email_err = $password_err = $confirm_password_err = $success_msg = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Username validation
    if (empty(trim($_POST["username"]))) {
        $username_err = "Please enter a username.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("s", $param_username);
            $param_username = trim($_POST["username"]);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows == 1) {
                $username_err = "This username is already taken.";
            } else {
                $username = trim($_POST["username"]);
            }
            $stmt->close();
        }
    }

    // Email validation
    if (empty(trim($_POST["email"]))) {
        $email_err = "Please enter an email.";
    } elseif (!filter_var(trim($_POST["email"]), FILTER_VALIDATE_EMAIL)) {
        $email_err = "Invalid email format.";
    } else {
        $sql = "SELECT id FROM users WHERE email = ?";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("s", $param_email);
            $param_email = trim($_POST["email"]);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows == 1) {
                $email_err = "This email is already registered.";
            } else {
                $email = trim($_POST["email"]);
            }
            $stmt->close();
        }
    }

    // Password validation
    if (empty(trim($_POST["password"]))) {
        $password_err = "Please enter a password.";
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "Password must have at least 6 characters.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Confirm password
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Please confirm password.";
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if ($password != $confirm_password) {
            $confirm_password_err = "Passwords did not match.";
        }
    }

    // Insert if no errors
    if (empty($username_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {
        $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("sss", $param_username, $param_email, $param_password);
            $param_username = $username;
            $param_email = $email;
            $param_password = password_hash($password, PASSWORD_DEFAULT);
            if ($stmt->execute()) {
                $success_msg = "Registration successful! <a href='login.php'>Login here</a>.";
                $username = $email = $password = $confirm_password = "";
            } else {
                $username_err = "Something went wrong. Please try again.";
            }
            $stmt->close();
        }
    }
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <h2>Register</h2>
    <?php if($success_msg) echo "<div class='success'>$success_msg</div>"; ?>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <label>Username</label>
        <input type="text" name="username" value="<?php echo htmlspecialchars($username); ?>">
        <span class="error"><?php echo $username_err; ?></span>

        <label>Email</label>
        <input type="email" name="email" value="<?php echo htmlspecialchars($email); ?>">
        <span class="error"><?php echo $email_err; ?></span>

        <label>Password</label>
        <input type="password" name="password">
        <span class="error"><?php echo $password_err; ?></span>

        <label>Confirm Password</label>
        <input type="password" name="confirm_password">
        <span class="error"><?php echo $confirm_password_err; ?></span>

        <input type="submit" value="Register">
        <p>Already have an account? <a href="login.php">Login here</a>.</p>
    </form>
</div>
</body>
</html>
