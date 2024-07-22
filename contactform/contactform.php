<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Dotenv\Dotenv;

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// Function to sanitize input data
function sanitizeInput($data) {
    return htmlspecialchars(trim($data));
}

// Function to validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Rate Limiter - Allow only 1 requests per minute per IP
session_start();
$requestsLimit = 1; // Number of requests allowed
$minutesLimit = 1; // Time limit in minutes
$currentTimestamp = time();
$requestsKey = 'requests_' . $_SERVER['REMOTE_ADDR'];

if (!isset($_SESSION[$requestsKey])) {
    $_SESSION[$requestsKey] = [];
}

// Clean up old requests data
foreach ($_SESSION[$requestsKey] as $timestamp => $count) {
    if ($timestamp < $currentTimestamp - $minutesLimit * 60) {
        unset($_SESSION[$requestsKey][$timestamp]);
    }
}

// Check request limit
if (array_sum($_SESSION[$requestsKey]) >= $requestsLimit) {
    echo "Too many requests. Please try again later.";
    exit;
}

// Increase request count for current minute
$_SESSION[$requestsKey][$currentTimestamp] = ($_SESSION[$requestsKey][$currentTimestamp] ?? 0) + 1;

// Handle POST request
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $sender = sanitizeInput($_POST['name']);
    $subject = sanitizeInput($_POST['subject']);
    $message = sanitizeInput($_POST['message']);
    $from = sanitizeInput($_POST['email']);
    
    // Validate input
    if ($sender && $subject && $message && $from && validateEmail($from)) {
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth = true;
            $mail->Username = $_ENV['SMTP_USERNAME'];
            $mail->Password = $_ENV['SMTP_PASSWORD'];
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = $_ENV['SMTP_PORT'];
            $mail->setFrom($from, $sender);
            $mail->addAddress($_ENV['SMTP_USERNAME']);
            $mail->addReplyTo($from, $sender);
            $mail->Subject = $subject;
            $mail->Body = $message;
            $mail->send();
            echo 'OK';
        } catch (Exception $e) {
            echo "Failed to send email. Please try again later.";
        }
    } else {
        echo "Failed to send email. Invalid input.";
    }
} else {
    echo "Failed to send email. Only POST requests are allowed.";
}
