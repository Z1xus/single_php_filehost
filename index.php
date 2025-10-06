<?php
require 'vendor/autoload.php';

use MongoDB\Client;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

session_start();

$is_file_upload = $_SERVER['REQUEST_METHOD'] === 'POST';

$uri = $_ENV['MONGODB_URI'];
$client = new Client($uri);
$collection = $client->selectCollection($_ENV['DB_NAME'], $_ENV['COLLECTION_NAME']);
$invitesCollection = $client->selectCollection($_ENV['DB_NAME'], 'invites');

if (isset($_SERVER['HTTP_TOKEN'])) {
    validateToken($collection);
}

$usernameValue = isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : null;
$passwordValue = $_POST['password'] ?? null;

$inviteCodeValue = isset($_POST['invite_code']) ? htmlspecialchars($_POST['invite_code'], ENT_QUOTES, 'UTF-8') : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($inviteCodeValue)) {
    $errorMessage = userRegister($usernameValue, $passwordValue, $inviteCodeValue, $invitesCollection, $collection);
} else {
    $errorMessage = validateCredentials($usernameValue, $passwordValue, $collection);
}

if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    serveLoginPage($errorMessage, $usernameValue, $passwordValue);
}

function html_header() {
    echo <<<EOT
<!DOCTYPE html>
<html lang="en">
<head>
    <title>zentimine the filehost</title>
    <link rel="icon" type="image/x-icon" href="img/favicon.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <meta name="referrer" content="strict-origin-when-cross-origin">

    <meta property="og:type" content="website" />
    <meta property="og:title" content="Sherbert" />
    <meta property="og:description" content="Best filehost <3\nRequest access @z1xus" />
    <meta property="og:url" content="https://zentimine.xyz/" />
    <meta property="og:image" content="https://zentimine.xyz/img/sherbert.jpg" />
    <meta name="theme-color" content="#a39187" />
    <meta name="twitter:card" content="summary_large_image">
</head>
EOT;
}

class CONFIG
{
    const MAX_FILESIZE = 2048; //max. filesize in MiB
    const MAX_FILEAGE = 0; //max. age of files in days
    const MIN_FILEAGE = 7; //min. age of files in days
    const DECAY_EXP = 2; //high values penalise larger files more

    const UPLOAD_TIMEOUT = 5*60; //max. time an upload can take before it times out
    const ID_LENGTH = 3; //length of the random file ID
    const STORE_PATH = 'files/'; //directory to store uploaded files in
    const LOG_PATH = 'uploads.log'; //path to log uploads + resulting links to
    const DOWNLOAD_PATH = '%s'; //the path part of the download url. %s = placeholder for filename
    const MAX_EXT_LEN = 7; //max. length for file extensions
    const EXTERNAL_HOOK = null; //external program to call for each upload
    const AUTO_FILE_EXT = false; //automatically try to detect file extension for files that have none

    const ADMIN_EMAIL = 'z1xuss@proton.me';  //address for inquiries

    public static function SITE_URL() : string
    {
        $proto = ($_SERVER['HTTPS'] ?? 'off') == 'on' ? 'https' : 'http';
        return "$proto://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
    }
};

function validateToken($collection) {
    $token = htmlspecialchars($_SERVER['HTTP_TOKEN'] ?? '', ENT_QUOTES, 'UTF-8');
    $user = $collection->findOne(['token' => $token]);

    if ($user !== null) {
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $user['username'];
        $_SESSION['token'] = $user['token'];
    } else {
        header('HTTP/1.0 401 Unauthorized');
        echo 'Invalid token';
        exit;
    }
}

function validateCredentials($usernameValue, $passwordValue, $collection) {
    if (isset($usernameValue) && isset($passwordValue)) {
        $username = $usernameValue;
        $password = $passwordValue;

        if (!empty($username) && !empty($password)) {
            if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) {
                return "Invalid username format";
            }
            
            $user = $collection->findOne(['username' => $username]);

            if ($user !== null && password_verify($password, $user['password'])) {
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $user['username'];
                $_SESSION['token'] = $user['token'];
            } else {
                usleep(500000);
                return "Invalid credentials";
            }
        } else {
            return "The fields cannot be empty";
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request']) && $_POST['request'] === 'generateInviteCode') {
    if (isset($_SESSION['username'])) {
        $username = $_SESSION['username'];
        $inviteCode = generateInviteCode($username, $invitesCollection);
        echo $inviteCode;
        exit;
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

function generateInviteCode($username, $invitesCollection) {
    $inviteCode = generateToken(10);

    $invitesCollection->insertOne([
        'code' => $inviteCode,
        'isValid' => true,
        'generatedBy' => $username
    ]);

    return $inviteCode;
}

function userRegister($usernameValue, $passwordValue, $inviteCodeValue, $invitesCollection, $collection) {
    if (isset($usernameValue) && isset($passwordValue) && isset($inviteCodeValue)) {
        $username = $usernameValue;
        $password = $passwordValue;
        $inviteCode = $inviteCodeValue;

        if (!empty($username) && !empty($password) && !empty($inviteCode)) {
            if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) {
                return "Invalid username format (3-32 alphanumeric chars, _ or - allowed)";
            }
            
            if (strlen($password) < 8) {
                return "Password must be at least 8 characters long";
            }
            
            if ($collection->findOne(['username' => $username]) !== null) {
                return "Username already taken";
            }
            
            $inviteCodeEntry = $invitesCollection->findOne(['code' => $inviteCode]);

            if ($inviteCodeEntry !== null && $inviteCodeEntry['isValid'] === true) {
                $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);
                $token = generateToken(64);

                $collection->insertOne([
                    'username' => $username,
                    'password' => $hashedPassword,
                    'isAdmin' => false,
                    'token' => $token,
                    'usedInviteCode' => $inviteCode,
                    'createdAt' => new \MongoDB\BSON\UTCDateTime()
                ]);

                $invitesCollection->updateOne(
                    ['code' => $inviteCode],
                    ['$set' => ['isValid' => false, 'usedAt' => new \MongoDB\BSON\UTCDateTime()]]
                );

                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['token'] = $token;
            } else {
                usleep(500000); // Prevent timing attacks
                return "Invalid invite code";
            }
        } else {
            return "All fields must be filled";
        }
    }
}

function userCreate($usernameValue, $passwordValue, $isAdmin, $collection) {
    if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $usernameValue)) {
        return false;
    }
    
    if ($collection->findOne(['username' => $usernameValue]) !== null) {
        return false;
    }
    
    if (strlen($passwordValue) < 8) {
        return false;
    }
    
    $hashedPassword = password_hash($passwordValue, PASSWORD_ARGON2ID);
    $token = generateToken(64);

    $collection->insertOne([
        'username' => $usernameValue,
        'password' => $hashedPassword,
        'isAdmin' => $isAdmin,
        'token' => $token,
        'createdAt' => new \MongoDB\BSON\UTCDateTime()
    ]);
    
    return true;
}

function serveLoginPage($errorMessage, $usernameValue, $passwordValue) {
    html_header();
    $headerText = "login";
    echo <<<EOT
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #bb86fc;
            --primary-dark: #9965db;
            --primary-light: #c8a3f0;
            --bg-dark: #000000;
            --bg-elevated: #0a0a0a;
            --bg-card: #111111;
            --text-primary: #e0e0e0;
            --text-secondary: #808080;
            --border: rgba(187, 134, 252, 0.15);
            --shadow: 0 2px 8px rgba(0, 0, 0, 0.6);
            --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.8);
        }
        
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, var(--bg-dark) 0%, #0a0314 100%);
            font-family: 'Space Mono', monospace;
            color: var(--text-primary);
            padding: 12px;
            text-transform: lowercase;
        }
        
        form {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 24px;
            width: 100%;
            max-width: 380px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border);
        }
        
        h2 {
            text-align: center;
            color: var(--text-primary);
            margin-bottom: 20px;
            font-size: 18px;
            font-weight: 700;
        }
        
        h2::before {
            content: '# ';
            color: var(--primary);
        }
        
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            margin-bottom: 12px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--bg-elevated);
            color: var(--text-primary);
            font-size: 11px;
            font-family: 'Space Mono', monospace;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }
        
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(187, 134, 252, 0.1);
        }
        
        input[type="text"]::placeholder, input[type="password"]::placeholder {
            color: var(--text-secondary);
        }
        
        input[type="submit"] {
            width: 100%;
            padding: 10px 16px;
            border-radius: 8px;
            border: none;
            font-size: 12px;
            font-weight: 400;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            font-family: 'Space Mono', monospace;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: var(--text-primary);
        }
        
        input[type="submit"]:hover {
            transform: translateY(-2px);
        }
        
        input[type="submit"]:active {
            transform: translateY(0);
        }
        
        .error {
            color: #cf6679;
            margin-bottom: 12px;
            font-size: 11px;
            min-height: 16px;
        }
        
        .password-container {
            position: relative;
        }
        
        .eye-icon {
            position: absolute;
            right: 12px;
            top: 12px;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 11px;
            transition: color 0.2s ease;
        }
        
        .eye-icon:hover {
            color: var(--text-primary);
        }
        
        .toggle-link {
            display: block;
            text-align: right;
            margin-top: 12px;
            color: var(--primary);
            text-decoration: none;
            font-size: 11px;
            transition: color 0.2s ease;
        }
        
        .toggle-link:hover {
            color: var(--primary-light);
        }
    </style>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" />
    <form method="post">
        <h2 id="formHeader">$headerText</h2>
        <input type="text" id="username" name="username" value="$usernameValue" placeholder="username">
        <div class="password-container">
            <input type="password" id="password" name="password" value="$passwordValue" placeholder="password">
            <i id="togglePassword" class="fas fa-eye eye-icon" onclick="togglePasswordVisibility()"></i>
        </div>
        <div class="error">$errorMessage</div>
        <input type="submit" value="login">
        <a href="#" id="toggleForm" onclick="toggleForms()" class="toggle-link">register</a>
    </form>
    <script>
        function togglePasswordVisibility() {
            var passwordField = document.getElementById('password');
            var togglePasswordIcon = document.getElementById('togglePassword');
            if (passwordField.type === "password") {
                passwordField.type = "text";
                togglePasswordIcon.classList.remove('fa-eye');
                togglePasswordIcon.classList.add('fa-eye-slash');
            } else {
                passwordField.type = "password";
                togglePasswordIcon.classList.remove('fa-eye-slash');
                togglePasswordIcon.classList.add('fa-eye');
            }
        }
        let isLoginForm = true;
        let inviteCodeFieldHTML = '<input type="text" id="invite_code" name="invite_code" placeholder="invite code" style="margin-bottom: 12px;">';

        function toggleForms() {
            const form = document.querySelector('form');
            const toggleFormLink = document.getElementById('toggleForm');
            const passwordContainer = form.querySelector('.password-container');
            const formHeader = document.getElementById('formHeader');
            if (isLoginForm) {
                passwordContainer.insertAdjacentHTML('afterend', inviteCodeFieldHTML);
                toggleFormLink.textContent = 'login';
                formHeader.textContent = 'register';
                form.querySelector('input[type="submit"]').value = 'register';
            } else {
                form.querySelector('#invite_code').remove();
                toggleFormLink.textContent = 'register';
                formHeader.textContent = 'login';
                form.querySelector('input[type="submit"]').value = 'login';
            }
            isLoginForm = !isLoginForm;
        }
    </script>
    EOT;
    exit;
}

// generate a random string of characters with given length
function rnd_str(int $len) : string
{
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    $max_idx = strlen($chars) - 1;
    $out = '';
    while ($len--)
    {
        $out .= $chars[random_int(0,$max_idx)];
    }
    return $out;
}

// check php.ini settings and print warnings if anything's not configured properly
function check_config() : void
{
    $warn_config_value = function($ini_name, $var_name, $var_val)
    {
        $ini_val = intval(ini_get($ini_name));
        if ($ini_val < $var_val)
            print("<pre>Warning: php.ini: $ini_name ($ini_val) set lower than $var_name ($var_val)\n</pre>");
    };

    $warn_config_value('upload_max_filesize', 'MAX_FILESIZE', CONFIG::MAX_FILESIZE);
    $warn_config_value('post_max_size', 'MAX_FILESIZE', CONFIG::MAX_FILESIZE);
    $warn_config_value('max_input_time', 'UPLOAD_TIMEOUT', CONFIG::UPLOAD_TIMEOUT);
    $warn_config_value('max_execution_time', 'UPLOAD_TIMEOUT', CONFIG::UPLOAD_TIMEOUT);
}

//extract extension from a path (does not include the dot)
function ext_by_path(string $path) : string
{
    $ext = pathinfo($path, PATHINFO_EXTENSION);
    //special handling of .tar.* archives
    $ext2 = pathinfo(substr($path,0,-(strlen($ext)+1)), PATHINFO_EXTENSION);
    if ($ext2 === 'tar')
    {
        $ext = $ext2.'.'.$ext;
    }
    return $ext;
}

function ext_by_finfo(string $path) : string
{
    $finfo = finfo_open(FILEINFO_EXTENSION);
    $finfo_ext = finfo_file($finfo, $path);
    finfo_close($finfo);
    if ($finfo_ext != '???')
    {
        return explode('/', $finfo_ext, 2)[0];
    }
    else
    {
        $finfo = finfo_open();
        $finfo_info = finfo_file($finfo, $path);
        finfo_close($finfo);
        if (strstr($finfo_info, 'text') !== false)
        {
            return 'txt';
        }
    }
    return '';
}

function sanitize_filename($name){
    $sanitized = preg_replace('/[^a-zA-Z0-9_\.]/',' ', $name);
    $sanitized = str_replace(" ", "_", $sanitized);
    return $sanitized;
}

function show_error_page($title, $message) {
    html_header();
    echo <<<EOT
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #bb86fc;
            --primary-dark: #9965db;
            --primary-light: #c8a3f0;
            --bg-dark: #000000;
            --bg-elevated: #0a0a0a;
            --bg-card: #111111;
            --text-primary: #e0e0e0;
            --text-secondary: #808080;
            --border: rgba(187, 134, 252, 0.15);
            --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.8);
            --error: #cf6679;
        }
        
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, var(--bg-dark) 0%, #0a0314 100%);
            font-family: 'Space Mono', monospace;
            color: var(--text-primary);
            padding: 12px;
            text-transform: lowercase;
        }
        
        .error-container {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 32px 28px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border);
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        
        h2 {
            font-size: 18px;
            font-weight: 700;
            color: var(--error);
            margin-bottom: 12px;
        }
        
        h2::before {
            content: '# ';
            color: var(--error);
        }
        
        .error-message {
            color: var(--text-secondary);
            font-size: 12px;
            margin-bottom: 24px;
        }
        
        .btn {
            padding: 10px 20px;
            border-radius: 8px;
            border: none;
            font-size: 12px;
            font-weight: 400;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            font-family: 'Space Mono', monospace;
            text-decoration: none;
            display: inline-block;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: var(--text-primary);
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
    </style>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
    
    <div class="error-container">
        <h2>$title</h2>
        <p class="error-message">$message</p>
        <a href="/" class="btn">go back</a>
    </div>
EOT;
    exit;
}

// store an uploaded file, given its name and temporary path (e.g. values straight out of $_FILES)
// files are stored wit a randomised name, but with their original extension
//
// $name: original filename
// $tmpfile: temporary path of uploaded file
// $formatted: set to true to display formatted message instead of bare link
function store_file(string $name, string $tmpfile, bool $formatted = false) : void
{
    if (strpos($name, '..') !== false || strpos($name, '/') !== false || strpos($name, '\\') !== false) {
        header('HTTP/1.0 400 Bad Request');
        print('Error 400: Invalid filename\n');
        return;
    }
    
    //create folder, if it doesn't exist
    if (!file_exists(CONFIG::STORE_PATH))
    {
        mkdir(CONFIG::STORE_PATH, 0750, true);
    }

    //check file size
    $size = filesize($tmpfile);
    if ($size > CONFIG::MAX_FILESIZE * 1024 * 1024)
    {
        if ($formatted) {
            show_error_page("file too large", "maximum file size is " . CONFIG::MAX_FILESIZE . " mib");
        } else {
            header('HTTP/1.0 413 Payload Too Large');
            print("Error 413: Max File Size (" . CONFIG::MAX_FILESIZE . " MiB) Exceeded\n");
        }
        return;
    }
    if ($size == 0)
    {
        if ($formatted) {
            show_error_page("empty file", "uploaded file is empty");
        } else {
            header('HTTP/1.0 400 Bad Request');
            print('Error 400: Uploaded file is empty\n');
        }
        return;
    }

    $original_name = pathinfo($name, PATHINFO_FILENAME);
    $ext = ext_by_path($name);
    
    if (strlen($ext) > CONFIG::MAX_EXT_LEN) {
        $ext = substr($ext, 0, CONFIG::MAX_EXT_LEN);
    }
    
    $basename = sanitize_filename($original_name . '_' . rnd_str(5) . '.' . $ext);
    $target_file = CONFIG::STORE_PATH . $basename;

    $res = move_uploaded_file($tmpfile, $target_file);
    if (!$res)
    {
        //TODO: proper error handling?
        header('HTTP/1.0 520 Unknown Error');
        return;
    }
    
    if (CONFIG::EXTERNAL_HOOK !== null)
    {
        putenv('REMOTE_ADDR='.$_SERVER['REMOTE_ADDR']);
        putenv('ORIGINAL_NAME='.$name);
        putenv('STORED_FILE='.$target_file);
        $ret = -1;
        $out = null;
        $last_line = exec(CONFIG::EXTERNAL_HOOK, $out, $ret);
        if ($last_line !== false && $ret !== 0)
        {
            unlink($target_file);
            header('HTTP/1.0 400 Bad Request');
            print("Error: $last_line\n");
            return;
        }
    }

    //print the download link of the file
    $url = sprintf(CONFIG::SITE_URL().CONFIG::DOWNLOAD_PATH, $basename);

    if ($formatted)
    {
        html_header();
        echo <<<EOT
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --primary: #bb86fc;
                --primary-dark: #9965db;
                --primary-light: #c8a3f0;
                --bg-dark: #000000;
                --bg-elevated: #0a0a0a;
                --bg-card: #111111;
                --text-primary: #e0e0e0;
                --text-secondary: #808080;
                --border: rgba(187, 134, 252, 0.15);
                --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.8);
            }
            
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, var(--bg-dark) 0%, #0a0314 100%);
                font-family: 'Space Mono', monospace;
                color: var(--text-primary);
                padding: 12px;
                text-transform: lowercase;
            }
            
            .success-container {
                background: var(--bg-card);
                border-radius: 10px;
                padding: 32px 28px;
                box-shadow: var(--shadow-lg);
                border: 1px solid var(--border);
                max-width: 500px;
                width: 100%;
                text-align: center;
            }
            
            .success-icon {
                font-size: 48px;
                margin-bottom: 16px;
            }
            
            h2 {
                font-size: 18px;
                font-weight: 700;
                color: var(--text-primary);
                margin-bottom: 20px;
            }
            
            h2::before {
                content: '# ';
                color: var(--primary);
            }
            
            .url-box {
                background: var(--bg-elevated);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 16px;
                word-break: break-all;
            }
            
            .url-link {
                color: var(--primary);
                text-decoration: none;
                font-size: 12px;
                transition: color 0.2s ease;
            }
            
            .url-link:hover {
                color: var(--primary-light);
            }
            
            .button-group {
                display: flex;
                gap: 12px;
                justify-content: center;
                flex-wrap: wrap;
            }
            
            .btn {
                padding: 10px 20px;
                border-radius: 8px;
                border: none;
                font-size: 12px;
                font-weight: 400;
                cursor: pointer;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                font-family: 'Space Mono', monospace;
                text-decoration: none;
                display: inline-block;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                color: var(--text-primary);
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
            }
            
            .btn-secondary {
                background: var(--bg-elevated);
                color: var(--text-secondary);
                border: 1px solid var(--border);
            }
            
            .btn-secondary:hover {
                color: var(--text-primary);
                transform: translateY(-2px);
            }
            
            .info-text {
                color: var(--text-secondary);
                font-size: 11px;
                margin-top: 16px;
                min-height: 16px;
                opacity: 0;
                transition: opacity 0.2s ease;
            }
            
            .info-text.show {
                opacity: 1;
            }
        </style>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
        
        <div class="success-container">
            <h2>file uploaded successfully</h2>
            
            <div class="url-box">
                <a href="$url" class="url-link" target="_blank">$url</a>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="copyToClipboard('$url')">copy link</button>
                <a href="/" class="btn btn-secondary">upload another</a>
            </div>
            
            <p class="info-text"></p>
        </div>
        
        <script>
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(function() {
                    const infoText = document.querySelector('.info-text');
                    infoText.textContent = '// link copied to clipboard!';
                    infoText.style.color = 'var(--primary)';
                    infoText.classList.add('show');
                    setTimeout(() => {
                        infoText.classList.remove('show');
                    }, 2000);
                }, function(err) {
                    const infoText = document.querySelector('.info-text');
                    infoText.textContent = '// failed to copy link';
                    infoText.style.color = '#cf6679';
                    infoText.classList.add('show');
                    setTimeout(() => {
                        infoText.classList.remove('show');
                    }, 2000);
                });
            }
        </script>
EOT;
    }
    else
    {
        print("$url");
    }

    // log uploader's IP, original filename, etc.
    if (isset($_SESSION['username']) && CONFIG::LOG_PATH)
    {
        $username = $_SESSION['username'];
        file_put_contents(
            CONFIG::LOG_PATH,
            implode("\t", array(
                date('c'),
                $_SERVER['REMOTE_ADDR'],
                $username,
                filesize($tmpfile),
                escapeshellarg($name),
                $basename
            )) . "\n",
            FILE_APPEND
        );
    }
}

// purge all files older than their retention period allows.
function purge_files() : void
{
    if (CONFIG::MAX_FILEAGE === 0) {
        print("File purging is disabled (MAX_FILEAGE = 0)\n");
        return;
    }
    
    $num_del = 0;    //number of deleted files
    $total_size = 0; //total size of deleted files

    //for each stored file
    foreach (scandir(CONFIG::STORE_PATH) as $file)
    {
        //skip virtual . and .. files
        if ($file === '.' ||
            $file === '..')
        {
            continue;
        }

        $file = CONFIG::STORE_PATH . $file;

        $file_size = filesize($file) / (1024*1024); //size in MiB
        $file_age = (time()-filemtime($file)) / (60*60*24); //age in days

        //keep all files below the min age
        if ($file_age < CONFIG::MIN_FILEAGE)
        {
            continue;
        }

        //calculate the maximum age in days for this file
        $file_max_age = CONFIG::MIN_FILEAGE +
                        (CONFIG::MAX_FILEAGE - CONFIG::MIN_FILEAGE) *
                        pow(1 - ($file_size / CONFIG::MAX_FILESIZE), CONFIG::DECAY_EXP);

        //delete if older
        if ($file_age > $file_max_age)
        {
            unlink($file);

            print("deleted $file, $file_size MiB, $file_age days old\n");
            $num_del += 1;
            $total_size += $file_size;
        }
    }
    print("Deleted $num_del files totalling $total_size MiB\n");
}

function send_text_file(string $filename, string $content) : void
{
    header('Content-type: application/octet-stream');
    header("Content-Disposition: attachment; filename=\"$filename\"");
    header('Content-Length: '.strlen($content));
    print($content);
}

// send a ShareX custom uploader config as .json
function send_sharex_config() : void
{
    if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
        header('HTTP/1.0 401 Unauthorized');
        echo 'HTTP/1.0 401 Unauthorized';
        exit;
    }

    if (!isset($_SESSION['username']) || !isset($_SESSION['token'])) {
        header('HTTP/1.0 400 Bad Request');
        echo 'HTTP/1.0 400 Bad Request';
        exit;
    }

    $token = $_SESSION['token'];

    $name = $_SERVER['SERVER_NAME'];
    $site_url = str_replace("?sharex", "", CONFIG::SITE_URL());
    send_text_file($name.'.sxcu', <<<EOT
{
  "Version": "17.0.0",
  "Name": "$name",
  "DestinationType": "ImageUploader, FileUploader",
  "RequestMethod": "POST",
  "RequestURL": "$site_url",
  "Headers": {
    "Token": "$token"
  },
  "Body": "MultipartFormData",
  "FileFormName": "file",
  "URL": "{response}"
}
EOT);
}

// send a Hupl uploader config as .hupl (which is just JSON)
function send_hupl_config() : void
{
    $name = $_SERVER['SERVER_NAME'];
    $site_url = str_replace("?hupl", "", CONFIG::SITE_URL());
    send_text_file($name.'.hupl', <<<EOT
{
  "name": "$name",
  "type": "http",
  "targetUrl": "$site_url",
  "fileParam": "file"
}
EOT);
}

// print a plaintext info page, explaining what this script does and how to
// use it, how to upload, etc.
function print_index() : void
{
    html_header();

    $site_url = CONFIG::SITE_URL();
    $sharex_url = $site_url.'?sharex';
    $hupl_url = $site_url.'?hupl';
    $logout_url = $site_url.'?logout';
    $decay = CONFIG::DECAY_EXP;
    $min_age = CONFIG::MIN_FILEAGE;
    $max_size = CONFIG::MAX_FILESIZE;
    $max_age = CONFIG::MAX_FILEAGE === 0 ? 'unlimited' : CONFIG::MAX_FILEAGE . ' days';
    $warning = CONFIG::MAX_FILEAGE === 0 ? '<p style="font-size: 10px; margin-top: 8px; opacity: 0.7;">do not use as cdn or permanent storage. files may be removed at any time without notice.</p>' : '';
    $mail = CONFIG::ADMIN_EMAIL;
    $username = htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES, 'UTF-8');

    $adminPanel = '';
    if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
        $user = $GLOBALS['collection']->findOne(['username' => $_SESSION['username']]);
        
        if ($user !== null && $user['isAdmin'] === true) {
            $adminPanel = <<<EOT
            <div class="container admin-panel">
                <h2 style="margin-bottom: 1em; user-select: none;">admin panel</h2>
                <form method="post" autocomplete="off">
                    <input class="styled-input" type="text" id="new_username" name="new_username" placeholder="username" autocomplete="off">
                    <input class="styled-input" type="password" id="new_password" name="new_password" placeholder="password" autocomplete="off">
                    <p style="padding-bottom: 0.8em; text-align: left !important; width: 100%;">
                      <label>
                        <input type="checkbox" id="isAdmin" name="isAdmin" />
                        <span>administrator</span>
                      </label>
                    </p>
                    <button class="styled-btn primary-btn" type="submit">create user</button>
                </form>
                <form method="post" id="inviteCodeForm" autocomplete="off">
                    <div class="btn-container">
                        <input class="styled-input" type="text" id="inviteCode" name="inviteCode" placeholder="invite code" readonly>
                        <button class="icon-btn primary-btn" type="button" id="generateInviteCode">
                            <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z" /></svg>
                        </button>
                    </div>
                </form>
            </div>
            <script>
                document.getElementById("generateInviteCode").addEventListener("click", function() {
                    var xhttp = new XMLHttpRequest();
                    xhttp.onreadystatechange = function() {
                        if (this.readyState == 4 && this.status == 200) {
                            document.getElementById("inviteCode").value = this.responseText;
                        }
                    };
                    xhttp.open("POST", "/", true);
                    xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                    xhttp.send("request=generateInviteCode");
                });
            </script>
            EOT;
        }
    }

    echo <<<EOT
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>zentimine.xyz</title>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
        <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --primary: #bb86fc;
                --primary-dark: #9965db;
                --primary-light: #c8a3f0;
                --bg-dark: #000000;
                --bg-elevated: #0a0a0a;
                --bg-card: #111111;
                --text-primary: #e0e0e0;
                --text-secondary: #808080;
                --border: rgba(187, 134, 252, 0.15);
                --shadow: 0 2px 8px rgba(0, 0, 0, 0.6);
                --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.8);
            }
            
            body {
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, var(--bg-dark) 0%, #0a0314 100%);
                font-family: 'Space Mono', monospace;
                color: var(--text-primary);
                padding: 12px;
                text-transform: lowercase;
            }
            
            .wrapper {
                width: 100%;
                max-width: 420px;
                animation: fadeIn 0.5s ease-out;
            }
            
            .admin-panel .container {
                max-width: 420px;
                margin-left: auto;
                margin-right: auto;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .header-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
                padding: 0 4px;
            }
            
            .user-info {
                display: flex;
                align-items: center;
                gap: 6px;
                color: var(--text-secondary);
                font-size: 11px;
                font-weight: 400;
            }
            
            .user-info::before {
                content: '>';
                color: var(--primary);
                font-weight: 700;
            }
            
            .logout-btn {
                padding: 6px 12px;
                border-radius: 6px;
                border: none;
                background: var(--bg-card);
                color: var(--text-secondary);
                font-size: 11px;
                font-weight: 400;
                cursor: pointer;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                text-decoration: none;
                display: inline-block;
            }
            
            .logout-btn:hover {
                background: var(--bg-elevated);
                color: var(--text-primary);
                transform: translateY(-1px);
            }
            
            .container {
                background: var(--bg-card);
                border-radius: 10px;
                padding: 20px 24px;
                box-shadow: var(--shadow-lg);
                border: 1px solid var(--border);
                margin-bottom: 12px;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .container:hover {
                box-shadow: 0 6px 24px rgba(0, 0, 0, 0.9);
                border-color: rgba(187, 134, 252, 0.25);
            }
            
            h1 {
                font-family: 'Space Mono', monospace;
                font-size: 20px;
                font-weight: 700;
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 20px;
                text-align: center;
                user-select: none;
                letter-spacing: 0px;
            }
            
            h1::before {
                content: '$ ';
                color: var(--primary);
            }
            
            h2 {
                font-size: 15px;
                font-weight: 700;
                color: var(--text-primary);
                margin-bottom: 16px;
            }
            
            h2::before {
                content: '# ';
                color: var(--primary);
            }
            
            form {
                display: flex;
                flex-direction: column;
                width: 100%;
                margin-bottom: 16px;
            }
            
            input[type="file"] {
                width: 100%;
                padding: 10px;
                margin-bottom: 10px;
                border-radius: 8px;
                border: 2px dashed var(--border);
                background: var(--bg-elevated);
                color: var(--text-primary);
                cursor: pointer;
                transition: all 0.2s ease;
                font-family: 'Space Mono', monospace;
                font-size: 11px;
            }
            
            input[type="file"]:hover {
                border-color: var(--primary);
                background: var(--bg-card);
            }
            
            input[type="file"]::file-selector-button {
                padding: 6px 12px;
                border-radius: 6px;
                border: none;
                background: var(--primary);
                color: var(--text-primary);
                cursor: pointer;
                font-weight: 400;
                margin-right: 10px;
                transition: all 0.2s ease;
                font-family: 'Space Mono', monospace;
                font-size: 11px;
            }
            
            input[type="file"]::file-selector-button:hover {
                background: var(--primary-dark);
                transform: translateY(-1px);
            }
            
            input[type="file"]::file-selector-button::before {
                content: '> ';
            }
            
            .styled-btn, input[type="submit"] {
                width: 100%;
                padding: 10px 16px;
                border-radius: 8px;
                border: none;
                font-size: 12px;
                font-weight: 400;
                cursor: pointer;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                font-family: 'Space Mono', monospace;
                position: relative;
                overflow: hidden;
            }
            
            .primary-btn, input[type="submit"] {
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                color: var(--text-primary);
            }
            
            .primary-btn:hover, input[type="submit"]:hover {
                transform: translateY(-2px);
            }
            
            .primary-btn:active, input[type="submit"]:active {
                transform: translateY(0);
            }
            
            .styled-input {
                width: 100%;
                padding: 10px 12px;
                margin-bottom: 12px;
                border-radius: 8px;
                border: 1px solid var(--border);
                background: var(--bg-elevated);
                color: var(--text-primary);
                font-size: 11px;
                font-family: 'Space Mono', monospace;
                transition: all 0.2s ease;
            }
            
            .styled-input:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(187, 134, 252, 0.1);
            }
            
            .styled-input::placeholder {
                color: var(--text-secondary);
            }
            
            .guide {
                text-align: center;
                margin-bottom: 16px;
                color: var(--text-secondary);
                line-height: 1.5;
            }
            
            .guide p {
                margin-bottom: 4px;
                font-size: 11px;
            }
            
            .guide p:first-child {
                font-size: 11px;
                color: var(--text-primary);
                margin-bottom: 8px;
            }
            
            .guide p:first-child::before {
                content: '// ';
                color: var(--primary);
                font-weight: 700;
            }
            
            .highlight {
                color: var(--primary-light);
                font-weight: 700;
            }
            
            .links {
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 6px;
                flex-wrap: wrap;
            }
            
            .links a {
                color: var(--primary);
                text-decoration: none;
                font-size: 11px;
                font-weight: 400;
                padding: 4px 8px;
                border-radius: 6px;
                transition: all 0.2s ease;
            }
            
            .links a::before {
                content: '[';
                color: var(--text-secondary);
                margin-right: 2px;
            }
            
            .links a::after {
                content: ']';
                color: var(--text-secondary);
                margin-left: 2px;
            }
            
            .links a:hover {
                background: var(--bg-elevated);
                color: var(--primary-light);
            }
            
            .separator {
                color: var(--text-secondary);
                user-select: none;
            }
            
            .admin-panel .container {
                animation: fadeIn 0.5s ease-out 0.1s both;
            }
            
            input[type="checkbox"] {
                position: absolute;
                opacity: 0;
            }
            
            input[type="checkbox"] + span {
                position: relative;
                padding-left: 26px;
                cursor: pointer;
                display: inline-block;
                user-select: none;
                color: var(--text-secondary);
                font-size: 11px;
            }
            
            input[type="checkbox"] + span:before {
                content: '';
                position: absolute;
                left: 0;
                top: -1px;
                width: 16px;
                height: 16px;
                border: 2px solid var(--border);
                border-radius: 4px;
                background: var(--bg-elevated);
                transition: all 0.2s ease;
            }
            
            input[type="checkbox"]:checked + span {
                color: var(--text-primary);
            }
            
            input[type="checkbox"]:checked + span:before {
                background: var(--primary);
                border-color: var(--primary);
            }
            
            input[type="checkbox"] + span:after {
                content: '';
                position: absolute;
                top: 2px;
                left: 6px;
                width: 4px;
                height: 8px;
                border: solid var(--text-primary);
                border-width: 0 2px 2px 0;
                transform: rotate(45deg);
                opacity: 0;
                transition: opacity 0.2s ease;
            }
            
            input[type="checkbox"]:checked + span:after {
                opacity: 1;
            }
            
            .btn-container {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .btn-container .styled-input {
                margin-bottom: 0;
                flex: 1;
            }
            
            .icon-btn {
                padding: 10px;
                border-radius: 8px;
                border: none;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                min-width: 38px;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .icon-btn.primary-btn {
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            }
            
            .icon-btn:hover {
                transform: translateY(-2px);
            }
            
            .icon {
                fill: var(--text-primary);
                width: 16px;
                height: 16px;
            }
            
            @media (max-width: 600px) {
                .container {
                    padding: 16px;
                }
                
                h1 {
                    font-size: 18px;
                }
                
                .user-info span {
                    display: none;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <div class="header-bar">
                <div class="user-info">
                    <span>$username</span>
                </div>
                <a href="$logout_url" class="logout-btn">logout</a>
            </div>
            
            <div class="container">
                <h1>zentimine.xyz</h1>
                <form method="post" enctype="multipart/form-data" id="uploadForm">
                    <input type="file" name="file" id="file" />
                    <input type="hidden" name="formatted" value="true" />
                    <input type="submit" value="upload file"/>
                </form>
                <p id="errorMessage" style="color: #cf6679; font-size: 11px; margin-top: 8px; min-height: 16px;"></p>
                <div class="guide">
                    <p>select a file and upload</p>
                    <p>max filesize: <span class="highlight">$max_size mib</span></p>
                    <p>files kept for maximum: <span class="highlight">$max_age</span></p>
                    $warning
                </div>
                <div class="links">
                    <a href="$sharex_url">sharex config</a>
                    <span class="separator">•</span>
                    <a href="https://github.com/Z1xus/single_php_filehost">source</a>
                    <span class="separator">•</span>
                    <a href="https://z1x.us">contact</a>
                </div>
            </div>
            
            <div class="admin-panel">
                $adminPanel
            </div>
        </div>
        
        <script>
            const maxFileSize = $max_size * 1024 * 1024;
            const uploadForm = document.getElementById('uploadForm');
            const fileInput = document.getElementById('file');
            const errorMessage = document.getElementById('errorMessage');
            
            uploadForm.addEventListener('submit', function(e) {
                errorMessage.textContent = '';
                
                if (!fileInput.files.length) {
                    e.preventDefault();
                    errorMessage.textContent = '// please select a file';
                    return false;
                }
                
                const file = fileInput.files[0];
                
                if (file.size > maxFileSize) {
                    e.preventDefault();
                    errorMessage.textContent = '// file too large (max $max_size mib)';
                    return false;
                }
                
                if (file.size === 0) {
                    e.preventDefault();
                    errorMessage.textContent = '// file is empty';
                    return false;
                }
            });
        </script>
    </body>
    </html>
    EOT;
}

function generateToken($length = 64) {
    return bin2hex(random_bytes($length / 2));
}

$newUsernameValue = isset($_POST['new_username']) ? htmlspecialchars($_POST['new_username'], ENT_QUOTES, 'UTF-8') : null;
$newPasswordValue = $_POST['new_password'] ?? null;
$isAdminValue = isset($_POST['isAdmin']) ? filter_var($_POST['isAdmin'], FILTER_VALIDATE_BOOLEAN) : false;

if (isset($newUsernameValue) && isset($newPasswordValue)) {
    $newUsername = $newUsernameValue;
    $newPassword = $newPasswordValue;
    $isAdmin = isset($_POST['isAdmin']) ? filter_var($_POST['isAdmin'], FILTER_VALIDATE_BOOLEAN) : false;

    if (!empty($newUsername) && !empty($newPassword)) {
        if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }
        
        $currentUser = $collection->findOne(['username' => $_SESSION['username']]);
        if ($currentUser === null || $currentUser['isAdmin'] !== true) {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }
        
        if (userCreate($newUsername, $newPassword, $isAdmin, $collection)) {
            $redirectURL = str_replace('index.php', '', $_SERVER['REQUEST_URI']);
            header("Location: " . $redirectURL);
            exit;
        }
    }
}

// decide what to do, based on POST parameters etc.
if (isset($_FILES['file']['name']) &&
    isset($_FILES['file']['tmp_name']) &&
    is_uploaded_file($_FILES['file']['tmp_name']))
{
    //file was uploaded, store it
    $formatted = isset($_SERVER['HTTP_TOKEN']) ? false : isset($_REQUEST['formatted']);
    store_file($_FILES['file']['name'],
              $_FILES['file']['tmp_name'],
              $formatted);
}
else if (isset($_GET['sharex']))
{
    send_sharex_config();
}
else if (isset($_GET['hupl']))
{
    send_hupl_config();
}
else if ($argv[1] ?? null === 'purge')
{
    purge_files();
}
else
{
    check_config();
    print_index();
}
