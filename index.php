<?php
require 'vendor/autoload.php';

use MongoDB\Client;
use MongoDB\Driver\ServerApi;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

session_start();

$is_file_upload = $_SERVER['REQUEST_METHOD'] === 'POST';

$uri = $_ENV['MONGODB_URI'];
$apiVersion = new ServerApi(ServerApi::V1);
$client = new Client($uri, [], ['serverApi' => $apiVersion]);
$collection = $client->selectCollection($_ENV['DB_NAME'], $_ENV['COLLECTION_NAME']);

if (isset($_SERVER['HTTP_TOKEN'])) {
    validateToken($collection);
}

$usernameValue = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$passwordValue = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

$inviteCodeValue = filter_input(INPUT_POST, 'invite_code', FILTER_SANITIZE_STRING);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($inviteCodeValue)) {
    $errorMessage = userRegister($usernameValue, $passwordValue, $inviteCodeValue, $collection);
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
    const MAX_FILEAGE = 31; //max. age of files in days
    const MIN_FILEAGE = 7; //min. age of files in days
    const DECAY_EXP = 2; //high values penalise larger files more

    const UPLOAD_TIMEOUT = 5*60; //max. time an upload can take before it times out
    const ID_LENGTH = 3; //length of the random file ID
    const STORE_PATH = 'files/'; //directory to store uploaded files in
    const LOG_PATH = null; //path to log uploads + resulting links to
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
    $token = filter_var($_SERVER['HTTP_TOKEN'], FILTER_SANITIZE_STRING);
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
            $user = $collection->findOne(['username' => $username]);

            if ($user !== null && password_verify($password, $user['password'])) {
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $user['username'];
                $_SESSION['token'] = $user['token'];
            } else {
                return "Invalid credentials";
            }
        } else {
            return "The fields cannot be empty";
        }
    }
}

function userRegister($usernameValue, $passwordValue, $inviteCodeValue, $collection) {
    if (isset($usernameValue) && isset($passwordValue) && isset($inviteCodeValue)) {
        $username = $usernameValue;
        $password = $passwordValue;
        $inviteCode = $inviteCodeValue;

        if (!empty($username) && !empty($password) && !empty($inviteCode)) {
            $inviteCodeEntry = $collection->findOne(['inviteCode' => $inviteCode]);

            if ($inviteCodeEntry !== null && $inviteCodeEntry['isValid'] === true) {
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $token = generateToken(64);

                $collection->insertOne([
                    'username' => $username,
                    'password' => $hashedPassword,
                    'isAdmin' => false,
                    'token' => $token,
                ]);

                $collection->updateOne(
                    ['inviteCode' => $inviteCode],
                    ['$set' => ['isValid' => false]]
                );

                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['token'] = $token;
            } else {
                return "Invalid invite code";
            }
        } else {
            return "All fields must be filled";
        }
    }
}

function userCreate($usernameValue, $passwordValue, $isAdmin, $collection) {
    $hashedPassword = password_hash($passwordValue, PASSWORD_DEFAULT);
    $token = generateToken(64);

    $collection->insertOne([
        'username' => $usernameValue,
        'password' => $hashedPassword,
        'isAdmin' => $isAdmin,
        'token' => $token,
    ]);
}

function serveLoginPage($errorMessage, $usernameValue, $passwordValue) {
    html_header();
    $headerText = "Login";
    echo <<<EOT
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100svh;
            margin: 0;
            background-color: #121212;
            font-family: Arial, sans-serif;
            color: #fff;
        }
        form {
            background-color: #1e1e1e;
            padding: 1em;
            border-radius: 5px;
            width: 70%;
            max-width: 300px;
            margin-left: auto;
            margin-right: auto;
            box-shadow: 0px 0px 10px 0px rgba(255,255,255,0.1);
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 1em;
            border-radius: 5px;
            border: 1px solid #6200ee;
            color: #fff;
            background-color: #1e1e1e;
            box-sizing: border-box;
        }
        input[type="submit"] {
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            border: 0;
            color: #fff;
            background-color: #6200ee;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #3700b3;
        }
        .error {
            color: #cf6679;
            margin-bottom: 1em;
        }
        .eye-icon {
            position: absolute;
            margin-left: -30px;
            margin-top: 12px;
            color: #ccc;
            cursor: pointer;
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" />
    <form method="post">
        <h2 id="formHeader" style="text-align: center; color: #fff; margin-bottom: 1em;">$headerText</h2>
        <input type="text" id="username" name="username" value="$usernameValue" placeholder="Username" style="margin-bottom: 1em;">
        <div style="position: relative;">
            <div>
                <input type="password" id="password" name="password" value="$passwordValue" placeholder="Password" style="margin-bottom: 1em;">
                <i id="togglePassword" class="fas fa-eye eye-icon" onclick="togglePasswordVisibility()"></i>
            </div>
        </div>
        <div class="error">$errorMessage</div>
        <input type="submit" value="Login">
        <a href="#" id="toggleForm" onclick="toggleForms()" style="display: block; text-align: right; margin-top: 10px; color: #9959f4; text-decoration: none;">Register</a>
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
        let inviteCodeFieldHTML = '<div id="inviteCodeContainer" style="position: relative;"><input type="text" id="invite_code" name="invite_code" placeholder="Invite Code" style="margin-bottom: 1em;"></div>';

        function toggleForms() {
            const form = document.querySelector('form');
            const toggleFormLink = document.getElementById('toggleForm');
            const passwordField = form.querySelector('#password').parentElement;
            const formHeader = document.getElementById('formHeader');
            if (isLoginForm) {
                passwordField.insertAdjacentHTML('afterend', inviteCodeFieldHTML);
                toggleFormLink.textContent = 'Login';
                formHeader.textContent = 'Register';
                form.querySelector('input[type="submit"]').value = 'Register';
            } else {
                form.querySelector('#inviteCodeContainer').remove();
                toggleFormLink.textContent = 'Register';
                formHeader.textContent = 'Login';
                form.querySelector('input[type="submit"]').value = 'Login';
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
        $out .= $chars[mt_rand(0,$max_idx)];
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

// store an uploaded file, given its name and temporary path (e.g. values straight out of $_FILES)
// files are stored wit a randomised name, but with their original extension
//
// $name: original filename
// $tmpfile: temporary path of uploaded file
// $formatted: set to true to display formatted message instead of bare link
function store_file(string $name, string $tmpfile, bool $formatted = false) : void
{
    //create folder, if it doesn't exist
    if (!file_exists(CONFIG::STORE_PATH))
    {
        mkdir(CONFIG::STORE_PATH, 0750, true); //TODO: error handling
    }

    //check file size
    $size = filesize($tmpfile);
    if ($size > CONFIG::MAX_FILESIZE * 1024 * 1024)
    {
        header('HTTP/1.0 413 Payload Too Large');
        print("Error 413: Max File Size ({CONFIG::MAX_FILESIZE} MiB) Exceeded\n");
        return;
    }
    if ($size == 0)
    {
        header('HTTP/1.0 400 Bad Request');
        print('Error 400: Uploaded file is empty\n');
        return;
    }

    $ext = ext_by_path($name);
    $randomPrefix = rnd_str(5);
    $basename = $randomPrefix.'_'.$name;
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
        print("<pre>Access your file here: <a href=\"$url\">$url</a></pre>");
    }
    else
    {
        print("$url\n");
    }

    // log uploader's IP, original filename, etc.
    if (CONFIG::LOG_PATH)
    {
        file_put_contents(
            CONFIG::LOG_PATH,
            implode("\t", array(
                date('c'),
                $_SERVER['REMOTE_ADDR'],
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
  "Name": "$name",
  "DestinationType": "ImageUploader, FileUploader",
  "RequestType": "POST",
  "RequestURL": "$site_url",
  "FileFormName": "file",
  "ResponseType": "Text",
  "Headers": {
    "Token": "$token"
  }
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
    $decay = CONFIG::DECAY_EXP;
    $min_age = CONFIG::MIN_FILEAGE;
    $max_size = CONFIG::MAX_FILESIZE;
    $max_age = CONFIG::MAX_FILEAGE;
    $mail = CONFIG::ADMIN_EMAIL;

    $adminPanel = '';
    if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
        $user = $GLOBALS['collection']->findOne(['username' => $_SESSION['username']]);
        
        if ($user !== null && $user['isAdmin'] === true) {
            $adminPanel = <<<EOT
            <div class="container admin-panel">
                <h2 style="margin-bottom: 1em; user-select: none;">Admin Panel</h2>
                <form method="post" autocomplete="off">
                    <input class="styled-input" type="text" id="new_username" name="new_username" placeholder="Username" autocomplete="off">
                    <input class="styled-input" type="password" id="new_password" name="new_password" placeholder="Password" autocomplete="off">
                    <p style="padding-bottom: 0.2em;">
                      <label>
                        <input type="checkbox" id="isAdmin" name="isAdmin" />
                        <span>Administrator</span>
                      </label>
                    </p>
                    <input class="styled-input styled-submit" type="submit" value="Create User">
                </form>
            </div>
            EOT;
        }
    }

    echo <<<EOT
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Zentimine.xyz</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
        <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@300&display=swap" rel="stylesheet" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background-color: #121212;
                font-family: Arial, sans-serif;
                color: #fff;
            }
            .wrapper {
                padding: 1.2em;
                margin: 1em; /* Add margin */
                box-sizing: border-box;
            }
            .container {
                display: flex;
                flex-direction: column;
                align-items: center;
                background-color: #1e1e1e;
                padding: 1.3em;
                border-radius: 5px;
                box-shadow: 0px 0px 10px 0px rgba(255,255,255,0.1);
                width: 100%;
                max-width: 600px;
                box-sizing: border-box;
            }
            form {
                display: flex;
                flex-direction: column;
                align-items: center;
                width: 100%;
                max-width: 300px;
                margin-bottom: 2em;
            }
            input[type="file"], input[type="submit"] {
                width: 100%;
                padding: 10px;
                margin-bottom: 2em;
                border-radius: 5px;
                border: 1px solid #6200ee;
                color: #fff;
                background-color: #1e1e1e;
                box-sizing: border-box;
                cursor: pointer;
            }
            input[type="submit"] {
                background-color: #6200ee;
                margin-bottom: -4px;
                width: 100%;
                padding: 10px;
                border-radius: 5px;
                border: 0;
                color: #fff;
                background-color: #6200ee;
                cursor: pointer;
            }
            input[type="submit"]:hover {
                background-color: #3700b3;
            }
            .guide {
                text-align: center;
                margin-bottom: 1em;
            }
            .guide p {
                margin-bottom: 0.5em
            }
            .links {
                display: flex;
                justify-content: center;
                gap: 10px;
            }
            .links a {
                color: #fff;
                text-decoration: none;
            }
            .links a:hover {
                text-decoration: underline;
            }
            .admin-panel {
                margin-top: 2em;
                padding-bottom: 1em;
                position: relative;
            }
            .styled-input {
                width: 100%;
                padding: 10px;
                margin-bottom: 1em;
                border-radius: 5px;
                border: 1px solid #6200ee;
                color: #fff;
                background-color: #1e1e1e;
                box-sizing: border-box;
            }
            .styled-submit {
                background-color: #6200ee;
                cursor: pointer;
                margin-top: 1em;
            }
            .styled-submit:hover {
                background-color: #3700b3;
            }
            input[type="checkbox"] {
                position: absolute;
                opacity: 0;
            }
            input[type="checkbox"] + span {
                position: relative;
                padding-left: 35px;
                cursor: pointer;
                display: inline-block;
            }
            input[type="checkbox"] + span:before {
                content: '';
                position: absolute;
                left: 0;
                top: -3px;
                width: 20px;
                height: 20px;
                border: 2px solid #6200ee;
                border-radius: 3px;
                background-color: transparent;
                transition: all 0.3s ease-in-out;
            }
            input[type="checkbox"] + span:after {
                content: '';
                position: absolute;
                top: 1px;
                left: 8px;
                width: 5px;
                height: 10px;
                border: solid white;
                border-width: 0 3px 3px 0;
                transform: rotate(45deg);
                opacity: 0;
                transition: all 0.3s ease-in-out;
            }
            input[type="checkbox"]:checked + span:before {
                background-color: #6200ee;
            }
            input[type="checkbox"]:checked + span:after {
                opacity: 1;
            }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <div class="container">
                <h1 style="color: #a500d0; font-family: 'Roboto Mono', sans-serif; margin-bottom: 1em; user-select: none;">zentimine.xyz</h1>
                <form method="post" enctype="multipart/form-data">
                    <input type="file" name="file" id="file" />
                    <input type="hidden" name="formatted" value="true" />
                    <input type="submit" value="Upload"/>
                </form>
                <div class="guide">
                    <p>j select file and upload :p</p>
                    <p>max filesize: <span style="color:#b88cf7">$max_size mib</span></p>
                    <p>files are kept for a maximum of <span style="color:#b88cf7">$max_age days</span></>
                </div>
                <div class="links">
                    <a style="color: #9959f4;" href="$sharex_url">sharex config</a><span style="color:#b88cf7"> •</span>
                    <a style="color: #9959f4;" href="https://github.com/Z1xus/single_php_filehost">source</a><span style="color:#b88cf7"> •</span>
                    <a style="color: #9959f4;" href="https://z1xus.netlify.app/">contact</a>
                </div>
            </div>
            <div class="admin-panel">
                $adminPanel
            </div>
        </div>
    </body>
    </html>
    EOT;
}

function generateToken($length = 64) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

$newUsernameValue = filter_input(INPUT_POST, 'new_username', FILTER_SANITIZE_STRING);
$newPasswordValue = filter_input(INPUT_POST, 'new_password', FILTER_SANITIZE_STRING);
$isAdminValue = filter_input(INPUT_POST, 'isAdmin', FILTER_VALIDATE_BOOLEAN);

if (isset($newUsernameValue) && isset($newPasswordValue)) {
    $newUsername = $newUsernameValue;
    $newPassword = $newPasswordValue;
    $isAdmin = isset($_POST['isAdmin']) ? filter_var($_POST['isAdmin'], FILTER_VALIDATE_BOOLEAN) : false;

    if (!empty($newUsername) && !empty($newPassword)) {
        userCreate($newUsername, $newPassword, $isAdmin, $collection);

        $redirectURL = str_replace('index.php', '', $_SERVER['REQUEST_URI']);
        header("Location: " . $redirectURL);
        exit;
    }
}

// decide what to do, based on POST parameters etc.
if (isset($_FILES['file']['name']) &&
    isset($_FILES['file']['tmp_name']) &&
    is_uploaded_file($_FILES['file']['tmp_name']))
{
    //file was uploaded, store it
    $formatted = isset($_REQUEST['formatted']);
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
