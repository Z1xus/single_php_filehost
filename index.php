<?php
require 'vendor/autoload.php';

use MongoDB\Client;
use MongoDB\Driver\ServerApi;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

session_start();

$is_file_upload = $_SERVER['REQUEST_METHOD'] === 'POST';

//connect to the MongoDB database
$uri = $_ENV['MONGODB_URI'];
$apiVersion = new ServerApi(ServerApi::V1);
$client = new Client($uri, [], ['serverApi' => $apiVersion]);
$collection = $client->selectCollection($_ENV['DB_NAME'], $_ENV['COLLECTION_NAME']);

if (isset($_SERVER['HTTP_TOKEN'])) {
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

function outputHTMLHeader() {
    echo <<<EOT
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Filehost</title>
    <meta name="description" content="Minimalistic service for sharing temporary files." />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
EOT;
}

$usernameValue = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$passwordValue = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

$errorMessage = '';
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
            $errorMessage = "Invalid credentials";
        }
    } else {
        $errorMessage = "The fields cannot be empty";
    }
}

if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    outputHTMLHeader();
    echo <<<EOT
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #121212;
            font-family: Arial, sans-serif;
            color: #fff;
        }
        form {
            background-color: #1e1e1e;
            padding: 20px;
            border-radius: 5px;
            width: 90%;
            max-width: 300px;
            box-shadow: 0px 0px 10px 0px rgba(255,255,255,0.1);
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
            border: 1px solid #ccc;
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
            margin-bottom: 20px;
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
        <div class="error">$errorMessage</div>
        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="$usernameValue">
        <label for="password">Password</label>
        <div style="position: relative;">
            <input type="password" id="password" name="password" value="$passwordValue">
            <i id="togglePassword" class="fas fa-eye eye-icon" onclick="togglePasswordVisibility()"></i>
        </div>
        <input type="submit" value="Login">
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
    </script>
    EOT;
    exit;
}

class CONFIG
{
    const MAX_FILESIZE = 512; //max. filesize in MiB
    const MAX_FILEAGE = 180; //max. age of files in days
    const MIN_FILEAGE = 31; //min. age of files in days
    const DECAY_EXP = 2; //high values penalise larger files more

    const UPLOAD_TIMEOUT = 5*60; //max. time an upload can take before it times out
    const ID_LENGTH = 3; //length of the random file ID
    const STORE_PATH = 'files/'; //directory to store uploaded files in
    const LOG_PATH = null; //path to log uploads + resulting links to
    const DOWNLOAD_PATH = '%s'; //the path part of the download url. %s = placeholder for filename
    const MAX_EXT_LEN = 7; //max. length for file extensions
    const EXTERNAL_HOOK = null; //external program to call for each upload
    const AUTO_FILE_EXT = false; //automatically try to detect file extension for files that have none

    const ADMIN_EMAIL = 'admin@example.com';  //address for inquiries

    public static function SITE_URL() : string
    {
        $proto = ($_SERVER['HTTPS'] ?? 'off') == 'on' ? 'https' : 'http';
        return "$proto://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
    }
};


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

    $original_name = pathinfo($name, PATHINFO_FILENAME);
    $ext = ext_by_path($name);
    $target_file = CONFIG::STORE_PATH . $name;

    //if file with the same name exists, append a random string to the name
    if (file_exists($target_file)) {
        $basename = $original_name . '_' . rnd_str(5) . '.' . $ext;
        $target_file = CONFIG::STORE_PATH . $basename;
    } else {
        $basename = $name;
    }

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
    $site_url = CONFIG::SITE_URL();
    $sharex_url = $site_url.'?sharex';
    $hupl_url = $site_url.'?hupl';
    $decay = CONFIG::DECAY_EXP;
    $min_age = CONFIG::MIN_FILEAGE;
    $max_size = CONFIG::MAX_FILESIZE;
    $max_age = CONFIG::MAX_FILEAGE;
    $mail = CONFIG::ADMIN_EMAIL;

echo <<<EOT
<body>
<pre>
 === How To Upload ===
You can upload files to this site via a simple HTTP POST, e.g. using curl:
curl -F "file=@/path/to/your/file.jpg" $site_url

Or if you want to pipe to curl *and* have a file extension, add a "filename":
echo "hello" | curl -F "file=@-;filename=.txt" $site_url

On Windows, you can use <a href="https://getsharex.com/">ShareX</a> and import <a href="$sharex_url">this</a> custom uploader.
On Android, you can use an app called <a href="https://github.com/Rouji/Hupl">Hupl</a> with <a href="$hupl_url">this</a> uploader.


Or simply choose a file and click "Upload" below:
(Hint: If you're lucky, your browser may support drag-and-drop onto the file 
selection input.)
</pre>
<form id="frm" method="post" enctype="multipart/form-data">
<input type="file" name="file" id="file" />
<input type="hidden" name="formatted" value="true" />
<input type="submit" value="Upload"/>
</form>
<pre>


 === File Sizes etc. ===
The maximum allowed file size is $max_size MiB.

Files are kept for a minimum of $min_age, and a maximum of $max_age Days.

How long a file is kept depends on its size. Larger files are deleted earlier 
than small ones. This relation is non-linear and skewed in favour of small 
files.

The exact formula for determining the maximum age for a file is:

MIN_AGE + (MAX_AGE - MIN_AGE) * (1-(FILE_SIZE/MAX_SIZE))^$decay


 === Source ===
The PHP script used to provide this service is open source and available on 
<a href="https://github.com/Z1xus/single_php_filehost">GitHub</a>
(This is a fork of <a href="https://github.com/Rouji/single_php_filehost">the original single_php_filehost </a>)


 === Contact ===
If you want to report abuse of this service, or have any other inquiries, 
please write an email to $mail
</pre>
</body>
</html>
EOT;
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
    outputHTMLHeader();
    print_index();
}
