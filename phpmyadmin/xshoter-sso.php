<?php
declare(strict_types=1);
$base = '/run/xshoter-control';
$tokenDir = $base . '/pma-tokens';
$sessionDir = $base . '/pma-sessions';
$cookie = 'XshoterPma';
function deny(string $message, int $code = 403): never {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}
if (isset($_GET['logout'])) {
    $sid = $_COOKIE[$cookie] ?? '';
    if (preg_match('/^[a-f0-9]{64}$/', $sid)) @unlink($sessionDir . '/' . $sid . '.json');
    setcookie($cookie, '', ['expires'=>1,'path'=>'/phpmyadmin/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
    header('Location: /phpmyadmin/');
    exit;
}
$token = $_GET['token'] ?? '';
if (!preg_match('/^[a-f0-9]{64}$/', $token)) deny('Invalid SSO token');
$file = $tokenDir . '/' . $token . '.json';
if (!is_readable($file)) deny('SSO token not found or already used');
$data = json_decode((string)file_get_contents($file), true);
@unlink($file);
if (!is_array($data) || !isset($data['database'], $data['expires'])) deny('Invalid SSO token');
$db = (string)$data['database'];
if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $db) || (int)$data['expires'] < time()) deny('SSO token expired');
$sid = bin2hex(random_bytes(32));
$session = json_encode(['database'=>$db,'expires'=>time()+43200], JSON_UNESCAPED_SLASHES);
if ($session === false || file_put_contents($sessionDir . '/' . $sid . '.json', $session, LOCK_EX) === false) deny('Unable to create SSO session', 500);
@chmod($sessionDir . '/' . $sid . '.json', 0640);
setcookie($cookie, $sid, ['expires'=>time()+43200,'path'=>'/phpmyadmin/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
header('Location: /phpmyadmin/index.php?db=' . rawurlencode($db));
exit;
