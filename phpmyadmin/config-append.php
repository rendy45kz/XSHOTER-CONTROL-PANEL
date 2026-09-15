// XSHOTER_CONTROL_SSO_BEGIN
$xcSid = $_COOKIE['XshoterPma'] ?? '';
if (preg_match('/^[a-f0-9]{64}$/', $xcSid)) {
    $xcFile = '/run/xshoter-control/pma-sessions/' . $xcSid . '.json';
    if (is_readable($xcFile)) {
        $xcData = json_decode((string) file_get_contents($xcFile), true);
        if (is_array($xcData) && isset($xcData['database'], $xcData['expires']) && (int)$xcData['expires'] >= time() && preg_match('/^[A-Za-z0-9_]{1,64}$/', (string)$xcData['database'])) {
            $xcDb = (string)$xcData['database'];
            foreach (array_keys($cfg['Servers'] ?? []) as $xcI) {
                if (!is_int($xcI) && !ctype_digit((string)$xcI)) continue;
                $cfg['Servers'][$xcI]['auth_type'] = 'config';
                $cfg['Servers'][$xcI]['user'] = 'xshoterpma';
                $cfg['Servers'][$xcI]['password'] = '';
                $cfg['Servers'][$xcI]['AllowNoPassword'] = true;
                $cfg['Servers'][$xcI]['only_db'] = $xcDb;
                $cfg['Servers'][$xcI]['LogoutURL'] = '/phpmyadmin/xshoter-sso.php?logout=1';
            }
        }
    }
}
// XSHOTER_CONTROL_SSO_END
