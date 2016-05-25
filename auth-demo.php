<!doctype html>
<html lang="de">
	<head>
		<meta charset="utf-8">
	  <meta name="author" content="Herbert Braun">
		<title>2-Faktor-Authentifizierung</title>
		<link rel="stylesheet" href="style.css">
	</head>
	<body>
		<h1>2-Faktor-Authentifizierung</h1>

<?php
error_reporting(E_ALL);

function connect_db()	{
	$hostname = "localhost";
	$databasename = "2factorauth";
	$username = "ich";
	$password = "starkespasswort";
	$connection = new mysqli($hostname, $username, $password, $databasename);
	if (mysqli_connect_errno())
		printf("Keine Verbindung zur Datenbank: %s\n", mysqli_connect_error()) && exit;
	$connection->set_charset("utf8");
	return $connection;
}

function display_totp_form($userid, $login, $pw) {
	// zeigt das Formular zur Eingabe des TOTP-Codes an
?>
		<h2>2-Faktor-Authentifizierung</h2>
		<form action="<?php echo $_SERVER['PHP_SELF']; ?>?action=totp" method="POST">
			<input type="hidden" name="userid" value="<?php echo $userid; ?>">
			<input type="hidden" name="login" value="<?php echo $login; ?>">
			<input type="hidden" name="pw" value="<?php echo $pw; ?>">
			<label>
				<span>Anmelde-Code</span>
				<input type="text" name="totp" autofocus>
			</label>
			<input type="submit" value="Abschicken!">
		</form>
<?php
}

$appname = '2-Faktor-Demo';
$domain = 'woerter.de';

if (empty($_GET['action'])) {
	// Keine action -> Startseite mit Login-Formular und Registrierungslink
?>
		<h2>Anmeldung</h2>
		<form action="<?php echo $_SERVER['PHP_SELF']; ?>?action=login_confirm" method="POST">
			<label>
				<span>Login</span>
				<input type="text" name="login" autofocus>
			</label>
			<label>
				<span>Passwort</span>
				<input type="password" name="password">
			</label>
			<input type="submit" value="Abschicken!">
		</form>

		<p>Sie sind noch nicht registriert? <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=register" title="Registrieren">Bitte hier entlang ...</a></p>

<?php
} elseif ($_GET['action'] == 'register') {
	// Registrierung -> Eingabeformular
?>
		<h2>Registrierung</h2>
		<form action="<?php echo $_SERVER['PHP_SELF']; ?>?action=register_confirm" method="POST">
			<label>
				<span>Ihr Login-Name</span>
				<input type="text" name="login" autofocus>
			</label>
			<label>
				<span>Ihr Passwort</span>
				<input type="text" name="password">
			</label>
			<input type="submit" value="Registrieren!">
		</form>

<?php
} elseif ($_GET['action'] == 'register_confirm') {
	// Registrierungsbestätigung -> Secret erzeugen, Daten speichern, QR-Code anzeigen
	// ACHTUNG, DEMO-APP - KEINE SICHERHEITSÜBERPRÜFUNG DER EINGABEN!
	echo '<h2>Ihre Anmeldedaten</h2>';
	if (!$_POST['login'] || !$_POST['password']) {
		echo '<p>Login oder Passwort fehlen.</p>';
		exit;
	}
	$db = connect_db();
	include_once('lib/GoogleAuthenticator.php');
	$g = new GoogleAuthenticator();
	$secret = $g->generateSecret();

/*
	// NUR ZUM TESTEN!
	$stmt = $db->prepare('DELETE FROM users WHERE login = ?');
	$stmt->bind_param('s', $_POST['login']);
	$stmt->execute();
	// NUR ZUM TESTEN ENDE
*/

	$stmt = $db->prepare('INSERT users (login, password, secret) VALUES (?, MD5(?), ?)') or die('Problem beim Anlegen eines neuen Users. Ist die Datenbank eingerichtet?');
	$stmt->bind_param('sss', $_POST['login'], $_POST['password'], $secret);
	$stmt->execute();
	$qrcodeURL = $g->getURL($_POST['login'], $domain, $secret, $appname);

	echo '<p>Der streng geheime Schlüssel <b>' . $appname . '</b> für den Benutzer <b>' . $_POST['login'] . '@' . $domain . '</b> mit dem Label lautet: <code>' . $secret . '</code></p>';
	echo '<p>Bitte scannen Sie den folgenden QR-Code mit Google Authenticator oder einer ähnlichen App ein:</p>';
	$imageData = base64_encode(file_get_contents($qrcodeURL));
	echo '<img src="data:image/png;base64,' . $imageData . '" alt="QR-Code">';
	echo '<!--' . $qrcodeURL . '-->';
	echo '<p><a href="' . $_SERVER['PHP_SELF'] . '">Zurück zur Anmeldung</a></p>';

} elseif ($_GET['action'] == 'login_confirm') {
	// Nach dem Login -> Gleiche Daten mit Registrierungsdatenbank ab und zeig die Eingabemaske für TOTP
	echo '<h2>Ihre Anmeldung</h2>';
	//echo '<pre>'; var_dump($_POST); echo '</pre>';
	if (!$login = $_POST['login']) die('Login-Name fehlt');
	if (!$pw = $_POST['password']) die('Passwort fehlt');
	$db = connect_db();
	$stmt = $db->prepare('SELECT id FROM users WHERE login = ? AND password = MD5(?) LIMIT 1');
	$stmt->bind_param('ss', $login, $pw);
	$stmt->execute();
	$stmt->bind_result($userid);
	$stmt->fetch();
	if (!$userid) die('Login oder Passwort waren falsch');
	echo '<p>Hallo, ' . $login . '! Bist du\'s wirklich?</p>';
	display_totp_form($userid, $login, $pw);

} elseif ($_GET['action'] == 'totp') {
	// überprüft den eingegebenen TOTP-Code
	if (!($userid = intval($_POST['userid']))) die('Keine User-ID');
	if (!($login = $_POST['login'])) die('Kein Login');
	if (!($pw = $_POST['pw'])) die('Kein Passwort');
	if (!$_POST['totp']) die('Kein Einmal-Passwort');
	$db = connect_db();
	$stmt = $db->prepare('SELECT secret FROM users WHERE id = ? AND login = ? AND password = MD5(?) LIMIT 1');
	$stmt->bind_param('iss', $userid, $login, $pw);
	$stmt->execute();
	$stmt->bind_result($secret);
	$stmt->fetch();
	if (!$secret) die('User konnte nicht gefunden werden');
	include_once('lib/GoogleAuthenticator.php');
	$g = new GoogleAuthenticator();
	if ($g->checkCode($secret, $_POST['totp'])) {
		echo '<p>Jawollja! Du bist es wirklich, ' . $login . '!</p>';
	} else {
		echo '<p>Falsch. Wie heißt das Zauberwort?</p>';
		display_totp_form($userid, $login, $pw);
	}

} else {
	die('WTF?');
}
?>
	</body>
</html>