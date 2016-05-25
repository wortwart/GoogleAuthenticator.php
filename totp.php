<!doctype html>
<html lang="de">
	<head>
		<meta charset="utf-8"/>
	  <meta name="author" content="Herbert Braun"/>
		<title>TOTP-Berechnung</title>
	</head>
	<body>
		<h1>TOTP-Berechnung</h1>

		<p>Dieses Skript berechnet aus dem Base32-kodierten String "Hallo,Welt" ein 30 Sekunden lang gültiges Einmal-Passwort. Es benötigt eine externe Bibliothek (FixedByteNotation.php) für die Base32-Konvertierung.</p>

		<pre>
			<?php
			$mytime = floor(time() / 30);
			$totpLength = 6; // Länge des TOTP
			$mysecret = 'JBQWY3DPFRLWK3DU'; // "Hallo,Welt"
			echo "\n", '$mysecret: '; var_dump($mysecret);

			include_once('lib/FixedByteNotation.php');
			$base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', TRUE, TRUE);
			$mysecret = $base32->decode($mysecret);
			$mytime = pack("N", $mytime);
			$mytime = str_pad($mytime, 8, chr(0), STR_PAD_LEFT);
			$sha1Hash = hash_hmac('sha1', $mytime, $mysecret, true);
			echo "\n", '$sha1Hash: '; var_dump(unpack('H*', $sha1Hash));
			$offset = ord(substr($sha1Hash, -1));
			echo "\n", '$offset: '; var_dump($offset);
			$offset = $offset & 0xF;
			echo "\n", 'unpacked $offset: '; var_dump(unpack('H*', $offset));
			$input = substr($sha1Hash, $offset, strlen($sha1Hash) - $offset);
			echo "\n", '$input: '; var_dump(unpack('H*', $input));
			$truncatedHash = unpack("N", substr($input, 0, 4))[1];
			echo "\n", '$truncatedHash: '; var_dump($truncatedHash);
			$truncatedHash &= 0x7FFFFFFF;
			echo "\n", 'unsigned $truncatedHash: '; var_dump($truncatedHash);
			$pinModulo = pow(10, $totpLength);
			echo "\n", '$pinModulo: '; var_dump($pinModulo);
			$pinValue = str_pad($truncatedHash % $pinModulo, $totpLength, "0", STR_PAD_LEFT);
			echo "\n", '$pinValue: '; var_dump($pinValue);
			?>
		</pre>
	</body>
</html>
