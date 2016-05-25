<?php
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Fork by wortwart (Herbert Braun)

include_once("FixedByteNotation.php");

class GoogleAuthenticator {
	static $PASS_CODE_LENGTH = 6;
	static $PIN_MODULO;
	static $SECRET_LENGTH = 10;

	public function __construct() {
		self::$PIN_MODULO = pow(10, self::$PASS_CODE_LENGTH);
	}

	public function checkCode($secret, $code) {
		$time = floor(time() / 30);
		for ($i = -1; $i <= 1; $i++) {
			if ($this->getCode($secret,$time + $i) == $code) {
				return true;
			}
		}
		return false;
	}

	public function getCode($secret, $time = null) {
		if (!$time)
			$time = floor(time() / 30);
		$base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', TRUE, TRUE);
		$secret = $base32->decode($secret);

		$time = pack("N", $time);
		$time = str_pad($time, 8, chr(0), STR_PAD_LEFT);

		$hash = hash_hmac('sha1', $time, $secret, true);
		$offset = ord(substr($hash, -1));
		$offset = $offset & 0xF;

		$snippet = substr($hash, $offset, 4);
		$int32 = unpack("N", $snippet);
		$truncatedHash = $int32[1] & 0x7FFFFFFF;
		$pinValue = str_pad($truncatedHash % self::$PIN_MODULO, 6, "0", STR_PAD_LEFT);
		return $pinValue;
	}

	public function getUrl($user, $hostname, $secret, $appname = '', $issuer = '') {
		$encoder = "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=";
		if ($appname !== '') $appname = urlencode($appname) . ':%20';
		if ($issuer !== '') $issuer = '&issuer=' . urlencode($issuer);
		$encoderURL = sprintf( "%sotpauth://totp/%s%s@%s?secret=%s%s", $encoder, $appname, $user, $hostname, $secret, $issuer);
		return $encoderURL;
	}

	public function generateSecret() {
		$secret = "";
		for($i = 1;  $i<= self::$SECRET_LENGTH;$i++) {
			$c = rand(0,255);
			$secret .= pack("c", $c);
		}
		$base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', TRUE, TRUE);
		return  $base32->encode($secret);
	}

}
