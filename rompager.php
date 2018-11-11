<?php

function verComp($ver1, $ver2) {
	$v1 = explode(".", $ver1);
	$v2 = explode(".", $ver2);

	for ($i = 0; $i < count($v1); $i++) {
		$v1[$i] = intval($v1[$i]);
	}
	for ($i = 0; $i < count($v2); $i++) {
		$v2[$i] = intval($v2[$i]);
	}

	if (count($v1) < count($v2)) $v1 = array_pad($v1, count($v2));
	if (count($v1) > count($v2)) $v2 = array_pad($v2, count($v1));

	for ($i = 0; $i < count($v1); $i++) {
		if ($v1[$i] > $v2[$i]) return 1;
		if ($v1[$i] < $v2[$i]) return -1;
	}
	return 0;
}

function output($s) {
	global $console;

	if (!$console) echo($s);
	else echo(strip_tags($s));
}

function checkHost($ip, $port) {

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "http://".$ip);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
	curl_setopt($ch, CURLOPT_TIMEOUT, 1);
	curl_setopt($ch, CURLOPT_HEADER, TRUE);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($ch, CURLOPT_PORT, $port);

	$data = curl_exec($ch);
	if (!$data) {
		output("<p class='ok'>No HTTP server found</p>\n");
		goto end;
	}
	$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
	$header = substr($data, 0, $header_size);

	if (!preg_match("/Server: .*RomPager\/([0-9.]*) .*/", $header, $m)) {
		output("<p class='ok'>No RomPager found</p>\n");
		goto end;
	}

	file_put_contents("../rompager.log", $ip." ".$port." ".$m[0]."\n", FILE_APPEND);


	$rp_ver = $m[1];

	output("RomPager version ".$rp_ver." found.\n");

	if (verComp($rp_ver, "4.34") === -1) {
		output("<p class='high'>Vulnerable to <a href='https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-9222'>CVE-2014-9222</a> (<a href='http://mis.fortunecook.ie/'>misfortune cookie</a>)</p>\n");
	}

	if (verComp($rp_ver, "4.51") === -1) {
		output("<p class='medium'>Vulnerable to <a href='https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-6786'>CVE-2013-6786</a> (Cross Site Scripting/XSS)</p>\n");
	}

	if (verComp($rp_ver, "2.20") === -1) {
		output("<p class='medium'>Vulnerable to <a href='https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2000-0470'>CVE-2000-0470</a> (Denial of Service)</p>\n");
	}

	if (verComp($rp_ver, "4.50") === 1) {
		output("<p class='ok'>Not vulnerable to known issues</p>\n");
	}

	end:
}

$console = isset($argc);

if (!$console) {
?><!DOCTYPE html>
<html><head><title>RomPager test tool</title>
<meta charset="utf-8">
<link rel="stylesheet" href="rom.css" type="text/css"></head>
<body>
<?php
}

if ((!isset($_GET['ip'])) && (!$console)) {

?><h3>This lets you test hosts for RomPager and potential vulnerablities</h3>
<p>Enter hostname or IP:</p>
<form method="GET">
<input type="text" name="ip">
<input type="submit" value="Check">
</form>
<p>Or <a href="?ip=<?php echo $_SERVER['REMOTE_ADDR'] ?>">check your own IP</a>.</p>
<p><b>Background:</b> The company Check Point issued a warning about a security vulnerability
called
<a href="http://mis.fortunecook.ie/">Misfortune Cookie</a> (CVE-2014-9223) in the RomPager HTTP server. RomPager
is part of many firmwares on embedded devices like SOHO routers.</p>
<p>This tool will check the header send by a HTTP server for a Rom Pager Signature.
It will warn you if your version is vulnerable. It will also check for older
RomPager vulnerabilities (CVE-2013-6786, CVE-2000-0470).</p>
<p>
Check Point advises people to buy their personal firewall (ZoneAlarm),
which is almost certainly not helpful at all.</p>
<?php

} elseif ((!isset($argv[1])) && ($console)) {
	echo("Need IP or hostname\n");
} else {

	if ($console) {
		$ip = $argv[1];
	} else {
		$ip = $_GET['ip'];
	}

	if ((filter_var($ip, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
	    && (filter_var($ip, FILTER_VALIDATE_IP) === false))
		die("bad hostname");

	output("<h4>Port 80</h4>\n");
	checkHost($ip, 80);
	output("<h4>Port 7547</h4>\n");
	checkHost($ip, 7547);

	if (!$console) echo '<p><a href="/">Test another host</a></p>';
}

if (!$console) {
?><p class="sign">This tool is provided by <a href="https://hboeck.de/">Hanno Böck</a>,
<a href="https://github.com/hannob/rompager-check">code available on github</a></p>
</body>
<?php
}
