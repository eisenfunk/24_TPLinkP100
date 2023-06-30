################################################################
# $Id$
#  Copyright notice
#
#  (c) 2023 Copyright: Michael Mayer
#  e-mail: michael at hirntot dot eu
#
#  Description:
#  This is a FHEM module for TP Link TAPO power outlets
#  P100 / P110 / P115
#  others may work, but are not tested due to a lack of hardware
#
#  Requirements:
# 	SetExtensions
# 	Digest::SHA qw(sha1_hex)
# 	Crypt::CBC
# 	Crypt::Cipher::AES
# 	Crypt::OpenSSL::RSA
# 	JSON
# 	LWP
# 	MIME::Base64
# 	Data::Dumper
#
# Origin:
#
################################################################
#
# TODOs
# store RSAKEY, TPKEY and TPIV
# units for readings like mW, mA, dB ...
# status symbol for not connected
#
# Version 0.3
# -- introduced attr disablePowermeasurement for model P110 with default 1
# -- power_measurement only when device is on
# -- set default timeout to 5s and disallow smaller
# -- set default interval to 300s and disallow smaller than 15s
# -- added notify handler (still empty)
# -- POD documentation DE
#
# Version 0.2
# -- Bugfixing: fhem crash by module due to null instead of json
#    Caused by cpan JSON, that will croak on error if used as function.
#    As object it's possible to set the option "allow-nonref"
# -- POD documentation
# -- UUID by fhem instead of UUID cpan module
# -- P110 introduced with energy measurement
#
# Version 0.1
# -- Handshake, Keyexchange and Login
# -- returned JSON split in internals and readings
# -- reading update on changed values
# -- basic switch functionality (on/off)
#
# Tested on:
# P115
# 	hw_ver 1.0
# 	fw_ver 1.1.6 Build 221114 Rel.203339
#
# P110
# 	hw_ver 1.0
# 	fw_ver 1.1.6 Build 221114 Rel.203339
# 	       1.2.3 Build 230425 Rel.142542
#
# P100
# 	hw_ver 2.0
# 	fw_ver 1.1.4 Build 221219 Rel.103556
#

package main;

use strict;
use warnings;
use SetExtensions;
use Digest::SHA qw(sha1_hex);
use Crypt::CBC;
use Crypt::Cipher::AES;   # Debian/Ubuntu: libcryptx-perl
use Crypt::OpenSSL::RSA;
use JSON;
use LWP;
use MIME::Base64;
use Data::Dumper;
use constant {
	TRUE => 1,
	FALSE => 0,
};

my $version = "0.3";
my $interval = 300;
my $timeout = 5;

sub __readingsBulkUpper ($$) {
	my ($hash, $readings) = @_;
	my $cnt = 0;
	my $save;

	if (keys(%$readings) > 0) {
		foreach my $key (keys(%$readings)) {
			if (ref($readings->{$key}) eq 'ARRAY') {
				Log(5, "DEBUG __readingsBulkUpper $readings->{$key} (" . @{$readings->{$key}} . ")");
				my @arr = @{$readings->{$key}};
				my $str = join (' ', @arr);
				$save->{$key} = $str if (ReadingsVal($hash->{NAME}, $key, "something") ne $str );
			} else {
				$save->{$key} = $readings->{$key} if (ReadingsVal($hash->{NAME}, $key, "something") ne $readings->{$key});
			}
		}
	}
	if (keys(%$save) > 0) {
		Log(5, "DEBUG __readingsBulkUpper START ($hash->{NAME})");
		readingsBeginUpdate($hash);
		foreach my $key (keys(%$save)) {
			readingsBulkUpdate($hash, $key, $save->{$key});
			$cnt++;
			Log(4, "__readingsBulkUpper SAVED '$save->{$key}' in '$key' #$cnt");

		}
		readingsEndUpdate($hash, 1);
		Log(5, "DEBUG __readingsBulkUpper END ($hash->{NAME}) had $cnt");
	}

	return $cnt;
}

sub __getToken ($) {
	my ($hash) = @_;
	Log (4, "$hash->{NAME} __getToken start sslHandshake");

	return undef if (!defined $hash->{helper}->{TPKEY}) && !__sslHandshake($hash);	

	Log (3,"$hash->{NAME} __getToken fetching new token");
	my $raw = __sendEncrypted($hash, 'login_device', (
			"username" => $hash->{helper}->{B64_USER},
			"password" => $hash->{helper}->{B64_PASS},
	));
	my $json = $hash->{helper}->{JSON}->decode($raw) if defined $raw;
	Log (5, "$hash->{NAME} __getToken received \$json = " . Dumper($json));

	if (__hasError($hash, $json)) {
		__unsetKeys($hash);
		return undef;
	} else {
		__setToken($hash, $json->{result}->{token});
		return $raw;
	}
}

sub __hasError ($$) {
	my ($hash, $json) = @_;
	my $codes = {
		0 => "OK",
		404 => "DEVICE NOT REACHABLE",
		500 => "INTERNAL ERROR BY FHEM MODULE",
		1002 => "INCORRECT REQUEST",
		1003 => "WRONG JSON FORMAT",
		1008 => "VARIABLE TYPE ERROR",
		1010 => "WRONG PUBLIC KEY LENGTH",
		1012 => "INVALID TERMINAL UUID",
		1015 => "INVALID REQUEST OR LOGIN",
		9999 => "DEVICE NOT REACHABLE",
	};
	Log (4, "$hash->{NAME} __hasError started $json->{error_code}");

	$json->{error_code} = 500 if (!defined $json->{error_code});
	$json->{error_code} = abs($json->{error_code});

	__readingsBulkUpper($hash, { "error_code" => $json->{error_code}, "error_msg" => $codes->{$json->{error_code}} });
	return FALSE if $json->{error_code} == 0;

	__unsetKeys($hash);
	return TRUE;
}

sub __readToken ($) {
	my ($hash) = @_;

	return ReadingsVal($hash->{NAME}, "token", undef);
}

sub __hasToken ($) {
	my ($hash) = @_;

	return TRUE if (defined ReadingsVal($hash->{NAME}, "token", undef) && ReadingsVal($hash->{NAME}, "connected", "no") eq "yes");
	return FALSE;
}

sub __unsetToken ($) {
	my ($hash) = @_;

	Log (4, "$hash->{NAME} __unsetToken");
	__readingsBulkUpper($hash, {"connected" => "no", "token" => undef});
	return TRUE;
}

sub __setToken ($$) {
	my ($hash, $token) = @_;

	Log (4, "$hash->{NAME} __setToken");
	__readingsBulkUpper($hash, {"connected" => "yes", "token" => $token});
	return TRUE if __readDeviceinfos($hash);
	return FALSE;
}

sub __unsetKeys ($) {
	my ($hash) = @_;

	$hash->{helper}->{TPKEY} = undef;
	$hash->{helper}->{TPIV} = undef;
	$hash->{helper}->{COOKIE} = undef;
	Log (4, "$hash->{NAME} __unsetKeys");
	__readingsBulkUpper($hash, {"connected" => "no", "token" => undef});

	return TRUE;
}

sub __setKeys ($$) {
	my ($hash, $key) = @_;

	Log (4, "$hash->{NAME} __setKeys");
	my $cryptkey = decode_base64($key);
	my $tpkey = $hash->{helper}->{RSAKEY}->decrypt($cryptkey);
	$hash->{helper}->{TPKEY} = substr($tpkey, 0, 16);
	$hash->{helper}->{TPIV} = substr($tpkey, 16, 16);

	return TRUE;
}

sub __readDeviceinfos($) {
	my ($hash) =@_;

	Log (4, "$hash->{NAME} __readDeviceinfo 'get_device_info'");
	return undef if !__getDeviceinfo($hash, 'get_device_info');
	if ($hash->{model} eq "P110" && 
	    AttrVal($hash->{NAME}, "disablePowermeasurement", 1) == 0 &&
	    $hash->{STATE} eq "on" ) {
		Log (4, "$hash->{NAME} __readDeviceinfos 'get_energy_usage'");
		return FALSE if !__getDeviceinfo($hash, 'get_energy_usage');
	}
}

sub __getDeviceinfo ($$) {
	my ($hash, $cmd) = @_;
	my $readings;
	my $internals = {
		"device_id" => 1,
		"fw_id" => 1,
		"fw_ver" => 1,
		"has_set_location_info" => 1,
		"hw_id" => 1,
		"hw_ver" => 1,
		"ip" => 1,
		"lang" => 1,
		"latitude" => 1,
		"longitude" => 1,
		"mac" => 1,
		"model" => 1,
		"nickname" => 1,
		"oem_id" => 1,
		"region" => 1,
		"specs" => 1,
		"time_diff" => 1,
		"type" => 1,
	};
	my $ignore = {
		"device_on" => 1,
		"default_states" => 1,
		"local_time" => 1,
	};

	return FALSE if !__hasToken($hash);

	Log(4, "$hash->{NAME} __getDeviceinfo ($cmd)");
	my $enc_json = __sendEncrypted($hash, $cmd, ());

	my $json = $hash->{helper}->{JSON}->decode($enc_json) if defined $enc_json;
	Log(5, "DEBUG $hash->{NAME} __getDeviceinfo ($cmd) " . Dumper($json));
	return FALSE if __hasError($hash, $json);

	if ($cmd eq 'get_device_info') {
		$json->{result}->{ssid} = decode_base64($json->{result}->{ssid});
		$json->{result}->{nickname} = decode_base64($json->{result}->{nickname});
	
		if ($json->{result}->{device_on} == 1) {
			$hash->{STATE} = "on";
			$readings->{status} = "on";
		} else {
			$hash->{STATE} = "off";
			$readings->{status} = "off";
		}
	}

	foreach (keys(%{$json->{result}})) {
		$hash->{$_} = $json->{result}->{$_} if (defined $internals->{$_});
		$readings->{$_} = $json->{result}->{$_} if (!defined $internals->{$_} && !defined $ignore->{$_});
	}
	Log(5, "DEBUG $hash->{NAME} __getDeviceinfo ($cmd) calling __readingBulkUpper " . Dumper($readings));
	__readingsBulkUpper($hash, $readings);

	return TRUE;
}

sub __sslHandshake ($) {
	my ($hash) = @_;

	my $raw = __jsonPost($hash, __cmdToJSON($hash, "handshake", $hash->{helper}->{PUBKEY}));
	my $json = $hash->{helper}->{JSON}->decode($raw) if defined $raw;
	return FALSE if __hasError($hash, $json);

	__setKeys($hash, $json->{result}->{key});
	return TRUE;
}

sub __cmdToJSON ($$$) {
	my ($hash, $cmd, $args) = @_;
	return encode_json ({
		"method" => $cmd,
		"requestTimeMils" => 0,
		"terminalUUID" => $hash->{FUUID},
		"params" => $args
	});
	return undef;
}

sub __jsonPost($$) {
	my ($hash, $json) = @_;

	my $http = LWP::UserAgent->new("timeout" => $hash->{TIMEOUT});
	my $url = $hash->{helper}->{URL};

	$url .= '?token=' . __readToken($hash) if (__hasToken($hash));

	my $request = HTTP::Request->new(POST => $url);
	$request->header('content-type' => 'application/json');
	$request->header('Cookie' => $hash->{helper}->{COOKIE}) if (defined $hash->{helper}->{COOKIE});
	Log(4, "$hash->{NAME} __jsonPost $url");
	Log(5, "DEBUG $hash->{NAME} __jsonPost COOKIE " . $hash->{helper}->{COOKIE}) if defined $hash->{helper}->{COOKIE};
	$request->content($json);

	Log(5, "DEBUG $hash->{NAME} __jsonPost HTTP::Request " . Dumper($request));

	my $raw = $http->request($request);
	if (!$raw->is_success) {
		return '{"error_code" : 404, "result" : "undef"}';
	}

	if (!defined $hash->{helper}->{COOKIE}) {
		my $cookie = $raw->header('Set-Cookie');
		if ($cookie=~/(TP_SESSIONID=\w+)/) {
			$hash->{helper}->{COOKIE} = $1;
		}
	}

	return $raw->decoded_content;
}

sub __sendEncrypted ($$%) {
	my ($hash, $cmd, %args) = @_;

	return undef if !defined($hash->{helper}->{TPKEY});

	my $cipher = Crypt::CBC->new(
			-cipher => 'Cipher::AES',
			-keysize => 128/8,
			-header => 'none',
			-literal_key => 1,
			-key => $hash->{helper}->{TPKEY},
			-iv => $hash->{helper}->{TPIV},
	);
	my $json_cmd = __cmdToJSON($hash, $cmd, \%args );
	Log(5, "DEBUG $hash->{NAME} __sendEncrypted ENC " . Dumper($json_cmd));

	my $enc = encode_base64($cipher->encrypt( $json_cmd ));
	$enc =~ s/\n//g;
	Log(5, "DEBUG $hash->{NAME} __sendEncrypted ENC $enc");

	my $transfer_json = encode_json({
			method => 'securePassthrough',
			params => { 
				request => $enc,
			}
	});
	Log(5, "DEBUG $hash->{NAME} __sendEncrypted RTS " . Dumper($transfer_json));

	my $raw = __jsonPost($hash, $transfer_json);
	my $json = $hash->{helper}->{JSON}->decode($raw) if defined $raw;
	return undef if __hasError($hash, $json);

	return $cipher->decrypt(decode_base64($json->{result}->{response}));
}

sub __switch ($$) {
	my ($hash, $cmd) = @_;

	return undef if ($hash->{STATE} eq $cmd);

	my $ret = __sendEncrypted($hash, 'set_device_info', ( "device_on" => $cmd eq "on" ? JSON::true : JSON::false ));
	if (!defined $ret) {
		return undef if (!__hasToken($hash) && !TPLinkP100_Connect ($hash));
	}

	$hash->{STATE} = $cmd;
	__readingsBulkUpper($hash,{ "status" => $cmd });

	return undef;
}

sub __startConditionFailed ($) {
	my ($hash) = @_;

	return TRUE if IsDisabled ($hash);	
	return TRUE if !$init_done;
}

sub TPLinkP100_Initialize($) {
	my ($hash) = @_;

	$hash->{DefFn}    = "TPLinkP100_Define";
	$hash->{UndefFn}  = "TPLinkP100_Undefine";
	$hash->{GetFn}    = "TPLinkP100_Get";
	$hash->{SetFn}    = "TPLinkP100_Set";
	$hash->{NotifyFn} = "TPLinkP100_Notify";
	$hash->{AttrFn}	  = "TPLinkP100_Attr";
	$hash->{AttrList} = "interval " .
			    "disable:0,1 " .
		    	    "timeout " .
			    "disablePowermeasurement:0,1 " .
			    "$readingFnAttributes";
}

sub TPLinkP100_Define($$) {
    my ($hash, $def) = @_;
    
	my @a = split("[ \t][ \t]*", $def);
	return "Wrong syntax: use define <name> TPLinkP100 <hostname/ip> username password interval timeout" if (int(@a) < 5);
	
	$hash->{helper}->{B64_USER} = encode_base64(sha1_hex($a[3]));
	$hash->{helper}->{B64_PASS} = encode_base64($a[4]);
	$hash->{password} = $a[4];
	if (@a == 6) {
		if ($a[5] < 15) {
			return "interval too small, please use an interval > 15s, default is ${interval}s";
		}
		if (@a == 8) {
			if ($a[5] < 5) {
				return "timeout too small, please a value > 5s, default is ${timeout}s";
			}
			if (@a > 8) {
				return "Wrong syntax: use define <name> TPLinkP100 <hostname/ip> username password interval timeout";
			}
		}
	}
	$hash->{interval} = $interval || $a[5];
	$hash->{TIMEOUT} = $timeout || $a[6];
	$hash->{version} = $version;

	#$hash->{helper}->{RSAKEY} = getKeyValue("RSAKEY");
	#if (!defined $hash->{helper}->{RSAKEY}) {
		$hash->{helper}->{RSAKEY} = Crypt::OpenSSL::RSA->generate_key(1024);
		$hash->{helper}->{RSAKEY}->use_pkcs1_padding();
		#}
		#setKeyValue("RSAKEY",$hash->{helper}->{RSAKEY});
	print STDERR Dumper($hash->{helper}->{RSAKEY});
	$hash->{helper}->{PUBKEY}->{key} = $hash->{helper}->{RSAKEY}->get_public_key_x509_string();
	$hash->{helper}->{URL} = 'http://' . $a[2] . '/app';
	$hash->{helper}->{COOKIE} = undef;


	# perl JSON does croak on error if used as a function.
	# Better way is to use an object an set allow_nonref
	# to prevent this default croaking which does stop fhem.
	$hash->{helper}->{JSON} = JSON->new->allow_nonref;

	Log (3, "TPLinkP100: $hash->{NAME} defined.");
	
	TPLinkP100_GetUpdate ($hash);
    return undef;
}

sub TPLinkP100_Notify ($$) {
	my ($hash, $dev_hash) = @_;

	return undef if IsDisabled ($hash);

	# nothing yet
}

sub TPLinkP100_Attr ($$$$) {
	my ($cmd, $name, $aName, $aValue) = @_;

	if ($cmd eq "set") {
		if ($aName eq "interval") {
			return "interval too small, please use an interval > 15s" if $aValue < 15
		}
		if ($aName eq "timeout") {
			return "timeout too small, please use an value > 5s" if $aValue < 5
		}
	}
	return undef;
}

sub TPLinkP100_Undefine($$) {
	my ($hash, $arg) = @_; 

	__unsetKeys($hash);
	RemoveInternalTimer($hash);

	return undef;
}

sub TPLinkP100_Get($$@) {
	my ($hash, $name, $opt, @args) = @_;

	return undef if __startConditionFailed($hash);
	return "\"get $name\" needs at least one argument" unless(defined($opt));
	return ReadingsVal ($hash->{NAME}, "status", "off") if ($opt eq "status");
	return "unknown argument $opt choose one of status";
}

sub TPLinkP100_Set($$@) {
	my ($hash, $name, $cmd, @args) = @_;
	my $cmdList = { "on" => 1, "off" => 1 };

	return undef if __startConditionFailed($hash);
	return "\"set $name\" needs at least one argument" unless(defined($cmd));
	return "unknown argument $cmd choose one of " . join(" ", keys(%{$cmdList})) if ($cmd eq "?");
	return __switch($hash, $cmd) if (defined $cmdList->{$cmd});
	return SetExtensions($hash, join(" ", keys(%{$cmdList})), $name, $cmd, @args);
}

sub TPLinkP100_GetUpdate ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 
	
	InternalTimer(gettimeofday()+$hash->{interval}, "TPLinkP100_GetUpdate", $hash);

	return undef if ((ReadingsVal ($hash->{NAME}, "connected", "no") eq "no") && !TPLinkP100_Connect ($hash));
	return undef if __readDeviceinfos($hash);
}

sub TPLinkP100_Connect ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 

	my $ret = __getToken($hash);

	return undef;
}

sub TPLinkP100_Disconnect ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 

	__unsetKeys($hash);

	return undef;
}


1;

=pod
=begin html

<a id="TPLinkP100"></a>
<h3>TPLinkP100</h3>
<ul>
    <i>TPLinkP100</i> implements basic switch functions for TP-Link Tapo WIFI switchable power outlets.
    P100, P110 and P115 were tested during development and work as expected. Other models like UK P125 may also work.
    Feedback is appreciated.
    Hardware feature on-till and off-till are not included in this module.
    SetExtensions is offering more grainful and better options, supported for all fhem devices, so there
    is no necessity to include this very basic hardware support.
    <br><br>
    P110 power measurement is included and does work UNTIL YOU UNPLUG THE DEVICE.
    After being powerless the device is returning 1003 MALFORMED JSON errors. Due to this the power measurement is disabled per default.
    If you want to use this feature, set the attribute "disablePowermeasurement" to 0. Please don't report this as a module bug.
    <br><br>
    The only way to let fhem reconnect successful to the device is a full hardware reset, done by pressing the power button for longer than 5 seconds.
    The led is starting to blink green/yellow again and you have to resetup the device with the Tapo App. After that the device is working again, without restarting fhem or reloading the module.

    <br><br>
    <a id="TPLinkP100-define"></a>
    <b>Define</b>
    <ul>
        <code>define &lt;name&gt; TPLinkP100 &lt;IP/Hostname&gt; &lt;Login&gt; &lt;Password&gt;</code>
        <br><br>
        Example: <code>define myOfficeTapo TPLinkP100 192.168.0.110 john@doe.com Secret</code>
        <br><br>
	The IP/Hostname must be reachable from your fhem installation. Login and Password are identical to your Tapo registration and are set
	when you follow the complete installation instructions of your device.
	The Tapo App is used for device installation only. After your device is setup you may block your device from internet access on your firewall/router.
	It's your decission to trust the TP-Link cloud, when you're using fhem.
	<br><br>
    </ul>
    <br>
    
    <a id="TPLinkP100-set"></a>
    <b>Set</b><br>
    <ul>
        <code>set &lt;name&gt; &lt;value&gt;</code>
        <br><br>
        You can <i>set</i> your device on or off and to any other value of SetExtensions like on-till etc.
        See <a href="http://fhem.de/commandref.html#set">commandref#set</a> for more info about the set command.
        <br><br>
    </ul>
    <br>

    <a id="TPLinkP100-get"></a>
    <b>Get</b><br>
    <ul>
        <code>get &lt;name&gt; &lt;status&gt;</code>
        <br><br>
        You can <i>get</i> the status of your tapo device. The status is not polled from your device to avoid too much blocking calls. Instead you receive the value of the "status" reading.
        <a href="http://fhem.de/commandref.html#get">commandref#get</a> for more info about 
        the get command.
        <br><br>
    </ul>
    <br>
    
    <a id="TPLinkP100-attr"></a>
    <b>Attributes</b><br>
    <ul>
        <code>attr &lt;name&gt; timeout &lt;seconds&gt;</code>
        <br><br>
	Timeout in seconds for the blocking REST api call. default: 5s
        <br><br>
        <code>attr &lt;name&gt; interval &lt;seconds&gt;</code>
        <br><br>
	Interval in seconds to refetch status informations from the device. default: 15s
        <br><br>
        <code>attr &lt;name&gt; disablePowermanagement &lt;0/1&gt;</code>
        <br><br>
	For model P110 only. default: 1. Please read the description above why this is disabled per default.
        <br><br>
        See <a href="http://fhem.de/commandref.html#attr">commandref#attr</a> for more info about 
        the attr command.
        <br><br>
    </ul>
    <br>

    <a id="TPLinkP100-require"></a>
    <b>Requirements</b><br>
    	This module does require the following perl modules:
	<br><br>
	<li>Digest::SHA</li>
	<li>Crypt::CBC</li>
	<li>Crypt::Cipher::AES</li>
	<li>Crypt::OpenSSL::RSA</li>
	<li>JSON</li>
	<li>LWP</li>
	<li>MIME::Base64</li>

    <ul>
    </ul>
    <br>
</ul>

=end html

=begin html_DE

<a id="TPLinkP100"></a>
<h3>TPLinkP100</h3>
<ul>
    <i>TPLinkP100</i> stellt Basis Funktionen f&uuml;r TP-Link Tapo WIFI schaltbare Steckdosen bereit.
    Getestet wurden P100, P110 und P115. UK Modelle wie P125 sollten auch funktionieren, sind aber nicht getestet.
    Hardware on-till und off-till Funktionen der Ger&auml;te sind nicht inplementiert.
    Fhem SetExtentions stellen dies skalierbarer und besser bereit.
    <br><br>
    P110 Power Management ist unterst&uuml;tzt und funktioniert BIS DAS GER&Auml;T ABGESTECKT WIRD.
    Wurde das Ger&auml;t stromlos, liefert es 1003 MALFORMED JSON Fehler an fhem zur&uuml;ck.
    Aus diesem Grund ist die Funktion per default mit dem Attribut "disablePowermeasurement" abgeschaltet.
    <br><br>
    Wenn das Ger&auml;t diesen Fehler aufzeigt, muss es zur&uuml;ckgesetzt werden.
    Daf&uuml;r ist die Power-Taste l&auml;nger als 5 Sekunden zu dr&uuml;cken. Die LED beginnt dann Gelb/Gr&uuml;n zu blinken.
    Per Tapo App kann es dann neu eingerichtet werden. Im Anschlu&szlig; funktioniert die R&uuml;ckmeldung wieder, ohne da&szlig; fhem oder das Modul neu gestartet werden m&uuml;ssen.

    <br><br>
    <a id="TPLinkP100-define"></a>
    <b>Define</b>
    <ul>
        <code>define &lt;name&gt; TPLinkP100 &lt;IP/Hostname&gt; &lt;Login&gt; &lt;Password&gt;</code>
        <br><br>
        Beispiel: <code>define meinOfficeTapo TPLinkP100 192.168.0.110 max@mustermann.de Secret</code>
        <br><br>
	IP/Hostname muss von der fhem Installation aus erreichbar sein. Login und Passwort sind die registrierten Zugangsdaten zur Tapo Cloud.
	Das Ger&auml;t mu&szlig; initial mit der Tapo App eingerichtet werden, damit es von fhem bedient werden kann.
	Nach dem Setup kann mit der/dem Firewall/Router der Internet Zugang blockiert werden. F&uuml;r die Bedienbarkeit per fhem spielt das keine Rolle.
	<br><br>
    </ul>
    <br>
    
    <a id="TPLinkP100-set"></a>
    <b>Set</b><br>
    <ul>
        <code>set &lt;name&gt; &lt;value&gt;</code>
        <br><br>
	Das Module versteht on/off und weitere SetExtensions Varianten wie on-till u.s.w.
        <br><br>
    </ul>
    <br>

    <a id="TPLinkP100-get"></a>
    <b>Get</b><br>
    <ul>
        <code>get &lt;name&gt; &lt;status&gt;</code>
        <br><br>
	Liefert den Status zur&uuml;ck. Bei einer Ger&auml;teabfrage werden immer alle readings &uuml;bermittelt, aber nur status ist inplementiert. Der get Aufruf startet keinen Call zum Tapo Ger&auml;t.
        <br><br>
    </ul>
    <br>
    
    <a id="TPLinkP100-attr"></a>
    <b>Attribute</b><br>
    <ul>
        <code>attr &lt;name&gt; timeout &lt;seconds&gt;</code>
        <br><br>
	Timeout in Sekunden: default 5s
        <br><br>
        <code>attr &lt;name&gt; interval &lt;seconds&gt;</code>
        <br><br>
	Abfrageintervall in Sekunden: default 15s
        <br><br>
        <code>attr &lt;name&gt; disablePowermanagement &lt;0/1&gt;</code>
        <br><br>
	Ausschlie&szlig;lich Modell P110: default 1.
        <br><br>
        <br><br>
    </ul>
    <br>

    <a id="TPLinkP100-require"></a>
    <b>Requirements</b><br>
        Diese Perl Module werden ben&ouml;tigt:
	<br><br>
	<li>Digest::SHA</li>
	<li>Crypt::CBC</li>
	<li>Crypt::Cipher::AES</li>
	<li>Crypt::OpenSSL::RSA</li>
	<li>JSON</li>
	<li>LWP</li>
	<li>MIME::Base64</li>

    <ul>
    </ul>
    <br>
</ul>

=end html_DE

=item summary Support for TPLink P100/P110/P115 wifi controlled power outlet

=item summary_DE Support für die TPLink P100/P110/P115 WLAN Steckdosen

=cut
