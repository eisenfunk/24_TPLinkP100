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
# units for readings like mW, mA, dB ...
# status symbol for not connected
# energy measurement (after new authentification)
#
# Version 0.4
# -- Removed old and unsecure authentification , please update the firmware of your device or install version 0.3
# -- Added new authentification
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
# Tested verion 0.3 on:
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
# Tested version 0.4 on:
# P115, P110, P100 with all newer firmware versions

package TapoDevice;

use strict;
use warnings;
use Encode;

use Digest::SHA qw(sha1_hex sha1 sha256_hex sha256);
use Data::Dumper;
use Crypt::Random::Seed;
use LWP;
use Crypt::Mode::CBC;
use JSON;
use constant {
	TRUE => 1,
	FALSE => 0
};

sub new {
	my $class = shift;
	my $seed = new Crypt::Random::Seed;
	my $self = {
		_hostname => shift,
		_username => shift,
		_password => shift,
		_localseed => $seed->random_bytes(16)
	};

	bless $self, $class;
	print STDERR "TapoDevice: Trying init() with $self->{_username} on $self->{_hostname}\n";
	$self->init();
	return $self;
}

sub init ($) {
	my ($self) = @_;

	$self->{_authhash} = sha256( sha1($self->{_username}) . sha1($self->{_password}) );
	$self->{_timeout} = 2;
	$self->{_auth} = FALSE;
	$self->{_ttl} = 0;

	$self->__authenticate();

	if ($self->{_auth} == TRUE) {
		print STDERR "TapoDevice: Authenticated\n";
	} else {
		print STDERR "TapoDevice: Authentification failed\n";
		return FALSE;
	}
	return $self;
}

sub isAuth ($) {
	my ($self) = @_;

	$self->init() if time() > $self->{_ttl};
	return $self->{_auth};
}

sub request ($$$) {
	my ($self, $path, $data) = @_;

	if (!$self->isAuth()) {
		$self->init();
		return undef if !$self->isAuth();
	}
	my $js = JSON->new->allow_nonref;
	my $json = $js->utf8(1)->encode($data);
	my $sendPck = $self->__encrypt($json);
	my $response = __requestRaw($self, "request", $sendPck, $self->{_cookie});

        if ($response->{_rc} == 200) {
                $self->{reply} = $js->decode($self->__decrypt($response->{_content}));
                $self->{reply}->{rc} = 200;
        } else {
                $self->{reply}->{rc} = $response->{_rc};
        }

        return $self->{reply};
}

sub __authenticate($) {
	my ($self) = @_;

	my $response = __requestRaw($self, "handshake1", $self->{_localseed});

	if ($response->{_rc} == 200) {
		print STDERR "AUTH1\n";
		$self->{_remoteseed} = substr($response->{_content},0,16);
		$self->{_serverhash} = substr($response->{_content},16);

		my $localseed_authhash = sha256( $self->{_localseed} . $self->{_remoteseed} . $self->{_authhash} );
		if ($localseed_authhash eq $self->{_serverhash}) {
			if ($response->{_headers}->{"set-cookie"} =~ /^(.+);TIMEOUT=(\d+)$/) {
				$self->{_cookie} = $1;
				$self->{_ttl} = time() + $2;
			} else {
				return FALSE;
			}
		}
		$self->{_handshake2} = sha256( $self->{_remoteseed} . $self->{_localseed} . $self->{_authhash} );
		
		$response = __requestRaw($self, "handshake2", $self->{_handshake2}, $self->{_cookie} );

		if ($response->{_rc} == 200) {
			$self->{_key} = substr(sha256( "lsk" . $self->{_localseed} . $self->{_remoteseed} . $self->{_authhash} ), 0, 16);
			$self->{_ivseq} = sha256("iv" . $self->{_localseed} . $self->{_remoteseed} . $self->{_authhash} );
			$self->{_iv} = substr($self->{_ivseq}, 0, 12);
			$self->{_sig} = substr(sha256( "ldk" . $self->{_localseed} . $self->{_remoteseed} . $self->{_authhash} ), 0, 28);
			$self->{_auth} = TRUE;
			$self->__unpackSeq();
			return TRUE;
		}
	}
	return FALSE;
}

sub __unpackSeq ($) {
	my ($self) = @_;
	$self->{_seq} = unpack("l>", substr($self->{_ivseq}, -4, 4));
	return TRUE;
}

sub __packSeq ($) {
	my ($self) = @_;
	$self->{_bseq} = pack("l>", $self->{_seq});
	return TRUE;
}

sub __incrSeq ($) {
	my ($self) = @_;
	$self->{_seq}++;
	$self->__packSeq();
	return TRUE;
}

sub __requestRaw ($$$$) {
	my ($self, $path, $data, $cookie) = @_;

	$self->{ua} = new LWP::UserAgent if !defined $self->{ua};
	$self->{ua}->timeout($self->{TIMEOUT});

	my $getopt = "";
	$getopt = "?seq=" .$self->{_seq} if $self->{_seq};

	my $request = new HTTP::Request(
		'POST',
		"http://$self->{_hostname}/app/${path}${getopt}"
	);
	$request->header("Cookie" => $cookie) if $cookie;
	$request->header("Connection" => "Keep-Alive");
	$request->header("Accept" => "*/*");
	$request->content($data);

	my $response = $self->{ua}->request($request);

	return $response;
}

sub __encrypt ($$) {
	my ($self, $data) = @_;

	$self->__incrSeq();

	# padding data
	my $padCnt = 16 - length($data) % 16;
	$data .= " " x $padCnt;

	my $enc = Crypt::Mode::CBC->new('AES');
	my $enc_text = $enc->encrypt($data, $self->{_key}, $self->{_iv}.$self->{_bseq});
	$self->{bsig} = sha256( $self->{_sig} . $self->{_bseq} . $enc_text );

	return $self->{bsig}.$enc_text;
}

sub __decrypt ($$) {
	my ($self, $data) = @_;

	# Original python code does not check the incoming signature, but this is part of the security concept.
	#if (substr($data,0,32) ne $self->{bsig}) {
		#return FALSE;
	#}
	my $enc = Crypt::Mode::CBC->new('AES');
	return $enc->decrypt(substr($data,32), $self->{_key}, $self->{_iv}.$self->{_bseq});
}

sub switch_on ($) {
	my ($self) = @_;
	my $response = $self->request("/request", {"method" => "set_device_info", "params" => {"device_on" => JSON::true}} );
	if ($response->{rc} == 200) {
		$self->get_info();
		return $response;
	} else {
		return FALSE;
	}
}

sub switch_off ($) {
	my ($self) = @_;
	my $response = $self->request("/request", {"method" => "set_device_info", "params" => {"device_on" => JSON::false}} );
	if ($response->{rc} == 200) {
		$self->get_info();
		return $response;
	} else {
		return FALSE;
	}
}

sub get_energy ($) {
	my ($self) = @_;
	my $response = $self->request("/request", {"method" => "get_energy_usage"} );
	if ($response->{rc} == 200) {
		return $response;
	}
	return FALSE;
}

sub get_info ($) {
	my ($self) = @_;
	my $response = $self->request("/request", {"method" => "get_device_info"} );
	if ($response->{rc} == 200) {
		return $response;
	}
	return FALSE;
}

1;

#
# This part of the code includes the old authentication protocol, which will be deleted in the future.
#
package main;

use strict;
use warnings;
use SetExtensions;
use Digest::SHA qw(sha1_hex);
use Crypt::CBC;
use Crypt::Cipher::AES;   # Debian/Ubuntu: libcryptx-perl
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha256_hex sha1_hex sha256 sha1);
use JSON;
use LWP;
use MIME::Base64;
use Data::Dumper;
use constant {
	TRUE => 1,
	FALSE => 0,
};

my $version = "0.4";
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

sub __getDeviceinfo ($$) {
	my ($hash, $json) = @_;
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

	return undef if !$json;

	print STDERR "TapoDevice: Parsing JSON\n";

	$json->{result}->{ssid} = decode_base64($json->{result}->{ssid});
	$json->{result}->{nickname} = decode_base64($json->{result}->{nickname});
	
	if ($json->{result}->{device_on} == 1) {
		$hash->{STATE} = "on";
		$readings->{status} = "on";
	} else {
		$hash->{STATE} = "off";
		$readings->{status} = "off";
	}

	foreach (keys(%{$json->{result}})) {
		$hash->{$_} = $json->{result}->{$_} if (defined $internals->{$_});
		$readings->{$_} = $json->{result}->{$_} if (!defined $internals->{$_} && !defined $ignore->{$_});
	}
	__readingsBulkUpper($hash, $readings);

	return TRUE;
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
	$hash->{helper}->{TapoDevice} = TapoDevice->new( $a[2], $a[3], $a[4] );

	if ($hash->{helper}->{TapoDevice}->isAuth()) {
		Log (3, "TPLinkP100: $hash->{NAME} defined.");
	} else {
		Log (3, "TPLinkP100: $hash->{NAME} unauthorized, host/ip, username and/or password is wrong");
		return undef;
	}
	TPLinkP100_GetUpdate($hash);
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

	$hash->{helper}->{TapoDevice} = "";
	RemoveInternalTimer($hash);

	return undef;
}

sub TPLinkP100_Get($$@) {
	my ($hash, $name, $opt, @args) = @_;

	return undef if IsDisabled ($hash);
	return "\"get $name\" needs at least one argument" unless(defined($opt));
	return ReadingsVal ($hash->{NAME}, "status", "off") if ($opt eq "status");
	return "unknown argument $opt choose one of status";
}

sub TPLinkP100_Set($$@) {
	my ($hash, $name, $cmd, @args) = @_;
	my $cmdList = { "on" => 1, "off" => 1 };

	return undef if IsDisabled ($hash);
	return "\"set $name\" needs at least one argument" unless(defined($cmd));
	#return "unknown argument $cmd choose one of " . join(" ", keys(%{$cmdList})) if ($cmd eq "?");

	if ($cmd eq "on") {
		$hash->{helper}->{TapoDevice}->switch_on($hash);
		__getDeviceinfo($hash, $hash->{helper}->{TapoDevice}->get_info($hash));
		return undef;
	}
	if ($cmd eq "off") {
		$hash->{helper}->{TapoDevice}->switch_off($hash);
		__getDeviceinfo($hash, $hash->{helper}->{TapoDevice}->get_info($hash));
		return undef;
	}
	if ($cmdList->{$cmd} eq "status") {
		__getDeviceinfo($hash, $hash->{helper}->{TapoDevice}->get_info($hash));
		__getDeviceinfo($hash, $hash->{helper}->{TapoDevice}->get_energy($hash));
		return undef;
	}

	return SetExtensions($hash, join(" ", keys(%{$cmdList})), $name, $cmd, @args);
}

sub TPLinkP100_GetUpdate ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 
	
	InternalTimer(gettimeofday()+$hash->{interval}, "TPLinkP100_GetUpdate", $hash);

	my $reply = $hash->{helper}->{TapoDevice}->get_energy($hash);
	__getDeviceinfo($hash, $reply);
	my $reply = $hash->{helper}->{TapoDevice}->get_info($hash);
	__getDeviceinfo($hash, $reply);
	return undef if ($reply->{rc} == 200);
}

sub TPLinkP100_Connect ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 
	my $reply = $hash->{helper}->{TapoDevice}->get_info($hash);
	$hash->__getDeviceinfo($reply);
	return undef if ($reply->{rc} == 200);
}

sub TPLinkP100_Disconnect ($) {
	my ($hash) = @_;
	return undef if IsDisabled ($hash); 
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
    Please note that TP-Link changed the authentification of all Tapo devices in 2023. The old authentification was unsecure
    and is also removed from this module. Please use version 0.3 if you want to go on with your old device, but consider updating.
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
    TP-Link hat die Authentifizierung in 2023 grundlegend verbessert und per Firmwareupdate herausgegeben.
    Die alte Authentifizierung war mangelhaft und ist ab Version 0.4 entfernt. Bitte verwende Version 0.3 f&uuml;r &auml;ltere Tapo Devices.
    Ein Update der Firmware ist aber dringend anzuraten.
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
