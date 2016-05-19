package Hep;
use strict;
use warnings;

require 5.004;

my $VERSION;
$VERSION = '0.1';

sub version { $VERSION; }

use IO::Socket;
use Time::HiRes qw(time);

=head1 NAME

Hep - Send HEP (Homer Encapsulation Protocol) packets from Perl

=head1 SYNOPSIS

use Hep;

# These two statements are identical, use one of them. 
'hostport' overrides host and port settings.

	$hep = Hep->new('host' => 'localhost', 'port' => 9060);

	$hep = Hep->new('hostport' => 'localhost:9060');

# Send HEP packet

	$hep->send('callid-of-correlating-call@localhost','{"key1": 105, "key2": "onehundredandfive"}');

=head1 DESCRIPTION

This module encapsulates all necessary information for sending out a Log
HEP packet to a HOMER capture node.
For details, see: http://hep.sipcapture.org/hepfiles/HEP3_rev11.pdf

=head1 methods

=over 4

=item Hep->new('host' => $host, 'port' => $port)

Instantiate a new Hep object. This will not create a socket, just set the parameters

=cut

sub new {
	my ($class, %args) = @_;
	my $self = {
		'hostport' => '',
		'host' => '127.0.0.1',
		'port' => 9060
		};

	# use parameters
	foreach (keys(%args)) {
		$self->{$_} = $args{$_};
	}
	
	if ($self->{'hostport'}) {
		($self->{'host'},$self->{'port'}) = split(/:/,$self->{'hostport'});
	}

	bless $self, ref $class || $class;
	return $self;

}

=item Hep->send($callid, $message)

Send out a log message.

To be found later in HOMER, the callid of the correlating call for the
log entry has to be set as first parameter.

The second parameter must be a JSON string. All parameter value tuples will
be displayed in a table in HOMER, later.

The function returns 1 on success, but can also die if the socket could
not be created. Maybe you want to wrap the call in an eval statement.

=cut

sub send {
	my ($self, $callid, $msg) = @_;

	return undef if (!defined($callid));
	return undef if (!defined($msg));

	my $sock = IO::Socket::INET->new(
		Proto    => 'udp',
		PeerPort => $self->{'port'},
		PeerAddr => $self->{'host'}
	) or die "Could not create socket: $!\n";

	# Build HEP packet
	my $hep_header = "HEP3";
	my $vendor = 0;
	my $chunktype = 1;
	my $chunkbaselength = 6;
	my $ip = $sock->sockhost;
	my $ipint = unpack 'N', pack 'C4', split '\.', $ip;
	my $port = 5060;

	my $timestamp = time;
	my @time = split(/\./,$timestamp);

	my $fakelength = 2400;

	my @chunks = ();
	push(@chunks,{'type' => 1, 'content' => 2, 'pack' => 'c'}); # Proto Family
	push(@chunks,{'type' => 2, 'content' => 17, 'pack' => 'c'}); # Proto ID (udp)
	push(@chunks,{'type' => 3, 'content' => $ipint, 'pack' => 'N'}); # SRC addr
	push(@chunks,{'type' => 4, 'content' => $ipint, 'pack' => 'N'}); # DST addr
	push(@chunks,{'type' => 7, 'content' => $port, 'pack' => 'n'}); # SRC port
	push(@chunks,{'type' => 8, 'content' => $port, 'pack' => 'n'}); # DST port
	push(@chunks,{'type' => 9, 'content' => int($time[0]), 'pack' => 'N'}); # Timestamp
	push(@chunks,{'type' => 10, 'content' => int($time[1]), 'pack' => 'N'}); # Microseconds
	push(@chunks,{'type' => 11, 'content' => 100, 'pack' => 'c'}); # Payload Type (100 = plain text)
	push(@chunks,{'type' => 12, 'content' => 0, 'pack' => 'N'}); # Capture Agent ID
	push(@chunks,{'type' => 17, 'content' => $callid, 'pack' => 'a'.length($callid)}); # Call-ID
	push(@chunks,{'type' => 15, 'content' => $msg, 'pack' => 'a'.(length($msg))}); # Payload

	my $packtemplate = "a4n";
	my @packetcontent = ();
	push(@packetcontent, $hep_header);
	push(@packetcontent, $fakelength);
	my $headertemplate = "nnn";

	foreach my $c (@chunks) {
		$packtemplate .= $headertemplate;
		$packtemplate .= $c->{'pack'};
		push(@packetcontent, $vendor);
		push(@packetcontent, $c->{'type'});
		# calculate length
		my $tmpcontent = pack($c->{'pack'},$c->{'content'});
		push (@packetcontent, length($tmpcontent)+$chunkbaselength);
		push(@packetcontent, $c->{'content'});
	}

	my ($packet) = pack($packtemplate,@packetcontent);

	# calculate correct length
	my $reallength = length($packet);
	$packetcontent[1] = $reallength;
	($packet) = pack($packtemplate,@packetcontent);
	$sock->send($packet) or die "Send Error: $!\n";

	close($sock);

	return 1;
}

1;

__END__

=back 
