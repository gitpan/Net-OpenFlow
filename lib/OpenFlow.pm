#
# $Id$
#
package Net::OpenFlow;

use strict;
use warnings;
use Carp;
use Net::OpenFlow::Protocol;


=head1 NAME

Net::OpenFlow - Communicate with OpenFlow switches.

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

This module allows communication with an OpenFlow compliant switch.

use Net::OpenFlow;


my $of = Net::OpenFlow->new;

<create connection to switch>

$of->send($fh, $of_message);

my $of_message = $of->recv($fd, $xid);

my $of_message_type = $of_message->{'ofp_header'}{'of_type'};

=head1 FUNCTIONS

=over

=cut

our $VERSION = 0.01;

my $private_data = {};

sub minimum_version($$) {
	my $self = shift;
	my $version = shift;

	my $ret = $Net::OpenFlow::Protocol::openflow_version;

	if ($version < $ret) {
		$ret = $version;
	}

#	$self->__debug($self->__function_debug(q{minimum_version}, $ret, [$version]));

	return $ret;
}

=item C<< new >>

This is the constructor for the Net::OpenFlow module.

my $of = Net::OpenFlow->new;

=cut

sub new {
	my $class = shift;

	my $self = {};

	bless $self, $class;

	$self->new_init($self->__fixup_params(@_));

	return $self;
}

sub new_init {
	my $self = shift;
	my $attr = shift;

	my $version = ($attr->{'version'} // 0x01);

	my $ofp;

	if (defined($attr->{'debug'}) and ($attr->{'debug'} =~ m{^\d+$})) {
		$ofp = Net::OpenFlow::Protocol::Debug->new;
	}
	else {
		$ofp = Net::OpenFlow::Protocol->new;
	}

	$self->protocol($ofp);
}

=item C<< protocol >>

This function will return an object of type Net::OpenFlow::Protocol so that messages can be constructed.

my $ofp = $of->protocol;

=cut

sub protocol($;$) {
	my $self = shift;
	my $object = shift;

	if (defined $object) {
		$private_data->{$self}{'Net::OpenFlow::Protocol'} = $object;
	}

	eval {
		$private_data->{$self}{'Net::OpenFlow::Protocol'}->isa(q{Net::OpenFlow::Protocol});
	};

	if ($@) {
		croak $@;
	}

	return $private_data->{$self}{'Net::OpenFlow::Protocol'};
}

=item C<< recv >>

This function will read the OpenFlow message from the file handle and return a decoded representation.

my $of_message = $of->recv($fh, $xid);

=cut

sub recv($$) {
	my $self = shift;
	my ($fh, $xid) = @_;

	my $fd = fileno($fh);

	if (defined $fd) {
		eval {
			$fh->can(q{read});
		};

		if ($@) {
			croak $@;
		}
	}
	else {
		croak q{Not a valid file handle};
	}

	my $of_message;

	eval {
		$of_message = $self->__recv($fh, $xid);
	};

	if ($@) {
		croak $@;
	}

	my $ret = $self->protocol->ofpt_decode(\$of_message);

	return $ret;

}

=item C<< send >>

This function will send the message specified by $of_message to the file handle $fh. The file handle must have a send() function for this to work.
The IO::Socket family are the most likely use case for this function.

my $of_message = $of->protocol->ofpt_encode(0x01, q{OFPT_HELLO}, 1);

$of->send($fh, $of_message);

=cut

sub send($$$) {
	my $self = shift;
	my ($fh, $data) = @_;

	my $fd = fileno($fh);

	if (defined $fd) {
		eval {
			$fh->can(q{send});
		};

		if ($@) {
			croak $@;
		}
	}
	else {
		croak q{Not a valid file handle};
	}

	eval {
		$fh->send($data);
	};

	if ($@) {
		croak $@;
	}
}

sub __fixup_params {
	my $self = shift;

	my $ret = {};

	if ((scalar(@_) % 2) == 0) {
		while (my ($key, $value) = splice(@_, 0, 2)) {
			$ret->{$key} = $value;
		}
	}
	elsif (scalar(@_) == 1) {
		my $param = $_[0];

		my $ref_type = ref($param);

		if ($ref_type eq q{HASH}) {
			$ret = $param;
		}
		elsif ($ref_type eq q{ARRAY}) {
			$ret = $self->__fixup_params(@{$param});
		}
		else {
			$ret->{'version'} = $param;
		}
	}
	else {
		croak q{Invalid parameters};
	}

	return $ret;
}

sub __recv {
	my $self = shift;
	my ($fh, $xid) = @_;

	my $buf;

	$fh->read($buf, $Net::OpenFlow::Protocol::header_length);

	my $ret = $buf;

	my $ofp_header = $self->protocol->struct_decode__ofp_header(\$buf);

	unless ($ofp_header->{'version'} <= $Net::OpenFlow::Protocol::openflow_version) {
		croak q{Unsupported version};
	}

	if (defined $xid) {
		unless ($xid == $ofp_header->{'xid'}) {
#			croak q{Mismatched xid};
		}
	}

	my $bytes_remaining = ($ofp_header->{'length'} - $Net::OpenFlow::Protocol::header_length);

	if ($bytes_remaining) {
		$fh->read($buf, $bytes_remaining);

		$ret .= $buf;
	}

	return $ret;
}

1;

=back
