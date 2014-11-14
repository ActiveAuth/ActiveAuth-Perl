package ActiveAuth;

=head
  Copyright 2014 Anton Katsarov <anton@webface.bg>

  Distributed under the MIT License.

  See accompanying file COPYING or copy at
  http://opensource.org/licenses/MIT
=cut

use strict;
use warnings;

use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);


sub _sign {
    my ($username, $integration_id, $key, $prefix, $expire_after) = @_;
    my $expire_time = time + $expire_after;
    my $account_string = encode_base64("$username|$integration_id|$expire_time", "");
    my $info_string = "$prefix|$account_string";
    my $signature = hmac_sha1_hex($info_string, $key);
    return "$info_string|$signature";
}

sub sign {
  my ($username, $integration_id, $server_key, $application_key) = @_;
  my $application_signature = _sign($username, $integration_id, $application_key, 'APP', 3600);
  my $server_signature = _sign($username, $integration_id, $server_key, 'SRV', 300);
  unless ($application_signature && $server_signature) {
    warn "One signature is missing.";
    return undef;
  }
  return "$application_signature:$server_signature";
}

sub _get_user {
  my ($signature, $key) = @_;
  my $now = time;
  my ($prefix, $account_string, $sent_signature) = split /\|/, $signature;
  my $verification = hmac_sha1_hex("$prefix|$account_string", $key);
  if ($sent_signature ne $verification) {
    warn "signatures do not match";
    return undef;
  }
  my ($user, undef, $expires) = split /\|/, decode_base64($account_string);
  if ($now >= $expires) {
    warn "Expired...";
    return undef;
  }
  return $user;
}

sub verify {
  my ($response, $server_key, $application_key) = @_;
  my ($server_response, $application_response) = split /:/, $response;
  my $server_user = _get_user($server_response, $server_key);
  my $application_user = _get_user($application_response, $application_key);
  if ($server_user ne $application_user) {
    warn "Users do not match.";
    return undef;
  }
  return $server_user;
}

1;
