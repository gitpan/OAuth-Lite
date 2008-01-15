#!/usr/bin/perl

use strict;
use warnings;

use File::Spec;
use FindBin;
use lib File::Spec->catdir($FindBin::Bin, '..', 'lib');

use Perl6::Say;
use Digest::SHA;
use MIME::Base64;
use OAuth::Lite::Util;

my $http_method = "GET";
my $request_url = "http://photos.example.net/photos";
my $params = {
	oauth_consumer_key     => 'dpf43f3p2l4k3l03',
	oauth_token            => 'nnch734d00sl2jdk',
	oauth_signature_method => 'HMAC-SHA1',
	oauth_timestamp        => '1191242096',
	oauth_nonce            => 'kllo9940pd9333jh',
	oauth_version          => '1.0',
	file                   => 'vacation.jpg',
	size                   => 'original',
};

my $base = OAuth::Lite::Util::create_signature_base_string($http_method, $request_url, $params);

say $base;

my $key = q{kd94hf93k423kf44&pfkkdhi9sl3r4s00};
#my $sign = Digest::SHA::hmac_sha1_base64($base, $key);
my $sign = encode_base64(Digest::SHA::hmac_sha1($base, $key));

chomp $sign;
say $sign;

$params->{oauth_signature} = $sign;

my $header = OAuth::Lite::Util::build_auth_header("http://photos.example.net/", $params);
say $header;

