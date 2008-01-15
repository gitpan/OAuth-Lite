package OAuth::Lite::Server::mod_perl2;

use strict;
use warnings;

use Apache2::Connection  ();
use Apache2::RequestIO   ();
use Apache2::RequestRec  ();
use Apache2::RequestUtil ();
use Apache2::Response    ();
use Apache2::URI         ();
use Apache2::ServerRec   ();
use URI::Escape          ();
use Apache2::Const -compile => qw(OK);

use List::MoreUtils qw(none);
use bytes ();

use OAuth::Lite::Util qw(:all);
use OAuth::Lite::ServerUtil;
use OAuth::Lite::AuthMethod qw(:all);

use base qw(
    Class::Accessor::Fast
    Class::ErrorHandler
);

use constant PROTECTED_RESOURCE => 'PROTECTED_RESOURCE';
use constant REQUEST_TOKEN      => 'REQUEST_TOKEN';
use constant ACCESS_TOKEN       => 'ACCESS_TOKEN';

__PACKAGE__->mk_accessors(qw/request realm oauth/);

=head1 NAME

OAuth::Lite::Server::mod_perl2 - mod_perl2 OAuth server

=head1 SYNOPSIS

Inherit this class, build your service with mod_perl2.
For example, write MyServiceWithOAuth.pm
And the source-code of L<OAuth::Lite::Server::Test::Echo> is nice example.
See it.

    package MyServiceWithOAuth;
    use base 'OAuth::Lite::Server::mod_perl2';

    sub init {
        my $self = shift;
        $self->allow_extra_params(qw/file size/);
        $self->support_signature_methods(qw/HMAC-SHA1 PLAINTEXT/);
    }

    sub get_request_token_secret {
        my ($self, $token_string) = @_;
        my $token = MyDB::Scheme->resultset('RequestToken')->find($token_string);
        unless ($token
            &&  $token->is_authorized_by_user
            &&  !$token->is_exchanged_to_access_token
            &&  !$token->is_expired) {
            return $self->error(q{Invalid token});
        }
        return $token->secret; 
    }

    sub get_access_token_secret {
        my ($self, $token_string) = @_;
        my $token = MyDB::Scheme->resultset('AccessToken')->find($token_string);
        unless ($token
            && !$token->is_expired) {
            return $self->error(q{Invalid token});
        }
        return $token->secret; 
    }

    sub get_consumer_secret {
        my ($self, $consumer_key) = @_;
        my $consumer = MyDB::Shceme->resultset('Consumer')->find($consumer_key);
        unless ($consumer
             && $consumer->is_valid) {
            return $self->error(q{Inalid consumer_key});
        }
        return $consumer->secret;
    }

    sub publish_request_token {
        my ($self, $consumer_key) = @_;
        my $token = OAuth::Lite::Token->new_random;
        MyDB::Scheme->resultset('RequestToken')->create({
            token        => $token->token,
            secret       => $token->secret,
            realm        => $self->realm,
            consumer_key => $consumer_key,
            expired_on   => '',
        });
        return $token;
    }

    sub publish_access_token {
        my ($self, $consumer_key, $request_token_string) = @_;
        my $request_token = MyDB::Scheme->resultset('RequestToken')->find($request_Token_string);
        unless ($request_token
            &&  $request_token->is_authorized_by_user
            && !$request_token->is_exchanged_to_access_token
            && !$request_token->is_expired) {
            return $self->error(q{Invalid token});
        }
        my $access_token = OAuth::Lite::Token->new_random;
        MyDB::Scheme->resultset('AccessToken')->create({
            token        => $request_token->token, 
            realm        => $self->realm,
            secret       => $request_token->secret,
            consumer_key => $consumer_key,
            author       => $request_token->author,
            expired_on   => '',
        });

        $request_token->is_exchanged_to_access_token(1);
        $request_token->update();

        return $access_token;
    }

    sub check_nonce_and_timestamp {
        my ($self, $consumer_key, $nonce, $timestamp) = @_;
        my $request_log = MyDB::Scheme->resultset('RequestLog');
        # check against replay-attack
        my $count = $request_log->count({
            consumer_key => $consumer_key,
            -nest => [
                nonce     => $nonce,
                timestamp => { '>' => $timestamp }, 
            ], 
        });
        if ($count > 0) {
            return $self->error(q{Invalid timestamp or consumer});
        }
        # save new request log.
        $request_log->create({
            consumer_key => $consumer_key,
            nonce        => $nonce,
            timestamp    => $timestamp,
        });
        return 1;
    }

    sub service {
        my ($self, $params) = @_;
    }

in httpd.conf

    PerlSwitches -I/var/www/MyApp/lib
    PerlModule MyServiceWithOAuth

    <VirtualHost *>

        ServerName api.example.com
        DocumentRoot /var/www/MyApp/root

        PerlSetVar Realm "http://api.example.com/picture"

        <Location /picture/request_token>
            SetHandler perl-script
            PerlSetVar Mode REQUEST_TOKEN
            PerlResponseHandler MyServiceWithOAuth
        </Location>

        <Location /picture/access_token>
            SetHandler perl-script
            PerlSetVar Mode ACCESS_TOKEN
            PerlResponseHandler MyServiceWithOAuth
        </Location>

        <Location /picture/resource>
            SetHandler perl-script
            PerlSetVar Mode PROTECTED_RESOURCE
            PerlResponseHandler MyServiceWithOAuth
        </Location>

    </VirtualHost>

=head1 DESCRIPTION

This module is for mod_perl2 PerlResponseHandler, and allows you to
build services with OAuth easily.

=head1 TUTORIAL

All you have to do is to make a package inheritting this module,
and override some methods, and in httpd.conf file, write
three configuration, each configuration needs to be set Mode value.
The each value must be REQUEST_TOKEN, ACCESS_TOKEN, or PROTECTED_RESOURCE.
And the Realm value is needed for each resource.

The methods you have to override is bellow.

=head1 METHODS YOU HAVE TO OVERRIDE

=head2 init

In this method, you can do some initialization.
For example, set what signature method your service supports,
and what extra-param is allowed.

    sub init {
        my $self = shift;
        $self->oauth->support_signature_method(qw/HMAC-SHA1 PLAINTEXT/);
        $self->oauth->allow_extra_params(qw/file size/);
    }

=head2 get_request_token_secret($token_string)

In this method, you should check if the request-token-string is
valid, and returns token-secret value corresponds to the
token value passed as argument.
If the token is invalid, you should call 'error' method.

=head2 get_access_token_secret($token_string)

In this method, you should check if the access-token-string is
valid, and returns token-secret value corresponds to the
token value passed as argument.
If the token is invalid, you should call 'error' method.

=head2 get_consumer_secret($consumer_key)

In this method, you should check if the consumer_key is valid,
and returns consumer_secret value corresponds to the consumer_key
passed as argument.
If the consumer is invalid, you should call 'error' method.

=head2 check_nonce_and_timestamp($consumer_key, $nonce, $timestamp)

Check passed nonce and timestamp.
Among requests the consumer send service-provider, there shouldn't be
same nonce, and new timestamp should be greater than old ones.
If they are valid, returns 1, or returns 0.

=head2 publish_request_token($consumer_key)

Create new request-token, and save it,
and returns it as L<OAuth::Lite::Token> object.

=head2 publish_access_token($consumer_key, $request_token_string)

If the passed request-token is valid,
create new access-token, and save it,
and returns it as L<OAuth::Lite::Token> object.
And disables the exchanged request-token.

=head2 service($params)

Handle protected resource.
This method should returns Apache2::Const::OK.

    sub service {
        my ($self, $params) = @_;
        my $token_string = $params->{oauth_token};
        my $access_token = MyDB::Scheme->resultset('RequestToken')->find($token_string);
        my $user = $access_token->author;

        my $resource = $user->get_my_some_resource();

        $self->request->status(200);
        $self->set_authenticate_header();
        $self->request->content_type(q{text/html; charset=utf-8});
        $self->print($resource);
        return Apache2::Const::OK;
    }

=head1 API

=head2 handler

Trigger method as response handler.

=head2 new

Constructor

=head2 request

Returns Apache request object.
See L<Apache2::RequestRec>, L<Apache2::RequestIO>, and etc...

    $self->request;

=head2 realm

The realm value you set in httpd.conf by PerlSetVar.

=head2 oauth

Returns l<OAuth::Lite::ServerUtil> object.

=head2 request_body

Requets body data when the request's http-method is POST or PUT

=head2 set_authenticate_header

Set proper 'WWW-Authentication' response header

=head2 error

L<Class::ErrorHandler> method.
In some check-method, when you find invalid request value,
call this method with error message and return it.

    sub check_nonce_and_timestamp {
        my ($self, $consumer_key, $nonce, $timestamp) = @_;
        if ($timestamp ...) {
            return $self->error(q{Invalid timestamp});
        }
        return 1;
    }

=head2 errstr

L<Class::ErrorHandler> method.
You can get error message that you set with error method.

    my $valid = $self->check_nonce_and_timestamp($consumer_key, $nonce, $timestamp);
    if (!$valid) {
        return $self->errout(401, $self->errstr);
    }

=head2 errout($code, $message)

Output error message. This returns Apache2::Const::OK,
so, don't forget 'return';

    return $self->errout(400, q{Bad request});

And you can override this and put some function into this process.
For example, logging.

    sub errout {
        my ($self, $code, $message) = @_;
        $self->my_log_process($code, $message);
        return $self->SUPER::errout($code, $message);
    }

    sub my_log_process {
        my ($self, $code, $message) = @_;
        warn ...
    }

=cut

sub handler : method {
    my $class = shift;
    my $server = $class->new(@_);
    return $server->__service();
}

sub new {
    my $class = shift;
    my $r = shift;
    my $self = bless {
        request => $r,
        oauth   => OAuth::Lite::ServerUtil->new,
        realm   => undef,
        secure  => 0,
        mode    => PROTECTED_RESOURCE,
    }, $class;
    my $realm = $self->request->dir_config('Realm');
    $self->{realm} = $realm if $realm;
    my $mode = $self->request->dir_config('Mode');
    if ($mode) {
        if (none { $mode eq $_ } (PROTECTED_RESOURCE, REQUEST_TOKEN, ACCESS_TOKEN)) {
            die "Invalid mode."; 
        } else {
            $self->{mode} = $mode;
        }
    }
    if ( ($INC{'Apache2/ModSSL.pm'} && $r->connection->is_https)
      || ($r->subprocess_env('HTTPS') && $r->subprocess_env('HTTPS') eq 'ON') ) {
        $self->{secure} = 1;
    }
    $self->init(@_);
    $self;
}

sub init {
    my ($self, %args) = @_;
}

sub request_body {
    my $self = shift;
    unless (defined $self->{_request_body}) {
        my $length = $self->request->headers_in->{'Content-Length'} || 0;
        my $body = "";
        while ($length) {
            $self->request->read( my $buffer, ($length < 8192) ? $length : 8192 );
            $length -= bytes::length($buffer);
            $body .= $buffer;
        }
        $self->{_request_body} = $body;
    }
    $self->{_request_body};
}

sub __service {
    my $self = shift;
    my $realm;
    my $params = {};
    my $authorization = $self->request->headers_in->{Authorization};
    if ($authorization && $authorization =~ /^\s*OAuth/) {
        ($realm, $params) = parse_auth_header($authorization);
    } elsif ( uc($self->request->method) eq 'POST'
          &&  $self->request->headers_in->{'Content-Type'} =~ m!application/x-www-form-urlencoded!) {
        for my $pair (split /&/, $self->request_body) {
            my ($key, $value) = split /=/, $pair;
            $params->{$key} = decode_param($value);
        }
    }
    for my $pair (split /&/, $self->request->args) {
        my ($key, $value) = split /=/, $pair;
        $params->{$key} = decode_param($value);
    }

    my $needs_to_check_token =  $self->__is_required_request_token
                             ? 0
                             : 1;

    unless ($self->oauth->validate_params($params, $needs_to_check_token)) {
        return $self->errout(400, $self->oauth->errstr);
    }

    my $consumer_key = $params->{oauth_consumer_key};
    my $timestamp    = $params->{oauth_timestamp};
    my $nonce        = $params->{oauth_nonce};

    my $consumer_secret = $self->get_consumer_secret($consumer_key);
    unless (defined $consumer_secret) {
        return $self->errout(401, $self->errstr || q{Invalid consumer key});
    }

    $self->check_nonce_and_timestamp($consumer_key, $nonce, $timestamp)
        or return $self->errout(400, $self->errstr || q{Invalid parameter});

    my $uri = URI->new;
    $uri->scheme( $self->{secure} ? 'https' : 'http' );
    $uri->host( $self->request->get_server_name );
    $uri->port( $self->request->get_server_port );
    $uri->path( $self->request->uri );

    my $request_uri = $uri->as_string;

    if ($self->__is_required_request_token) {

        $self->oauth->verify_signature(
            method          => $self->request->method, 
            params          => $params,
            url             => $request_uri,
            consumer_secret => $consumer_secret,
        ) or return $self->errout(401, q{Invalid signature});

        my $request_token = $self->publish_request_token($consumer_key);
        return $self->__output_token($request_token);

    } elsif ($self->__is_required_access_token) {

        my $token_value = $params->{oauth_token};
        my $token_secret = $self->get_request_token_secret($token_value);
        unless (defined $token_secret) {
            return $self->errout(401, $self->errstr || q{Invalid token}); 
        }
        $self->oauth->verify_signature(
            method          => $self->request->method, 
            params          => $params,
            url             => $request_uri,
            consumer_secret => $consumer_secret || '',
            token_secret    => $token_secret || '',
        ) or return $self->errout(401, q{Invalid signature});
        my $access_token = $self->publish_access_token($consumer_key, $token_value)
            or return $self->errout(401, $self->errstr);
        return $self->__output_token($access_token);

    } else {

        my $token_value = $params->{oauth_token};
        my $token_secret = $self->get_access_token_secret($token_value);
        unless (defined $token_secret) {
            return $self->errout(401, q{Invalid token});
        }

        $self->oauth->verify_signature(
            method          => $self->request->method, 
            params          => $params,
            url             => $request_uri,
            consumer_secret => $consumer_secret || '',
            token_secret    => $token_secret || '',
        ) or return $self->errout(401, q{Invalid signature});

        return $self->service($params);
    }
}

sub __output_token {
    my ($self, $token) = @_;
    my $token_string = $token->as_encoded;
    $self->set_authenticate_header();
    $self->request->status(200);
    $self->request->content_type(q{text/plain; charset=utf-8});
    $self->request->set_content_length(bytes::length($token_string));
    $self->request->print($token_string);
    return Apache2::Const::OK;
}

sub __is_required_request_token {
    my $self = shift;
    return ($self->{mode} eq REQUEST_TOKEN) ? 1 : 0;
}

sub __is_required_access_token {
    my $self = shift;
    return ($self->{mode} eq ACCESS_TOKEN) ? 1 : 0;
}

sub service {
    my ($self, $params) = @_;
}

sub get_request_token_secret {
    my ($self, $token) = @_;
    my $secret;
    return $secret;
}

sub get_access_token_secret {
    my ($self, $token) = @_;
    my $secret;
    return $secret;
}

sub get_consumer_secret {
    my ($self, $consumer_key);
    my $consumer_secret;
    return $consumer_secret;
}

sub publish_request_token {
    my ($self, $consumer_key) = @_;
    my $token = OAuth::Lite::Token->new;
    return $token;
}

sub publish_access_token {
    my ($self, $request_token_string) = @_;
    # validate request token
    # and publish access token
    # return $token;
    my $token = OAuth::Lite::Token->new;
    return $token;
}

sub check_nonce_and_timestamp {
    my ($self, $consumer_key, $timestamp, $nonce) = @_;
    return $self->error(q{Invalid Consumer});
    return $self->error(q{Invalid Timestamp});
    return $self->error(q{Invalid Nonce});
    return 1;
}

sub set_authenticate_header {
    my $self = shift;
    $self->request->err_headers_out->add( 'WWW-Authenticate',
        sprintf(q{OAuth realm="%s"}, $self->realm));
}

sub errout {
    my ($self, $code, $message) = @_;
    $self->set_authenticate_header();
    $self->request->status($code);
    $self->request->content_type(q{text/plain; charset=utf-8});
    $self->request->set_content_length(bytes::length($message));
    $self->request->print($message);
    return Apache2::Const::OK;
}

=head1 SEE ALSO

L<OAuth::Lite::ServerUtil>
L<OAuth::Lite::Server::Test::Echo>

=head1 AUTHOR

Lyo Kato, C<lyo.kato _at_ gmail.com>

=head1 COPYRIGHT AND LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

