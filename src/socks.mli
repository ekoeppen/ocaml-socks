open Socks_types

(** SOCKS CONNECT parsing and generation *)

(** This library implements functions for parsing and generating
    the packets required to establish connections using SOCKS CONNECT (versions 4A and 5).

    The parsing functions prefixed with [parse_] return unconsumed bytes in a [type Socks_types.leftover_bytes = string].

    This version of the library does not handle BIND and UDP methods since
    I haven't seen that in use anywhere).
*)

(** {2:basic General functions} *)

val parse_request : string -> request_result
(** [parse_request buf] parses the given [buf] and returns a [request_result]
    which matches the content.

    Valid requests are either SOCKS 5 authentication requests, or SOCKS 4A CONNECT requests. *)

(** {2:basic Functions specific to SOCKS 5} *)

val make_socks5_auth_request : username_password:bool -> string
(** [make_socks5_auth_request ~username_password] returns a binary
    string which represents a SOCKS5 authentication request.
    In the protocol this is a list of authentication modes that the client is willing to use, but in our API it's a choice between "no auth methods" and "username/password".

    This library only supports "no auth" and "username/password" authentication.
*)

(** [parse_socks5_auth_request data] is contained within [parse_request]
*)

val make_socks5_auth_response : socks5_authentication_method -> string
(** [make_socks5_auth_response auth_method] returns a binary string which
    represents a SOCKS5 authentication response. *)

val make_socks5_username_password_request :
  username:string -> password:string -> (string,unit) Result.result
(** [make_socks5_username_password_request ~username ~password] returns a
    binary string which represents a SOCKS5 password request from [RFC1929].
    The function fails if either of the strings are longer than 255 bytes, or contain 0 bytes.
*)

val parse_socks5_username_password_request :
  string -> socks5_username_password_request_parse_result
(** [parse_socks5_username_password_request buf] parses the given [buf] and
    returns either an [Incomplete_request] or a
    [socks5_username_password_request_parse_result]. *)

val socks5_authentication_method_of_char : char -> socks5_authentication_method
(** [socks5_authentication_method_of_char char] is a conversion function which
    translates the given character to a [socks5_authentication_method]
    value. If no matches were found, the value is [No_acceptable_methods]. *)

val make_socks5_request : socks5_request -> (string, request_invalid_argument) Result.result
(** [make_socks5_request (Connect|Bind {address; port}) ]
    returns a binary string which represents a SOCKS5 request as described in RFC 1928 section "4.  Requests" (on page 3).
    For DOMAINNAME addresses the length of the domain must be 1..255
*)

val parse_socks5_connect :
  string ->
  (socks5_struct * leftover_bytes, socks5_username_password_request_parse_result)
  Result.result
(** [parse_socks5_connect buf] returns an OK result with port and hostname
    if [buf] represents a SOCKS5 CONNECT command with the DOMAINNAME form.
    If anything is amiss, it will return [R.error] values, wrapping
    [Invalid_argument], [Invalid_request] and [Incomplete_request]. *)

val make_socks5_response : socks5_reply_field -> bnd_port:int -> socks5_address ->(string, unit) result
(** [make_socks5_response reply_field ~bnd_port address] returns a binary string which represents the response to a SOCKS5 action (CONNECT|BIND|UDP_ASSOCIATE).
 NB that for e.g. BIND you will need to send several of these.
 TODO reference RFC section.
*)

val parse_socks5_response : string -> (socks5_reply_field * socks5_struct * leftover_bytes, socks5_response_error) result
(** [parse_response response_string]
  TODO document. But basically it returns the error code (if any), and the remote bound address/port info from the server.
*)
