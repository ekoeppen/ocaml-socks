open Socks_types

(** SOCKS header parsing and generation *)

(** This library implements functions for parsing and generating SOCKS4A
    CONNECT headers (the current version does not handle BIND since
    I haven't seen that in use anywhere). *)

val make_socks4_request : username:string -> hostname:string -> int -> (string, request_invalid_argument) Result.result
(** [make_socks4_request ~username ~hostname port] returns a binary string
    which represents a SOCKS4A request.
    The SOCKS4A protocol does not support password authentication.
*)

val make_socks5_auth_request : username:string -> password:string -> string
(** [make_socks5_auth_request ~username ~password ] returns a binary
    string which represents a SOCKS5 authentication request.
    This library only supports username/password authentication.
*)

val make_socks5_auth_response : socks5_authentication_method -> string
(** [make_socks5_auth_response auth_method] returns a binary string which
    represents a SOCKS5 authentication response. *)

val make_socks5_request : string -> int -> (string, request_invalid_argument) Result.result
(** [make_socks5_request hostname port] returns a binary string which
    represents a SOCKS5 request which comprises a CONNECT operation with the
    ATYP (address type) set to 'DOMAINNAME'.
    The length of DOMAINNAME must be 1..255
*)

val make_socks5_response : bnd_port:int -> socks5_reply_field -> string
(** [make_socks5_response ~bnd_port reply_field] returns a binary string which
    represents a SOCKS5 response. *)

val make_socks5_username_password_request :
  username:string -> password:string -> string
(** [make_socks5_username_password_request ~username ~password] returns a
    binary string which represents a SOCKS5 password request. *)

val parse_socks5_username_password_request :
  string -> socks5_username_password_request_parse_result
(** [parse_socks5_username_password_request buf] parses the given [buf] and
    returns either an [Incomplete_request] or a
    [socks5_username_password_request_parse_result]. *)

val make_response : success:bool -> string
(** [make_response success] returns a binary string which represents a granted
    or rejected response. *)

val socks5_authentication_method_of_char : char -> socks5_authentication_method
(** [socks5_authentication_method_of_char char] is a conversion function which
    translates the given character to a [socks5_authentication_method]
    value. If no matches were found, the value is [No_acceptable_methods]. *)

val parse_socks5_connect :
  string ->
  (socks5_connect * leftover_bytes, socks5_username_password_request_parse_result)
  Result.result
(** [parse_socks5_connect buf] returns an OK result with port and hostname
    if [buf] represents a SOCKS5 CONNECT command with the DOMAINNAME form.
    If anything is amiss, it will return [R.error] values, wrapping
    [Invalid_argument], [Invalid_request] and [Incomplete_request]. *)

val parse_request : string -> request_result
(** [parse_request buf] parses the given [buf] and returns a [request_result]
    which matches the content. For SOCKS5, the CONNECT method is supported.
    Either it is a SOCKS5 authentication request.
    Or, it's a SOCKS 4 CONNECT request, either using a domain name or an IPv4
    IP address. *)

val parse_response : string -> (leftover_bytes, response_error) Result.result
(** [parse_response result] returns an OK [Result.result] with a unit value on
    success, and a [Rejected] on failure. Bad values return an
    [Incomplete_response]. *)
