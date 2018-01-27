type socks5_address =
| IPv4_address of Ipaddr.V4.t
| IPv6_address of Ipaddr.V6.t
| Domain_address of string

type socks5_struct =
  { port    : int
  ; address : socks5_address }

type socks5_request =
| Connect of socks5_struct
| Bind of socks5_struct
| UDP_associate of socks5_struct

type request_invalid_argument = Invalid_hostname | Invalid_port

type socks5_username = string
type socks5_password = string
type leftover_bytes = string

type socks5_authentication_method =
  | No_authentication_required
  | GSSAPI
  | Username_password of (socks5_username * socks5_password)
  | No_acceptable_methods

type socks5_method_selection_request = socks5_authentication_method list

type socks5_reply_field =
  | (* 0 *) Succeeded
  | (* 1 *) General_socks_server_failure
  | (* 2 *) Connection_not_allowed_by_ruleset
  | (* 3 *) Network_unreachable
  | (* 4 *) Host_unreachable
  | (* 5 *) Connection_refused
  | (* 6 *) TTL_expired
  | (* 7 *) Command_not_supported
  | (* 8 *) Address_type_not_supported
  | (* _ *) Unassigned

type socks5_response_error =
  | Incomplete_response
  | Invalid_response

type socks5_username_password_request_parse_result =
  | Incomplete_request
  | Invalid_request
  | Username_password of socks5_username * socks5_password * leftover_bytes

val make_socks5_auth_request : username_password:bool -> string

val parse_socks5_auth_response : string -> socks5_authentication_method

val make_socks5_auth_response : socks5_authentication_method -> string

val make_socks5_username_password_request :
  username:string -> password:string -> (string,unit) Result.result

val make_socks5_request : socks5_request -> (string, request_invalid_argument) Result.result

val parse_socks5_response : string -> (socks5_reply_field * socks5_struct * leftover_bytes, socks5_response_error) result
