(* types for SOCKS4; SOCKS4A; SOCKS5 *)

type socks4_request =
  { port    : int
  ; address : string
  ; username : string }

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

type socks4_response_error =
  | Rejected
  | Incomplete_response (* The user should read more bytes and call again *)

type socks5_username = string
type socks5_password = string
type leftover_bytes = string

type socks5_authentication_method =
  | No_authentication_required
  | Username_password of (socks5_username * socks5_password)
  | No_acceptable_methods

type socks5_method_selection_request = socks5_authentication_method list

type request_result =
  | Invalid_request
  | Incomplete_request (* The user should read more bytes and call again *)
  | Socks5_method_selection_request of socks5_method_selection_request * leftover_bytes
  | Socks4_request of socks4_request * leftover_bytes

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
