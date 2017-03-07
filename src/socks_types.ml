(* types for SOCKS4; SOCKS4A; SOCKS5 *)

type socks4_request =
  { port    : int
  ; address : string
  ; username : string }

type socks5_connect =
  { port    : int
  ; address : string }

type response_error =
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

type socks5_username_password_request_parse_result =
  | Incomplete_request
  | Invalid_request
  | Username_password of socks5_username * socks5_password * leftover_bytes

type socks5_reply_field =
  | Succeeded
  | Failure
