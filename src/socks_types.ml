(* types for SOCKS4; SOCKS4A; SOCKS5 *)

type socks4_request =
  { port    : int
  ; address : string
  ; username : string }

type socks5_connect =
  { port    : int
  ; address : string }

type socks5_method_selection_request = socks5_authentication_method list

type request_result =
  | Invalid_request
  | Incomplete_socks4_request (* The user should read more bytes and call again *)
  | Incomplete_socks5_method_selection_request
  | Socks5_method_selection_request of socks5_method_selection_request * bytes
  | Socks4_request of socks4_request

type response_error =
  | Rejected
  | Incomplete_response (* The user should read more bytes and call again *)

type socks5_username = string
type socks5_password = string

type socks5_authentication_method =
  | No_authentication_required
  | Username_password of (socks5_username * socks5_password)
  | No_acceptable_methods

type socks5_reply_field =
  | Succeeded
  | Failure
