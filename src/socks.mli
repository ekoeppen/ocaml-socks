val make_socks4_request : username:string -> string -> int -> string
val make_socks5_auth_request : username:'a -> 'b -> 'c -> string
val make_socks5_auth_response :
  Socks_types.socks5_authentication_method -> string
val make_socks5_request : string -> int -> string
val make_socks5_response :
  bnd_port:int -> Socks_types.socks5_reply_field -> string
val make_socks5_username_password_request :
  username:string -> password:string -> string
val parse_socks5_username_password_request :
  string -> Socks_types.socks5_username_password_request_parse_result
val make_response : success:bool -> string
val socks5_authentication_method_of_char :
  char -> Socks_types.socks5_authentication_method
val parse_socks5_connect :
  bytes ->
  (Socks_types.socks5_connect,
   Socks_types.socks5_username_password_request_parse_result)
  Result.result
val parse_request : bytes -> Socks_types.request_result
val parse_response :
  bytes -> (unit, Socks_types.response_error) Result.result
