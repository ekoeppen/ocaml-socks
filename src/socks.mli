open Socks_types

val make_request : username:string  -> string -> int -> string
val make_response : success:bool -> string
val parse_request : string -> (socks4_request, request_result) Result.result
val parse_response : string -> (unit , response_error) Result.result

