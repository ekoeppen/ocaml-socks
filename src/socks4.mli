type socks4_request =
  { port    : int
  ; address : string
  ; username : string }

type request_result =
  | Invalid_request
  | Incomplete_request (* The user should read more bytes and call again *)

type response_error =
  | Incomplete_response (* The user should read more bytes and call again *)
  | Rejected

val make_request : username:string  -> string -> int -> string
val make_response : success:bool -> string
val parse_request : string -> (socks4_request, request_result) Result.result
val parse_response : string -> (unit , response_error) Result.result

