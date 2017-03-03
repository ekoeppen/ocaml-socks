(* A SOCKS4a helper. Wraps a Lwt file_descr

*)

open Lwt
open Socks
open Socks_types

let connect_client (username : string)
                   (proxy_fd_in   : Lwt_io.input_channel)
                   (proxy_fd_out  : Lwt_io.output_channel)
                    hostname port : bool Lwt.t =
  let message = Socks.make_socks4_request ~username hostname port in
  try%lwt
  Lwt_io.write proxy_fd_out message >>= fun () ->
  Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun result ->
  (*TODO handle case when fewer than 8 bytes are read *)
  if Result.Ok () = Socks.parse_response result
  then return true
  else return false
  with
  | End_of_file -> return false

let receive_request (client_fd_in : Lwt_io.input_channel) : Socks_types.request_result Lwt.t =
  (* read minimum amount of bytes needed*)
  let rec read_request header =
    begin match ((parse_request header) : request_result) with
    | Incomplete_request ->
      Lwt_io.read ~count:1 client_fd_in
      >>=
      (function
          | "" -> return @@ (Invalid_request : request_result)
          | s  -> read_request @@ String.concat "" [header ; s]
      )
    | result -> return result
    end
  in read_request ""
