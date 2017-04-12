(* SOCKS helper. Wraps a Lwt file_descr *)

open Rresult
open Lwt
open Socks
open Socks_types

let connect_socks4_client (username : string)
                   (proxy_fd_in   : Lwt_io.input_channel)
                   (proxy_fd_out  : Lwt_io.output_channel)
                    hostname port : bool Lwt.t =
  let rec read_request socks_header =
    begin match Socks.parse_socks4_response socks_header with
    | Error Incomplete_response ->
      Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun new_header ->
      read_request (socks_header ^ new_header)
    | x -> Lwt.return x
    end
  in
  try%lwt
    R.bind (Socks.make_socks4_request ~username ~hostname port)
    (fun out_request ->
    Lwt_io.write proxy_fd_out out_request >>= fun () ->
    Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun header ->
    read_request header
    ) >>= fun x -> R.reword_error (fun e -> Lwt.return e) x
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
