(* A SOCKS4a helper. Wraps a Lwt file_descr

*)

open Lwt
open Socks

let connect_client (username : string)
                   (proxy_fd_in   : Lwt_io.input_channel)
                   (proxy_fd_out  : Lwt_io.output_channel)
                    hostname port : bool Lwt.t =
  let message = Socks4.make_request ~username hostname port in
  try_lwt
  Lwt_io.write proxy_fd_out message >>= fun () ->
  Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun result ->
  (*TODO handle case when fewer than 8 bytes are read *)
  if Result.Ok () = Socks4.parse_response result
  then return true
  else return false
  with
  | End_of_file -> return false

let receive_request (client_fd_in : Lwt_io.input_channel) =
  (* read minimum amount of bytes needed*)
  let open Result in
  let rec read_request header =
    begin match parse_request header with
    | Error Incomplete_request ->
      Lwt_io.read ~count:1 client_fd_in
      >>= (function
      | "" -> return @@ Result.Error Invalid_request
      | s  -> read_request @@ String.concat "" [header ; s])
    | result -> return result
    end
  in read_request ""
