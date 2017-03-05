open Rresult
open QCheck
open QCheck.Test
open OUnit2
open Socks

let bigendian_port_of_int port =
  String.concat ""
    [
      (port land 0xff00) lsr 8 |> char_of_int |> String.make 1
    ;  port land 0xff          |> char_of_int |> String.make 1
    ]

let test_making_a_request ctx =
  check_exn @@ QCheck.Test.make ~count:10000
    ~name:"making a request is a thing"
    (triple string string small_int)
    @@ (fun (username, hostname, port) ->
      (make_socks4_request ~username hostname port
      = "\x04\x01"
      ^ bigendian_port_of_int port
      ^ "\x00\x00\x00\xff"
      ^ username ^ "\x00"
      ^ hostname ^ "\x00");)
;;

let suite = [
  "test_making_a_request" >:: test_making_a_request;
  ]
