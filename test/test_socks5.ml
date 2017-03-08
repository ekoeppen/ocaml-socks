open QCheck
open QCheck.Test
open OUnit2
open Socks
open Socks_types

let bigendian_port_of_int port =
  String.concat ""
    [
      (port land 0xff00) lsr 8 |> char_of_int |> String.make 1
    ;  port land 0xff          |> char_of_int |> String.make 1
    ]

let test_making_a_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
    ~name:"making a request is a thing"
    (pair string small_int)
    @@ (fun (hostname, port) ->
      (begin match make_socks5_request hostname port with
       | Ok data ->  data = "\x05\x01\x00" (* VER CMD RSV = [5; CONNECT; reserved] *)
                          ^ "\x03" (* ATYP = DOMAINNAME *)
                          ^ String.(length hostname |> char_of_int |> make 1)
                          ^ hostname
                          ^ (bigendian_port_of_int port)
       | Error (Invalid_hostname : request_invalid_argument)
           when 0 = String.length hostname  
           || 255 < String.length hostname -> true
       | _ -> false
       end
      );
    )
;;

let suite = [
  "make_socks5_request" >:: test_making_a_request;
  ]
(*
open OUnit2
open Socks
open Socks_types
open Rresult

let is_invalid (r : request_result) =
  r = Invalid_request

let is_incomplete (r : request_result) =
  r = Incomplete_request

let is_request = function Ok _ -> true | _ -> false

let test_make_request _ =
  let username = "myusername" in
  let hostname = "example.com" in
  assert_bool "example.com:4321"
    (make_socks5_request ~username "example.com" 4321
    = "\x04\x01"
    ^ "\x10\xe1" (* port *)
    ^ "\x00\x00\x00\xff"
    ^ username ^ "\x00"
    ^ hostname ^ "\x00")
;;

let test_make_response _ =
  let empty_ip_and_port = "\x00\x00" ^ "\x00\x00\x00\x00" in
  assert_equal (make_response ~success:true)
  ("\x00\x5a" ^ empty_ip_and_port)
  ;;
  let empty_ip_and_port = "\x00\x00" ^ "\x00\x00\x00\x00" in
  assert_equal (make_response ~success:false)
  ("\x00\x5b" ^ empty_ip_and_port)
  ;;

let invalid_requests _ =
  assert_bool "invalid protocol" (is_invalid (parse_request "\x00\x001234567")) ;;

let incomplete_requests _ =
  "\x04"
  |> parse_request |> is_incomplete |> assert_bool
  "8 bytes" ;;

let requests _ =
  let r = make_socks4_request ~username:"user" "host" 515 in
  begin match parse_request (r ^ "X") with
  | Socks4_request (pr , "X") ->
      (pr.port = 515 && pr.username = "user"
       && pr.address = "host")
  | _ -> false
  end |> assert_bool
  "self-check request" ;;

(** TODO: OUnit2 should detect test cases automatically. *)
let suite = [
    "make_request" >:: test_make_request;
    "make_response" >:: test_make_response;
    "parse_request: invalid_requests" >:: invalid_requests;
    "parse_request: incomplete_requests" >:: incomplete_requests;
    "is_request" >:: requests;
  ]
*)
