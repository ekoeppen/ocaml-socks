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

let small_string = QCheck.Gen.string_size @@ QCheck.Gen.int_range 0 0xff |> QCheck.make
let charz = QCheck.Gen.(int_range 1 0xff |> map char_of_int) |> QCheck.make

let test_make_socks5_auth_request _ =
  begin match
    make_socks5_auth_request ~username_password:true
  , make_socks5_auth_request ~username_password:false
  with
  | "\x05\x01\x02"
  , "\x05\x01\x00" -> ()
  | _ -> failwith ("make_socks5_auth_request doesn't work")
  end

let test_make_socks5_auth_response _ =
  begin match
    make_socks5_auth_response No_authentication_required
  , make_socks5_auth_response (Username_password ("" , ""))
  , make_socks5_auth_response No_acceptable_methods
  with
  | "\x05\x00"
  , "\x05\x02"
  , "\x05\xff"
  -> ()
  | _ -> failwith "make_socks5_auth_response doesn't work"
  end

let test_make_socks5_username_password_request _ =
  begin match make_socks5_username_password_request
              ~username:"username"
              ~password:"password"
  with
  | Ok "\x05\x08username\x08password" -> ()
  | _ ->  failwith "test_make_socks5_username_password_request doesn't work"
  end

let test_parse_socks5_username_password_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"parse_socks5_username_password_request"
  (triple small_string small_string small_string)
  @@ (fun (username,password,extraneous) ->
    begin match (make_socks5_username_password_request ~username ~password) with
    | Error () when username = "" -> true
    | Error () when password = "" -> true
    | Error () when 255 < String.length username -> true
    | Error () when 255 < String.length password -> true
    | Ok req ->
      begin match parse_socks5_username_password_request (req ^ extraneous) with
      | Username_password (u, p, x) when u=username && p=password && x=extraneous ->true
      | _ -> assert false
      end
    | _ -> assert false
    end
  )

let test_making_a_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
    ~name:"making a request is a thing"
    (pair string small_int)
    @@ (fun (hostname, port) ->
      begin match make_socks5_request hostname port with
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
    )
;;

let test_parse_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"testing socks5: parse_request"
  (pair small_string string)
  @@ (fun (methods, extraneous) ->
     let data = "\x05"
              ^ String.(length methods |> char_of_int |> make 1)
                ^ methods
              ^ extraneous
     in let data_len = String.length data in
     begin match parse_request data with
     | Socks5_method_selection_request ([], _) ->
         false (* This should be an Invalid_request *)
     | Socks5_method_selection_request (mthds, _)
       when List.(length mthds <> String.length methods) ->
         false
     | Socks5_method_selection_request (_, x)
       when x <> extraneous -> false

     | Socks5_method_selection_request (authlst, x)
       when not @@ List.mem No_acceptable_methods authlst
            && authlst <> []
            && x = extraneous -> true
         (*when there is at least one auth method, and the extraneous matches *)

     | Incomplete_request
       when data_len < 1+1 + String.(length methods + length extraneous)
       -> true (* Up to and including missing one byte we ask for more *)

     | Incomplete_request -> false
     | Socks4_request _ -> false

     | Invalid_request ->
         true (* Expected behavior is to reject invalid requests; hence true *)
     | _ -> false
     end
     )
;;

let suite = [
  "socks5: make_socks5_auth_request" >:: test_make_socks5_auth_request;
  "socks5: parse_request" >:: test_parse_request;
  "socks5: make_socks5_username_password_request" >:: test_make_socks5_username_password_request;
  "socks5: parse_socks5_username_password_request" >:: test_parse_socks5_username_password_request;
  "socks5: make_socks5_request" >:: test_making_a_request;
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
