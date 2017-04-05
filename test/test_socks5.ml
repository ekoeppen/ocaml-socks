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

let test_parse_socks5_connect _ =
  let header = "\x05\x01\x00\x03" in
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"testing socks5: parse_socks5_connect"
  (quad small_int small_int small_string small_string)
  @@ (fun (truncation, port, address, extraneous) ->
  let connect_string = header
                     ^ (char_of_int String.(length address)|> String.make 1)
                     ^ address
                     ^ (bigendian_port_of_int port)
                     ^ extraneous
  in
  let valid_request_len = String.(length header) + 1 + String.(length address) + 2 in
  let truncated_connect_string = String.sub connect_string 0 (min String.(length connect_string) truncation) in
  begin match parse_socks5_connect connect_string with
  | Error Invalid_request when 0 = String.length address -> true
  | Ok ({port = parsed_port; address = Domain_address parsed_address}, parsed_leftover)
    when port = parsed_port
      && address = parsed_address
      && parsed_leftover = extraneous
    ->
    begin match parse_socks5_connect truncated_connect_string with
    | Error Incomplete_request when truncation < valid_request_len -> true
    | Ok ({port = truncated_port; address = Domain_address truncated_address}, truncated_leftover)
      when port = truncated_port
        && address = truncated_address
        && truncated_leftover = String.sub extraneous 0 (min String.(length extraneous) (truncation-valid_request_len))
      -> true
    | _ -> false
    end
  | Error Incomplete_request -> false
  | _ -> false
  end
  )
;;

let test_make_socks5_response _ =
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"testing socks5: make_socks5_response"
  (pair small_int bool)
  @@ (fun (bnd_port, reply) ->
    let reply = begin match reply with true -> Succeeded | false -> Socks_types.Failure end in
    begin match make_socks5_response ~bnd_port reply with
    | Ok _ -> true
    | Error () -> false
    end
  )
;;

let test_parse_socks5_response_ipv4 _ =
  (* this test only deals with IPv4 addresses *)
  let header = "\x05\x00\x00\x01" in
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"testing socks5: parse_socks5_response"
  (triple int small_int small_string)
  @@ (fun (ip_int, port, extraneous) ->
    let ip = Ipaddr.V4.(of_int32 (Int32.of_int ip_int) |> to_bytes) in
    let response = header ^ ip ^ (bigendian_port_of_int port) ^ extraneous in
    begin match parse_socks5_response response with
    | Bound_ipv4 (parsed_ip, parsed_port, parsed_leftover)
      when ip = Ipaddr.V4.(begin match of_string parsed_ip with Some i -> to_bytes i end)
        && parsed_port = port
        && parsed_leftover = extraneous -> true
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
  "socks5: parse_socks5_connect" >:: test_parse_socks5_connect;
  "socks5: make_socks5_response" >:: test_make_socks5_response;
  "socks5: parse_socks5_response (ipv4)" >:: test_parse_socks5_response_ipv4;
  ]
