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
  check_exn @@ QCheck.Test.make ~count:20000
    ~name:"making a request is a thing"
    (pair string small_int)
    @@ (fun (hostname, port) ->
      begin match make_socks5_request (Connect {address = Domain_address hostname; port}) with
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

let test_parse_socks5_connect _ =
  let header = "\x05\x01\x00\x03" in
  check_exn @@ QCheck.Test.make ~count:20000
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
  check_exn @@ QCheck.Test.make ~count:20000
  ~name:"testing socks5: make_socks5_response"
  (quad small_int bool small_string small_string)
  @@ (fun (bnd_port, reply, domain, extraneous) ->
    let reply = begin match reply with true -> Succeeded | false -> Socks.General_socks_server_failure end in
    let domain_len = String.length domain in
    begin match make_socks5_response ~bnd_port reply (Domain_address domain) with
    | Error () when 0 = domain_len -> true
    | Error () when 255 < domain_len -> true
    | Ok serialized ->
      begin match parse_socks5_response (serialized ^ extraneous) with
      | Ok (_, {address = Domain_address parsed_domain; _}, _)
        when parsed_domain <> domain -> false
      | Ok (_, {port = parsed_port; _}, _)
        when parsed_port <> bnd_port -> false
      | Ok (_, _, leftover_bytes)
        when leftover_bytes <> extraneous -> false
      | Error _ -> false
      | Ok (parsed_reply, {address = Domain_address _; _}, _)
        when parsed_reply = reply -> true
      end
    | Error () -> false
    end
  )
;;

let test_parse_socks5_response_ipv4_ipv6 _ =
  (* this test only deals with IPv4 and IPv6 addresses *)
  let header = "\x05\x00\x00" in
  check_exn @@ QCheck.Test.make ~count:10000
  ~name:"testing socks5: parse_socks5_response"
  (quad bool int small_int small_string)
  @@ (fun (do_ipv6, ip_int, port, extraneous) ->
    let atyp, ip, ip_bytes =
      begin match do_ipv6 with
      | true ->
        let ip32 = Int32.of_int ip_int in
        let ip = Ipaddr.V6.of_int32 (ip32, ip32, ip32, ip32) in
        "\x04", Ipaddr.V6 ip, Ipaddr.V6.to_bytes ip
      | false ->
        let ip = Ipaddr.V4.of_int32 (Int32.of_int ip_int) in
        "\x01", Ipaddr.V4 ip , Ipaddr.V4.to_bytes ip
      end
    in
    let response = header ^ atyp ^ ip_bytes ^ (bigendian_port_of_int port) ^ extraneous in
    begin match parse_socks5_response response with
    | Ok (_, {port = parsed_port ; _}, _)
      when parsed_port <> port -> failwith (if do_ipv6 then "IPv6 port mismatch" else "IPv4 port mismatch")
    | Ok (_, _, parsed_leftover)
      when parsed_leftover <> extraneous -> failwith "extraneous fail"
    | Ok (Succeeded,  {address = IPv4_address parsed_ip; _}, _)
      when not do_ipv6 ->
        if ip = Ipaddr.V4 parsed_ip then true else failwith "ipv4 er fucked"
    | Ok (Succeeded, {address = IPv6_address parsed_ip; _}, _)
      when do_ipv6 ->
        if ip = Ipaddr.V6 parsed_ip then true else failwith "ipv6 er fucked"
    | _ -> false
    end
  )
;;

let suite = [
  "socks5: make_socks5_auth_request" >:: test_make_socks5_auth_request;
  "socks5: make_socks5_username_password_request" >:: test_make_socks5_username_password_request;
  "socks5: parse_socks5_username_password_request" >:: test_parse_socks5_username_password_request;
  "socks5: make_socks5_request" >:: test_making_a_request;
  "socks5: parse_socks5_connect" >:: test_parse_socks5_connect;
  "socks5: parse_socks5_response (IPv4/IPv6)" >:: test_parse_socks5_response_ipv4_ipv6;
(*"socks5: parse_socks5_response (domainname)" >:: test_parse_socks5_response_domainname;
*)
  "socks5: make_socks5_response" >:: test_make_socks5_response;
  ]
