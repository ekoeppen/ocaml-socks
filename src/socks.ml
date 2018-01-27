open Rresult

type socks5_address =
| IPv4_address of Ipaddr.V4.t
| IPv6_address of Ipaddr.V6.t
| Domain_address of string

type socks5_struct =
  { port    : int
  ; address : socks5_address }

type socks5_request =
| Connect of socks5_struct
| Bind of socks5_struct
| UDP_associate of socks5_struct

type request_invalid_argument = Invalid_hostname | Invalid_port

type socks5_username = string
type socks5_password = string
type leftover_bytes = string

type socks5_authentication_method =
  | No_authentication_required
  | GSSAPI
  | Username_password of (socks5_username * socks5_password)
  | No_acceptable_methods

type socks5_method_selection_request = socks5_authentication_method list

type socks5_reply_field =
  | (* 0 *) Succeeded
  | (* 1 *) General_socks_server_failure
  | (* 2 *) Connection_not_allowed_by_ruleset
  | (* 3 *) Network_unreachable
  | (* 4 *) Host_unreachable
  | (* 5 *) Connection_refused
  | (* 6 *) TTL_expired
  | (* 7 *) Command_not_supported
  | (* 8 *) Address_type_not_supported
  | (* _ *) Unassigned

type socks5_response_error =
  | Incomplete_response
  | Invalid_response

type socks5_username_password_request_parse_result =
  | Incomplete_request
  | Invalid_request
  | Username_password of socks5_username * socks5_password * leftover_bytes

let bigendian_port_of_int port =
  begin match port with
  | x when 0 <= x && x <= 0xFFFF ->
    R.ok @@
    String.concat ""
    [
      (port land 0xff00) lsr 8 |> char_of_int |> String.make 1
    ;  port land 0xff          |> char_of_int |> String.make 1
    ]
  | _ -> R.error ()
  end

let string_of_socks5_authentication_method : socks5_authentication_method -> string = function
  | No_authentication_required -> "\x00"
  | GSSAPI -> "\x01"
  | Username_password _ -> "\x02"
  | No_acceptable_methods -> "\xFF"

let socks5_authentication_method_of_char : char -> socks5_authentication_method = function
  | '\x00' -> No_authentication_required
  | '\x01' -> GSSAPI
  | '\x02' -> Username_password ("", "")
  | '\x03'..'\xFF' -> No_acceptable_methods

let string_of_socks5_reply_field = function
  | Succeeded -> "\x00"
  | General_socks_server_failure -> "\x01"
  | Connection_not_allowed_by_ruleset -> "\x02"
  | Network_unreachable -> "\x03"
  | Host_unreachable -> "\x04"
  | Connection_refused -> "\x05"
  | TTL_expired -> "\x06"
  | Command_not_supported -> "\x07"
  | Address_type_not_supported -> "\x08"
  | Unassigned -> "\xFF"

let reply_field_of_char = function
  | '\x00' -> Succeeded
  | '\x01' -> General_socks_server_failure
  | '\x02' -> Connection_not_allowed_by_ruleset
  | '\x03' -> Network_unreachable
  | '\x04' -> Host_unreachable
  | '\x05' -> Connection_refused
  | '\x06' -> TTL_expired
  | '\x07' -> Command_not_supported
  | '\x08' -> Address_type_not_supported
  | '\x09'..'\xff' -> Unassigned

let string_of_socks5_request = function
  | Connect _ -> "\x01"
  | Bind    _ -> "\x02"
  | UDP_associate _ -> "\x03"

let make_socks5_auth_request ~(username_password:bool) =
  String.concat ""
    [ (* field 1: SOCKS version *)
      "\x05"
      (* NMETHODS - number of METHODS *)
    ; "\x01"
    ; string_of_socks5_authentication_method @@
      if username_password then
        Username_password ("", "")
      else No_authentication_required
    ]

(* let parse_socks5_auth_request data
   see [parse_request]
*)

let make_socks5_auth_response auth_method =
  String.concat ""
    [ (* SOCKS version*)
      "\x05"
      (* METHOD chosen by the server *)
    ; string_of_socks5_authentication_method auth_method
    ]

let encode_str str : (string, unit) result =
  (* add uint8_t length prefix, error if not 0 < str < 256 *)
  if String.(length str < 1 || 255 < length str)
  then R.error ()
  else
  R.ok @@
    String.(length str |> char_of_int |> make 1)
  ^ str

let make_socks5_username_password_request ~username ~password =
  encode_str username >>= fun username ->
  encode_str password >>= fun password ->
  R.ok @@
  String.concat ""
  [ (* SOCKS 5 version *)
    "\x05"
    (* ULEN - username length *)
    (* UNAME - username *)
  ; username
    (* PLEN - password length *)
    (* PASSWD - password *)
  ; password
  ]

let parse_socks5_auth_response buf : socks5_authentication_method =
  let buf_len = String.length buf in
  begin match buf.[0], buf.[1] with
   | exception Invalid_argument _ -> No_acceptable_methods
   | '\x05', nmethods  -> (* SOCKS 5 CONNECT *)
     let nmethods = int_of_char nmethods in
     if nmethods < 1 then No_authentication_required
     else
     let method_selection_end = 1 (* version *) + 1 (* nmethods *) + nmethods in
     if buf_len < method_selection_end
     then No_acceptable_methods
     else
     let rec f_auth_methods acc n =
       if n > 0
       then f_auth_methods (socks5_authentication_method_of_char buf.[1+n] :: acc) (n-1)
       else acc
     in
     let auth_methods = f_auth_methods [] nmethods in
     if List.length auth_methods <> 0 && not @@ List.mem No_acceptable_methods auth_methods
     then List.nth auth_methods 0
     else No_acceptable_methods
  | _ -> No_acceptable_methods
  end

let serialize_address =
  begin function
  | IPv4_address ipv4 -> R.ok ["\x01"; Ipaddr.V4.to_bytes ipv4 ]
  | Domain_address hostname ->
      encode_str hostname
      >>= fun hostname ->
      R.ok ["\x03"; hostname]
  | IPv6_address ipv6 -> R.ok ["\x04"; Ipaddr.V6.to_bytes ipv6 ]
  end

let make_socks5_request request =
  (* Serialize the address to bytes: *)
  begin match request with
  | Connect       {address; _ }
  | Bind          {address; _ }
  | UDP_associate {address; _ }
  -> address
  end
  |> serialize_address |> R.reword_error (fun () -> Invalid_hostname)
  >>= fun serialized_address ->
  bigendian_port_of_int (match request with Connect {port;_}
                                          | Bind {port;_}
                                          | UDP_associate {port;_} -> port)
  |> R.reword_error (fun () -> Invalid_port)
  >>= fun port ->
  R.ok @@
  String.concat "" @@
  [ (* SOCKS5 version*)
    "\x05"
    (* CMD (we only implement 'connect' *)
  ; string_of_socks5_request request
    (* RSV - reserved *)
  ; "\x00"
    (* DST.ADDR *)
  ] @ serialized_address
    (* DST.PORT *)
  @ [ port ]

let socks5_authentication_method_of_char : char -> socks5_authentication_method = function
  | '\x00' -> No_authentication_required
  | '\x03' -> Username_password ("", "")
  | _ -> No_acceptable_methods

let int_of_bigendian_port_tuple ~port_msb ~port_lsb =
  (int_of_char port_msb lsl 8) + int_of_char port_lsb

let parse_socks5_response buf : (socks5_reply_field * socks5_struct * leftover_bytes, socks5_response_error) result =
  let buf_len = String.length buf in
  if buf_len < 4+1+2 then
    R.error Incomplete_response
  else
  begin match buf.[0], buf.[1], buf.[2], buf.[3] with
  | '\x05', ('\x00'..'\x08' as reply_field), '\x00', ('\x01'|'\x03'|'\x04' as atyp) ->
    begin match atyp with
    | '\x01' when 4+4+2 <= buf_len -> (* IPv4 *)
        let address = IPv4_address (match Ipaddr.V4.of_bytes @@ String.sub buf 4 4 with Some ip -> ip) in
        R.ok (address, (*port offset:*) 4+4)
    | '\x03' when 4+1+2 <= buf_len -> (* DOMAINNAME *)
      let domain_len = int_of_char buf.[4] in
      if 0 = domain_len
      then R.error Invalid_response
      else
      if buf_len < 4+1+2+domain_len then
        R.error Incomplete_response
      else
      let domain = Domain_address String.(sub buf (4+1) domain_len) in
      R.ok (domain , 4+1+domain_len)
    | '\x04' when 4+16+2 <= buf_len -> (* IPv6 *)
      let sizeof_ipv6 = 16 (*128/8*) in
      let address = IPv6_address (match Ipaddr.V6.of_bytes @@ String.sub buf 4 sizeof_ipv6 with Some ip -> ip) in
      R.ok (address, 4+sizeof_ipv6)
    | ('\x01'|'\x03'|'\x04') -> (* when-guards are used for size constraints above *)
      R.error Incomplete_response
    end
    >>= fun (address, port_offset) ->
    let port = int_of_bigendian_port_tuple
      ~port_msb:buf.[port_offset]
      ~port_lsb:buf.[port_offset+1]
    in
    R.ok ((reply_field_of_char reply_field), {address; port}, String.sub buf (port_offset+2) (buf_len-port_offset-2))
  | _ -> R.error Invalid_response
  end
