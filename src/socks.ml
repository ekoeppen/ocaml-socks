open Rresult
include Socks_types

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
  | Username_password _ -> "\x02"
  | No_acceptable_methods -> "\xFF"

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

let parse_socks5_username_password_request buf : socks5_username_password_request_parse_result =
  let buf_len = String.length buf in
  if buf_len < 3 then Incomplete_request
  else
  begin match buf.[0], buf.[1] with
  | exception Invalid_argument _ -> Incomplete_request
  | '\x05', ulen ->
     let ulen = int_of_char ulen in
     if buf_len < 3 + ulen then Incomplete_request
     else
     let username = String.sub buf 2 ulen in
     let plen = int_of_char buf.[1+1+ulen] in
     if buf_len < 3 + ulen + plen then Incomplete_request
     else
     let password = String.sub buf (3 + ulen) plen in
     Username_password (username , password,
                        String.(sub buf (3 + ulen + plen) (buf_len - 3 - ulen - plen))
     )
  | _ -> Invalid_request
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

let make_socks5_response reply_field ~bnd_port address =
  serialize_address address
  >>= fun address ->
  bigendian_port_of_int bnd_port
  >>= fun bnd_port ->
  R.ok @@
  String.concat "" @@
  [ (* SOCKS version *)
    "\x05"
    (* REP - reply field *)
  ; string_of_socks5_reply_field reply_field
    (* RSV - reserved *)
  ; "\x00"
    (* ATYP - adddress type *)
    (* BND.ADDR *)
  ] @ address
    (* BND.PORT *)
  @ [ bnd_port ]

let socks5_authentication_method_of_char : char -> socks5_authentication_method = function
  | '\x00' -> No_authentication_required
  | '\x03' -> Username_password ("", "")
  | _ -> No_acceptable_methods

let int_of_bigendian_port_tuple ~port_msb ~port_lsb =
  (int_of_char port_msb lsl 8) + int_of_char port_lsb

let parse_socks5_connect buf =
  let buf_len = String.length buf in
  begin match buf.[0], buf.[1], buf.[2], buf.[3] with
  | '\x05', (* VER - version *)
    '\x01', (* CMD - TODO we only implement CONNECT *)
    '\x00', (* RSV - reserved *)
    '\x03' (* ATYP TODO: we only implement DOMAINNAME *)
    ->
      if buf_len < 5 then R.error Incomplete_request
      else
      let atyp_len = int_of_char buf.[4] in
      if buf_len < 2 + 5 + atyp_len then R.error Incomplete_request
      else
      if atyp_len = 0 then R.error Invalid_request
      else
      let address = Domain_address String.(sub buf 5 atyp_len) in
      let port = int_of_bigendian_port_tuple
                   ~port_msb:buf.[5+atyp_len]
                   ~port_lsb:buf.[5+atyp_len+1]
      in
      R.ok ({ port ; address }, String.sub buf (4+1+atyp_len+2) (buf_len-4-1-atyp_len-2) )
  | exception Invalid_argument _ -> R.error Incomplete_request
  | _ -> R.error Invalid_request
  end

let parse_request buf : request_result =
  let buf_len = String.length buf in
  begin match buf.[0], buf.[1] with
   | exception Invalid_argument _ -> Incomplete_request
   | '\x05', nmethods  -> (* SOCKS 5 CONNECT *)
     let nmethods = int_of_char nmethods in
     if nmethods < 1 then Invalid_request
     else
     let method_selection_end = 1 (* version *) + 1 (* nmethods *) + nmethods in
     if buf_len < method_selection_end
     then Incomplete_request
     else
     let rec f_auth_methods acc n =
       if n > 0
       then f_auth_methods (socks5_authentication_method_of_char buf.[1+n] :: acc) (n-1)
       else acc
     in
     let auth_methods = f_auth_methods [] nmethods in
     if List.length auth_methods <> 0 && not @@ List.mem No_acceptable_methods auth_methods
     then
       Socks5_method_selection_request
         ( auth_methods,
           (String.sub buf method_selection_end (buf_len - method_selection_end) ))
     else Invalid_request
   | _ ->
  begin match buf.[0], buf.[1], buf.[2], buf.[3] with
  | exception Invalid_argument _ -> Incomplete_request
  | '\x04' , '\x01' , port_msb, port_lsb -> (* SOCKS 4 CONNECT*)
    let username_offset = 8 in
    begin match String.index_from buf username_offset '\x00' with
    | exception Not_found -> (* no user_id / user_id > 255 *)
        if buf_len < username_offset + 256
        then Incomplete_request
        else Invalid_request
    | username_end ->
      let port = int_of_bigendian_port_tuple ~port_msb:port_msb ~port_lsb:port_lsb in
      let username = String.sub buf username_offset (username_end - username_offset) in
      begin match buf.[4], buf.[5], buf.[6] with
      | exception Invalid_argument _ ->
          Incomplete_request
      | '\x00' , '\x00', '\x00' ->
        let address_offset = 1 + username_end in
        begin match String.index_from buf address_offset '\x00' with
        | exception Not_found -> (* no domain name / domain name > 255 *)
            if buf_len < address_offset + 256
            then Incomplete_request
            else Invalid_request
        | address_end ->
          let address = String.sub buf address_offset (address_end - address_offset) in
          Socks4_request ({ port ; username ; address},
                         String.sub buf (address_end + 1) (buf_len - address_end -1))
        end
      | _ -> (* address is an IPv4 tuple *)
        let address = String.concat "." List.(map
          (fun i -> string_of_int (int_of_char buf.[i])) [ 4; 5; 6; 7 ] )
        in
        Socks4_request ({ port ; username ; address}
          , String.sub buf (username_end +1 + 4) (buf_len - username_end - 4 -1))
      end
    end
  | _ -> Invalid_request
  end
  end

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
