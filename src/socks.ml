(* SOCKS4 / SOCKS4a

http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol

https://en.wikipedia.org/wiki/SOCKS#SOCKS4a

*)

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

let make_socks4_request ~username ~hostname port : (string, request_invalid_argument) result =
  let hostname_len = String.length hostname in
  if 0 == hostname_len || 255 < hostname_len
  then R.error (Invalid_hostname : request_invalid_argument)
  else R.ok ()
  >>= fun _ ->
  bigendian_port_of_int port
  |> R.reword_error (fun () -> Invalid_port)
  >>= fun port ->
  R.ok @@ String.concat ""
    [ (* field 1: SOCKS version *)
      "\x04"
      (* field 2: command code: "connect stream": *)
    ; "\x01"
      (* field 3: bigendian port: *)
    ; port
      (* field 4: invalid ip: *)
    ; "\x00\x00\x00\xff"
      (* field 5: user ID string followed by terminator: *)
    ; username ; "\x00"
      (* field 6: hostname string followed by terminator: *)
    ; hostname ; "\x00"
    ]

let string_of_socks5_authentication_method : socks5_authentication_method -> string = function
  | No_authentication_required -> "\x00"
  | Username_password _ -> "\x02"
  | No_acceptable_methods -> "\xFF"

let string_of_socks5_reply_field = function
  | Succeeded -> "\x00"
  | Failure -> "\xFF" (* TODO look this up*)

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

let make_socks5_username_password_request ~username ~password =
  begin match String.(length username , length password) with
  | 0 , _
  | _ , 0 -> R.error ()
  | x , y when x > 255 || y > 255 -> R.error ()
  | _ ->
  R.ok @@
  String.concat ""
  [ (* SOCKS 5 version *)
    "\x05"
    (* ULEN - username length *)
  ; username |> String.length |> char_of_int |> String.make 1
    (* UNAME - username *)
  ; username
    (* PLEN - password length *)
  ; password |> String.length |> char_of_int |> String.make 1
    (* PASSWD - password *)
  ; password
  ]
  end

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

let make_socks5_request hostname port =
  let hostname_len = String.length hostname in
  if 255 < hostname_len || 0 = hostname_len then
    R.error (Invalid_hostname : request_invalid_argument)
  else R.ok ()
  >>= fun () ->
  bigendian_port_of_int port
  |> R.reword_error (fun () -> Invalid_port)
  >>= fun port ->
  R.ok @@
  String.concat ""
  [ (* SOCKS5 version*)
    "\x05"
    (* CMD (we only implement 'connect' *)
  ; "\x01"
    (* RSV - reserved *)
  ; "\x00"
    (* ATYP - address type (ipv4; ipv6; domain name) *)
    (* (we only implement 'domainname' *)
  ; "\x03"
    (* address *)
  ; String.(length hostname) |> char_of_int |> String.make 1
  ; hostname
    (* port *)
  ; port
  ]

let make_socks5_response ~bnd_port reply_field =
  bigendian_port_of_int bnd_port
  >>= fun bnd_port ->
  R.ok @@
  String.concat ""
  [ (* SOCKS version *)
    "\x05"
    (* REP - reply field *)
  ; string_of_socks5_reply_field reply_field
    (* RSV - reserved *)
  ; "\x00"
    (* ATYP - adddress type *)
  ; "\x01" (* TODO: we only send IPv4 *)
    (* BND.ADDR - TODO handle ATYP *)
  ; "\x00\x00\x00\x00"
    (* BND.PORT - TODO handle ATYP *)
  ; bnd_port
  ]

let make_socks4_response ~(success : bool) = String.concat ""
  (* field 1: null byte*)
  [ "\x00"
  (* field 2: status, 1 byte 0x5a = granted; 0x5b = rejected/failed : *)
  ; (if success then "\x5a" else "\x5b")
  (* Note: the next two fields are "ignored" according to the RFC,
   * but socat (among other clients) refuses to parse the response
   * if it's not zeroed out, so that's what we do (same as ssh): *)
  (* field 3: bigendian port: *)
  ; String.make 2 '\x00'
  (* field 4: "network byte order ip address"*)
  ; String.make 4 '\x00' (* IP *)
  ]

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
      let address = String.sub buf 5 atyp_len in
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

let parse_socks4_response result : (string, socks4_response_error) Result.result =
  let buf_len = String.length result in
  if 8 > buf_len then
    R.error (Incomplete_response : socks4_response_error)
  else
  if result.[0] = '\x00'
    && result.[1] = '\x5a'
    (* TODO not checking port *)
    && result.[4] = '\x00'
    && result.[5] = '\x00'
    && result.[6] = '\x00'
    && result.[7] = '\xff'
  then
    if buf_len <> 8 then
      R.ok @@ String.sub result 8 (buf_len - 8)
    else
      R.ok ""
  else
    R.error Rejected

let parse_socks5_response buf : socks5_response_result =
  let buf_len = String.length buf in
  if buf_len < 4+1+2 then
    Incomplete_response
  else
  begin match buf.[0], buf.[1], buf.[2], buf.[3] with
  | '\x05', '\x00', '\x00', atyp ->
    begin match atyp with
    | '\x01' -> (* IPv4 *)
        if buf_len < 4+2+4 then
          Incomplete_response
        else
        let ipv4_address = String.concat "." List.(map
          (fun i -> string_of_int (int_of_char buf.[i])) [ 4; 5; 6; 7 ] )
        in
        let port = int_of_bigendian_port_tuple ~port_msb:buf.[8] ~port_lsb:buf.[9] in
        Bound_ipv4 (ipv4_address
             , port
             , String.sub buf (4+2+4) (buf_len-4-2-4)
             )
    | '\x03' -> (* DOMAINNAME *)
      let domain_len = int_of_char buf.[4] in
      if 0 = domain_len then
        Invalid_response
      else
      if buf_len < 4+1+2+domain_len then
        Incomplete_response
      else
      let domain = String.sub buf (4+1) domain_len in
      let port = int_of_bigendian_port_tuple
        ~port_msb:buf.[4+1+domain_len]
        ~port_lsb:buf.[4+1+domain_len+1]
      in
      Bound_domain (domain
           , port
           , String.sub buf (4+1+domain_len+2) (buf_len -4 -1 - domain_len -2)
           )
    | '\x04' -> (* IPv6 *)
      if buf_len < 4+2+128/4 then
        Incomplete_response
      else
      let port = int_of_bigendian_port_tuple
        ~port_msb:buf.[4+128/4]
        ~port_lsb:buf.[4+128/4+1]
      in
      Bound_ipv6 (String.sub buf 4 (128/4)
           , port (* TODO transform into a nice string *)
           , String.(sub buf (4+128/4+2) (buf_len - 4 -128/4-2))
           )
    | _ -> Invalid_response
    end
  | _ -> Invalid_response
  end
