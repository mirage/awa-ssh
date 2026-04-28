(*
 * Copyright (c) 2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Util

let ( let* ) = Result.bind

let get_uint32 buf off =
  trap_error (fun () ->
      Ok (String.get_int32_be buf off, off + 4))

let put_uint32 (buf, off) value =
  Bytes.set_int32_be buf off value;
  off + 4

let get_uint8 buf off =
  trap_error (fun () ->
      Ok (String.get_uint8 buf 0, off + 1))

let put_uint8 (buf, off) value =
  Bytes.set_uint8 buf off value;
  off + 1

let get_bool buf off =
  let* b, off' = get_uint8 buf off in
  Ok (b <> 0, off')

let put_bool t value =
  let x = if value then 1 else 0 in
  put_uint8 t x

let get_string buf off =
  trap_error (fun () ->
      let* len, off' = get_uint32 buf off in
      let len = Int32.to_int len in
      Ssh.guard_sshlen_exn len;
      Ok ((String.sub buf off' len), off' + len))

let put_string (buf, off) s =
  let len = String.length s in
  let off = put_uint32 (buf, off) (Int32.of_int len) in
  Bytes.blit_string s 0 buf off len;
  off + len

let put_raw (buf, off) data =
  let len = String.length data in
  Bytes.blit_string data 0 buf off len;
  off + len

let put_random t len =
  put_raw t (Mirage_crypto_rng.generate len)

let get_mpint ?(signed = true) buf off =
  trap_error (fun () ->
      let* len, off' = get_uint32 buf off in
      match Int32.to_int len with
      | 0 -> Ok (Z.zero, off')
      | len ->
        Ssh.guard_sshlen_exn len;
        let mpbuf = String.sub buf off' len in
        let msb = String.get_uint8 mpbuf 0 in
        if signed && (msb land 0x80) <> 0 then
          Error "Negative mpint"
        else
          (* of_octets_be strips leading zeros for us *)
          Ok (Mirage_crypto_pk.Z_extra.of_octets_be mpbuf,
              off' + len))

let put_mpint ?(signed = true) (buf, off) mpint =
  let mpbuf = Mirage_crypto_pk.Z_extra.to_octets_be mpint in
  let mplen = String.length mpbuf in
  let off' =
    if signed && mplen > 0 &&
       ((String.get_uint8 mpbuf 0) land 0x80) <> 0 then
      let off = put_uint32 (buf, off) (Int32.of_int (succ mplen)) in
      put_uint8 (buf, off) 0;
    else
      put_uint32 (buf, off) (Int32.of_int mplen)
  in
  put_raw (buf, off') mpbuf

let get_message_id buf off =
  let* id, off' = get_uint8 buf off in
  match Ssh.int_to_message_id id with
  | None -> Error (Printf.sprintf "Unknown message id %d" id)
  | Some msgid -> Ok (msgid, off')

let put_message_id t id =
  put_uint8 t (Ssh.message_id_to_int id)

let get_nl buf off =
  let* (s, off') = get_string buf off in
  Ok (String.split_on_char ',' s, off')

let put_nl t nl =
  put_string t (String.concat "," nl)

let blob_of_pubkey pk =
  let len =
    match pk with
    | Hostkey.Rsa_pub rsa ->
      let bytes bits = 1 + ((bits - 1) / 8) in
      let open Mirage_crypto_pk.Rsa in
      (* 4 byte length + maybe 1 byte signed + data *)
      5 + bytes (Z.numbits rsa.e) + 5 + bytes (Z.numbits rsa.n)
    | Hostkey.Ed25519_pub _ ->
      (* 3 byte length + public key *)
      4 + 32
  in
  let name = Hostkey.sshname pk in
  let buf = Bytes.create (len + 4 + String.length name) in
  let off = put_string (buf, 0) name in
  let off =
    match pk with
    | Hostkey.Rsa_pub rsa ->
      let open Mirage_crypto_pk.Rsa in
      let off = put_mpint (buf, off) rsa.e in
      put_mpint (buf, off) rsa.n
    | Hostkey.Ed25519_pub pub ->
      let pub_str = Mirage_crypto_ec.Ed25519.pub_to_octets pub in
      put_string (buf, off) pub_str
  in
  let s = Bytes.unsafe_to_string buf in
  if off = len then
    s
  else
    String.sub s 0 off

let pubkey_of_blob (buf, off) =
  let* key_type, off =
    Result.map_error (fun s -> `Msg s) (get_string buf off)
  in
  match key_type with
  | "ssh-rsa" ->
    let* e, off = Result.map_error (fun s -> `Msg s) (get_mpint buf off) in
    let* n, _ = Result.map_error (fun s -> `Msg s) (get_mpint buf off) in
    let* pub = Mirage_crypto_pk.Rsa.pub ~e ~n in
    Ok (Hostkey.Rsa_pub pub)
  | "ssh-ed25519" ->
    let* pub, _ = Result.map_error (fun s -> `Msg s) (get_string buf off) in
    let* pubkey =
      Result.map_error
        (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
        (Mirage_crypto_ec.Ed25519.pub_of_octets pub)
    in
    Ok (Hostkey.Ed25519_pub pubkey)
  | k -> Error (`Unsupported k)

let pubkey_of_blob_error_as_string blob =
    Result.map_error
      (function `Msg s -> s | `Unsupported alg -> "unsupported algorithm: " ^ alg)
      (pubkey_of_blob blob)

(* Prefer using get_pubkey_alg always *)
let get_pubkey_any buf off =
  let* blob, off = get_string buf off in
  let* pubkey = pubkey_of_blob_error_as_string (blob, 0) in
  Ok (pubkey, off)

(* Always use get_pubkey_alg since it returns Unknown if key_alg mismatches *)
let get_pubkey buf off key_alg =
  let* pubkey, off = get_pubkey_any buf off in
  if Hostkey.comptible_alg pubkey key_alg then
    Ok (pubkey, off)
  else
    Error ("public key algorithm not supported " ^ key_alg)

let put_pubkey t pubkey =
  put_string t (blob_of_pubkey pubkey)

let pubkey_of_openssh s =
  let tokens = String.split_on_char ' ' s in
  let* () = guard (List.length tokens = 3) "Invalid format" in
  let key_type = List.nth tokens 0 in
  let key_buf = List.nth tokens 1 in
  (* let key_comment = List.nth tokens 2 in *)
  let* blob =
    Result.map_error
      (function `Msg m -> m)
      (Base64.decode key_buf)
  in
  (* NOTE: can't use get_pubkey here, there is no string blob *)
  let* key = pubkey_of_blob_error_as_string (blob, 0) in
  let* () = guard (Hostkey.sshname key = key_type) "Key type mismatch" in
  Ok key

let openssh_of_pubkey key =
  let key_buf = blob_of_pubkey key |> Base64.encode_string in
  String.concat "" [ Hostkey.sshname key ; " "; key_buf; " awa-ssh\n" ]

let privkey_of_pem buf =
  let* p = X509.Private_key.decode_pem buf in
  match p with
  | `RSA key -> Ok (Hostkey.Rsa_priv key)
  | `ED25519 key -> Ok (Hostkey.Ed25519_priv key)
  | _ -> Error (`Msg "unsupported private key")

let privkey_of_openssh data =
  (* as defined in https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/plain *)
  let id s =
    let dash = "-----" in
    dash ^ (if s then "BEGIN" else "END") ^ " OPENSSH PRIVATE KEY" ^ dash
  in
  let* data =
    match String.split_on_char '\n' data with
    | hd :: data ->
      begin match List.rev data with
        | "" :: last :: data' | last :: data' ->
          let data = String.concat "" (List.rev data') in
          if String.equal hd (id true) && String.equal last (id false) then
            Result.map_error (function `Msg m -> m ) (Base64.decode data)
          else
            Error "not an OpenSSH private key"
        | [] -> Error "not a valid OpenSSH private key"
      end
    | [] -> Error "invalid OpenSSH private key"
  in
  let auth_magic = "openssh-key-v1\000" in
  let pre = String.sub data 0 (String.length auth_magic) in
  let* () = guard (String.equal pre auth_magic) "bad auth magic" in
  let* cipher, off = get_string data (String.length auth_magic) in
  let* () = guard (String.equal cipher "none") "only unencrypted private keys supported" in
  let* kdf, off = get_string data off in
  let* () = guard (String.equal kdf "none") "only unencrypted private keys supported" in
  let* kdfopts, off = get_string data off in
  let* () = guard (String.equal kdfopts "") "only no kdfoptions supported" in
  let* keys, off = get_uint32 data off in
  let* () = guard (keys = 1l) "only one key supported" in
  let* pklen, off = get_uint32 data off in
  let* _plen, off = get_uint32 data (off + Int32.to_int pklen) in
  (* 64 bit checkint - useful when crypted *)
  let* keytype, off = get_string data (off + 8) in
  match keytype with
  | "ssh-ed25519" ->
    let* _pub, off = get_string data off in
    let* priv, off = get_string data off in
    let* comment, _off = get_string data off in
    let priv = String.sub priv 0 32 in
    let* priv_key =
      Result.map_error
        (Fmt.to_to_string Mirage_crypto_ec.pp_error)
        (Mirage_crypto_ec.Ed25519.priv_of_octets priv)
    in
    Ok (Hostkey.Ed25519_priv priv_key, comment)
  | "ssh-rsa" ->
    let* n, off = get_mpint data off in
    let* e, off = get_mpint data off in
    let* d, off = get_mpint data off in
    let* q', off = get_mpint data off in
    let* p, off = get_mpint data off in
    let* q, _off = get_mpint data off in
    let* comment, _padding = get_string data off in
    let dp = Z.(d mod (pred p)) and dq = Z.(d mod (pred q)) in
    let* p =
      Result.map_error
        (function `Msg m -> m)
        (Mirage_crypto_pk.Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q')
    in
    Ok (Hostkey.Rsa_priv p, comment)
  | x -> Error ("unsupported key type " ^ x)

let put_kexinit t kex =
  let open Ssh in
  let kex_algs = match kex.ext_info with
    | None -> kex.kex_algs
    | Some `Ext_info_c -> "ext-info-c" :: kex.kex_algs
    | Some `Ext_info_s -> "ext-info-s" :: kex.kex_algs
  in
  let nll = [ kex_algs;
              kex.server_host_key_algs;
              kex.encryption_algs_ctos;
              kex.encryption_algs_stoc;
              kex.mac_algs_ctos;
              kex.mac_algs_stoc;
              kex.compression_algs_ctos;
              kex.compression_algs_stoc;
              kex.languages_ctos;
              kex.languages_stoc; ]
  in
  let off = put_raw t kex.cookie in
  let buf = fst t in
  let off = List.fold_left (fun off nl -> put_nl (buf, off) nl) off nll in
  let off = put_bool (buf, off) kex.first_kex_packet_follows in
  put_uint32 (buf, off) Int32.zero

let blob_of_kexinit kex =
  let b = Bytes.create 0xffff (* TODO length *) in
  let off = put_message_id (b, 0) Ssh.MSG_KEXINIT in
  let off = put_kexinit (b, off) kex in
  String.sub (Bytes.unsafe_to_string b) 0 off

let rec put_extensions (buf, off) extensions =
  match extensions with
  | [] -> off
  | Ssh.Extension { name; value } :: extensions ->
    let off = put_string (buf, off) name in
    let off = put_string (buf, off) value in
    put_extensions (buf, off) extensions

let get_signature_raw buf off =
  let* blob, off' = get_string buf off in
  let* sig_alg, off = get_string blob 0 in
  let* key_sig, _ = get_string blob off in
  Ok ((sig_alg, key_sig), off')

let get_signature buf off =
  Result.bind
    (get_signature_raw buf off)
    (fun ((sig_alg, key_sig), off) ->
       let* sig_alg = Hostkey.alg_of_string sig_alg in
       Ok ((sig_alg, key_sig), off))

let put_signature_raw t (alg, signature) =
  let blob =
    let b = Bytes.create 0xffff in (* TODO: length *)
    let off = put_string (b, 0) alg in
    let off = put_string (b, off) signature in
    String.sub (Bytes.unsafe_to_string b) 0 off
  in
  put_string t blob

let put_signature t (alg, signature) =
  put_signature_raw t (Hostkey.alg_to_string alg, signature)

let put_channel_data (buf, off) channel_data =
  let open Ssh in
  match channel_data with
  | Session -> off
  | X11 (address, port) ->
    let off = put_string (buf, off) address in
    put_uint32 (buf, off) port
  | Forwarded_tcpip (con_addr, con_port, origin_addr, origin_port) ->
    let off = put_string (buf, off) con_addr in
    let off = put_uint32 (buf, off) con_port in
    let off = put_string (buf, off) origin_addr in
    put_uint32 (buf, off) origin_port
  | Direct_tcpip (addr, port, origin_addr, origin_port) ->
    let off = put_string (buf, off) addr in
    let off = put_uint32 (buf, off) port in
    let off = put_string (buf, off) origin_addr in
    put_uint32 (buf, off) origin_port
  | Raw_data data -> put_raw (buf, off) data

let blob_of_channel_data channel_data =
  (* TODO figure out length *)
  let b = Bytes.create 0xffff in
  let off = put_channel_data (b, 0) channel_data in
  String.sub (Bytes.unsafe_to_string b) 0 off

let get_message buf =
  let open Ssh in
  let* msgid, off = get_message_id buf 0 in
  match msgid with
  | MSG_DISCONNECT ->
    let* code, off = get_uint32 buf off in
    let* desc, off = get_string buf off in
    let* lang, _ = get_string buf off in
    Ok (Msg_disconnect (int_to_disconnect_code code, desc, lang))
  | MSG_IGNORE ->
    let* x, _ = get_string buf off in
    Ok (Msg_ignore x)
  | MSG_UNIMPLEMENTED ->
    let* x, _ = get_uint32 buf off in
    Ok (Msg_unimplemented x)
  | MSG_DEBUG ->
    let* always_display, off = get_bool buf off in
    let* message, off = get_string buf off in
    let* lang, _ = get_string buf off in
    Ok (Msg_debug (always_display, message, lang))
  | MSG_SERVICE_REQUEST ->
    let* x, _ = get_string buf off in
    Ok (Msg_service_request x)
  | MSG_SERVICE_ACCEPT ->
    let* x, _ = get_string buf off in
    Ok (Msg_service_accept x)
  | MSG_KEXINIT ->
    (* Jump over cookie *)
    let cookie_end = off + 16 in
    let* kex_algs, off = get_nl buf cookie_end in
    let* server_host_key_algs, off = get_nl buf off in
    let* encryption_algs_ctos, off = get_nl buf off in
    let* encryption_algs_stoc, off = get_nl buf off in
    let* mac_algs_ctos, off = get_nl buf off in
    let* mac_algs_stoc, off = get_nl buf off in
    let* compression_algs_ctos, off = get_nl buf off in
    let* compression_algs_stoc, off = get_nl buf off in
    let* languages_ctos, off = get_nl buf off in
    let* languages_stoc, off = get_nl buf off in
    let* first_kex_packet_follows, _ = get_bool buf off in
    let kex_algs =
      List.filter (function "ext-info-s" | "ext-info-c" -> false | _ -> true) kex_algs
    and ext_info =
      List.find_map (function
          | "ext-info-s" -> Some `Ext_info_s
          | "ext-info-c" -> Some `Ext_info_c
          | _ -> None)
        kex_algs
    in
    Ok (Msg_kexinit
          { cookie = String.sub buf (cookie_end - 16) 16;
            kex_algs;
            ext_info;
            server_host_key_algs;
            encryption_algs_ctos;
            encryption_algs_stoc;
            mac_algs_ctos;
            mac_algs_stoc;
            compression_algs_ctos;
            compression_algs_stoc;
            languages_ctos;
            languages_stoc;
            first_kex_packet_follows;
            rawkex = buf })
  | MSG_EXT_INFO ->
    let* nr_extensions, off = get_uint32 buf 0 in
    let* nr_extensions = match Int32.unsigned_to_int nr_extensions with
      | None -> Error "Ridiculous number of extensions advertised"
      | Some n -> Ok n
    in
    let rec loop buf off n acc =
      if n = 0 then
        Ok (Msg_ext_info (List.rev acc))
      else
        let* name, off = get_string buf off in
        let* value, off = get_string buf off in
        loop buf off (pred n) (Extension { name; value } :: acc)
    in
    loop buf off nr_extensions []
  | MSG_NEWKEYS ->
    Ok Msg_newkeys
  | MSG_KEX_0 | MSG_KEX_1 | MSG_KEX_2 | MSG_KEX_3 | MSG_KEX_4 ->
    Ok (Msg_kex (msgid, buf))
  | MSG_USERAUTH_REQUEST ->
    let* user, off = get_string buf 0 in
    let* service, off = get_string buf off in
    let* auth_method, off = get_string buf off in
    let* auth_method, _ =
      match auth_method with
      | "publickey" ->
        let* has_sig, off = get_bool buf off in
        let* sig_alg_raw, off = get_string buf off in
        let* pubkey_raw, off = get_string buf off in
        if has_sig then
          let* signature, off = get_signature_raw buf off in
          Ok (Pubkey (sig_alg_raw, pubkey_raw, Some signature), off)
        else
          Ok (Pubkey (sig_alg_raw, pubkey_raw, None), off)
      | "password" ->
        let* has_old, off = get_bool buf off in
        if has_old then
          let* oldpassword, off = get_string buf off in
          let* password, off = get_string buf off in
          Ok (Password (password, Some oldpassword), off)
        else
          let* password, off = get_string buf off in
          Ok (Password (password, None), off)
      | "keyboard-interactive" ->
        let* language, off = get_string buf off in
        let* submethods, off = get_string buf off in
        let lang_opt = if String.length language = 0 then None else Some language
        and submethods = String.split_on_char ',' submethods
        in
        Ok (Keyboard_interactive (lang_opt, submethods), off)
      | "none" -> Ok (Authnone, off)
      | _ -> Error ("Unknown method " ^ auth_method)
    in
    Ok (Msg_userauth_request (user, service, auth_method))
  | MSG_USERAUTH_FAILURE ->
    let* nl, off = get_nl buf off in
    let* psucc, _ = get_bool buf off in
    Ok (Msg_userauth_failure (nl, psucc))
  | MSG_USERAUTH_SUCCESS -> Ok Msg_userauth_success
  | MSG_USERAUTH_1 -> Ok (Msg_userauth_1 buf)
  | MSG_USERAUTH_2 -> Ok (Msg_userauth_2 buf)
  | MSG_USERAUTH_BANNER ->
    let* s1, off = get_string buf off in
    let* s2, _ = get_string buf off in
    Ok (Msg_userauth_banner (s1, s2))
  | MSG_GLOBAL_REQUEST ->
    let* request, off = get_string buf off in
    let* want_reply, off = get_bool buf off in
    let* global_request, _ =
      match request with
      | "tcpip-forward" ->
        let* address, off = get_string buf off in
        let* port, off = get_uint32 buf off in
        Ok (Tcpip_forward (address, port), off)
      | "cancel-tcpip-forward" ->
        let* address, off = get_string buf off in
        let* port, off = get_uint32 buf off in
        Ok (Cancel_tcpip_forward (address, port), off)
      | _ ->
        let* data, off = get_string buf off in
        Ok (Unknown_request data, off)
    in
    Ok (Msg_global_request (request, want_reply, global_request))
  | MSG_REQUEST_SUCCESS ->
    let req_data = if String.length buf > 0 then Some buf else None in
    Ok (Msg_request_success req_data)
  | MSG_REQUEST_FAILURE -> Ok Msg_request_failure
  | MSG_CHANNEL_OPEN ->
    let* request, off = get_string buf off in
    let* send_channel, off = get_uint32 buf off in
    let* init_win, off = get_uint32 buf off in
    let* max_pkt, off = get_uint32 buf off in
    (match request with
     | "session" ->
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt, Session))
     | "x11" ->
       let* address, off = get_string buf off in
       let* port, _ = get_uint32 buf off in
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              (X11 (address, port))))
     | "forwarded-tcpip" ->
       let* con_address, off = get_string buf off in
       let* con_port, off = get_uint32 buf off in
       let* origin_address, off = get_string buf off in
       let* origin_port, _ = get_uint32 buf off in
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              Forwarded_tcpip (con_address, con_port, origin_address,
                               origin_port)))
     | _ -> Error ("Unknown channel open " ^ request))
  | MSG_CHANNEL_OPEN_CONFIRMATION ->
    let* recp_channel, off = get_uint32 buf off in
    let* send_channel, off = get_uint32 buf off in
    let* init_win, off = get_uint32 buf off in
    let* max_pkt, off = get_uint32 buf off in
    let rest = String.sub buf off (String.length buf - off) in
    (*
     * The protocol does not tell us which channel type this is, so we can't
     * give the caller a good type for channel open and must return Raw_data.
     * We must provide the caller a function to make the conversion.
     *)
    Ok (Msg_channel_open_confirmation
          (recp_channel, send_channel,
           init_win, max_pkt,
           rest))
  | MSG_CHANNEL_OPEN_FAILURE ->
    let* recp_channel, off = get_uint32 buf off in
    let* reason, off = get_uint32 buf off in
    let* desc, off = get_string buf off in
    let* lang, _ = get_string buf off in
    Ok (Msg_channel_open_failure (recp_channel, reason, desc, lang))
  | MSG_CHANNEL_WINDOW_ADJUST ->
    let* channel, off = get_uint32 buf off in
    let* n, _ = get_uint32 buf off in
    Ok (Msg_channel_window_adjust (channel, n))
  | MSG_CHANNEL_DATA ->
    let* channel, off = get_uint32 buf off in
    let* data, _ = get_string buf off in
    Ok (Msg_channel_data (channel, data))
  | MSG_CHANNEL_EXTENDED_DATA ->
    let* channel, off = get_uint32 buf off in
    let* data_type, off = get_uint32 buf off in
    let* data, _ = get_string buf off in
    Ok (Msg_channel_extended_data (channel, data_type, data))
  | MSG_CHANNEL_EOF ->
    let* channel, _ = get_uint32 buf off in
    Ok (Msg_channel_eof channel)
  | MSG_CHANNEL_CLOSE ->
    let* channel, _ = get_uint32 buf off in
    Ok (Msg_channel_close channel)
  | MSG_CHANNEL_REQUEST ->
    let* channel, off = get_uint32 buf off in
    let* request, off = get_string buf off in
    let* want_reply, off = get_bool buf off in
    (match request with
     | "pty-req" ->
       let* term_env, off = get_string buf off in
       let* width_char, off = get_uint32 buf off in
       let* height_row, off = get_uint32 buf off in
       let* width_px, off = get_uint32 buf off in
       let* height_px, off = get_uint32 buf off in
       let* term_modes, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Pty_req (term_env, width_char, height_row,
                                         width_px, height_px, term_modes)))
     | "x11-req" ->
       let* single_con, off = get_bool buf off in
       let* x11_auth_proto, off = get_string buf off in
       let* x11_auth_cookie, off = get_string buf off in
       let* x11_screen_nr, _ = get_uint32 buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                X11_req (single_con, x11_auth_proto,
                                         x11_auth_cookie, x11_screen_nr)))
     | "env" ->
       let* name, off = get_string buf off in
       let* value, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Env (name, value)))
     | "exec" ->
       let* command, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Exec (command)))
     | "shell" -> Ok (Msg_channel_request (channel, want_reply, Shell))
     | "subsystem" ->
       let* name, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Subsystem (name)))
     | "window-change" ->
       let* width_char, off = get_uint32 buf off in
       let* height_row, off = get_uint32 buf off in
       let* width_px, off = get_uint32 buf off in
       let* height_px, _ = get_uint32 buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Window_change (width_char, height_row,
                                               width_px, height_px)))
     | "xon-xoff" ->
       let* client_can_do, _ = get_bool buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Xon_xoff (client_can_do)))
     | "signal" ->
       let* name, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Signal (name)))
     | "exit-status" ->
       let* status, _ = get_uint32 buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Exit_status (status)))
     | "exit-signal" ->
       let* name, off = get_string buf off in
       let* core_dumped, off = get_bool buf off in
       let* message, off = get_string buf off in
       let* lang, _ = get_string buf off in
       Ok (Msg_channel_request (channel, want_reply,
                                Exit_signal (name, core_dumped, message, lang)))
     | _ -> Error ("Unknown channel request " ^ request))
  | MSG_CHANNEL_SUCCESS ->
    let* channel, _ = get_uint32 buf off in
    Ok (Msg_channel_success channel)
  | MSG_CHANNEL_FAILURE ->
    let* channel, _ = get_uint32 buf off in
    Ok (Msg_channel_failure channel)
  | MSG_VERSION ->
    Error "got MSG_VERSION"

let dh_kexdh_of_kex id buf =
  (* for common DH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    let* e, _ = get_mpint buf 0 in
    Ok (Msg_kexdh_init e)
  | MSG_KEX_1 ->
    let* k_s, off = get_pubkey_any buf 0 in
    let* f, off = get_mpint buf off in
    let* key_sig, _off = get_signature buf off in
    Ok (Msg_kexdh_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let dh_kexecdh_of_kex id buf =
  (* for ECDH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    let* e, _ = get_mpint ~signed:false buf 0 in
    Ok (Msg_kexecdh_init e)
  | MSG_KEX_1 ->
    let* k_s, off = get_pubkey_any buf 0 in
    let* f, off = get_mpint ~signed:false buf off in
    let* key_sig, _off = get_signature buf off in
    Ok (Msg_kexecdh_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let dh_kexdh_gex_of_kex id buf =
  (* for RFC 4419 GEX *)
  let open Ssh in
  match id with
  | MSG_KEX_4 ->
    let* min, off = get_uint32 buf 0 in
    let* n, off = get_uint32 buf off in
    let* max, _ = get_uint32 buf off in
    Ok (Msg_kexdh_gex_request (min, n, max))
  | MSG_KEX_1 ->
    let* p, off = get_mpint buf 0 in
    let* g, _ = get_mpint buf off in
    Ok (Msg_kexdh_gex_group (p, g))
  | MSG_KEX_2 ->
    let* e, _ = get_mpint buf 0 in
    Ok (Msg_kexdh_gex_init e)
  | MSG_KEX_3 ->
    let* k_s, off = get_pubkey_any buf 0 in
    let* f, off = get_mpint buf off in
    let* key_sig, _ = get_signature buf off in
    Ok (Msg_kexdh_gex_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let userauth_pk_ok buf =
  let* key_alg, off = get_string buf 0 in
  let* pubkey, _ = get_pubkey buf off key_alg in
  Ok (Ssh.Msg_userauth_pk_ok pubkey)

let userauth_info_request buf =
  let* name, off = get_string buf 0 in
  let* instruction, off = get_string buf off in
  let* lang, off = get_string buf off in
  let* num_prompts, off = get_uint32 buf off in
  let rec collect_prompts buf off acc = function
    | 0 -> Ok (List.rev acc)
    | n ->
      let* prompt, off = get_string buf off in
      let* echo, off = get_bool buf off in
      collect_prompts buf off ((prompt, echo) :: acc) (n - 1)
  in
  let* prompts = collect_prompts buf off [] (Int32.to_int num_prompts) in
  Ok (Ssh.Msg_userauth_info_request (name, instruction, lang, prompts))

let put_message (buf, off) msg =
  let open Ssh in
  let put_id = put_message_id in (* save some columns *)
  match msg with
  | Msg_disconnect (code, desc, lang) ->
    let off = put_id (buf, off) MSG_DISCONNECT in
    let off = put_uint32 (buf, off) (disconnect_code_to_int code) in
    let off = put_string (buf, off) desc in
    put_string (buf, off) lang
  | Msg_ignore s ->
    let off = put_id (buf, off) MSG_IGNORE in
    put_string (buf, off) s
  | Msg_unimplemented x ->
    let off = put_id (buf, off) MSG_UNIMPLEMENTED in
    put_uint32 (buf, off) x
  | Msg_debug (always_display, message, lang) ->
    let off = put_id (buf, off) MSG_DEBUG in
    let off = put_bool (buf, off) always_display in
    let off = put_string (buf, off) message in
    put_string (buf, off) lang
  | Msg_service_request s ->
    let off= put_id (buf, off) MSG_SERVICE_REQUEST in
    put_string (buf, off) s
  | Msg_service_accept s ->
    let off = put_id (buf, off) MSG_SERVICE_ACCEPT in
    put_string (buf, off) s
  | Msg_kexinit kex ->
    let off = put_id (buf, off) MSG_KEXINIT in
    put_kexinit (buf, off) kex
  | Msg_ext_info extensions ->
    let nr_extensions = List.length extensions in
    let off = put_id (buf, off) MSG_EXT_INFO in
    (* XXX: overflow *)
    let off = put_uint32 (buf, off) (Int32.of_int nr_extensions) in
    put_extensions (buf, off) extensions
  | Msg_newkeys ->
    put_id (buf, off) MSG_NEWKEYS
  | Msg_kexdh_init e ->
    let off = put_id (buf, off) MSG_KEX_0 in
    put_mpint (buf, off) e
  | Msg_kexdh_reply (k_s, f, signature) ->
    let off = put_id (buf, off) MSG_KEX_1 in
    let off = put_pubkey (buf, off) k_s in
    let off = put_mpint (buf, off) f in
    put_signature (buf, off) signature
  | Msg_kexecdh_init e ->
    let off = put_id (buf, off) MSG_KEX_0 in
    put_mpint ~signed:false (buf, off) e
  | Msg_kexecdh_reply (k_s, f, signature) ->
    let off = put_id (buf, off) MSG_KEX_1 in
    let off = put_pubkey (buf, off) k_s in
    let off = put_mpint ~signed:false (buf, off) f in
    put_signature (buf, off) signature
  | Msg_kexdh_gex_request (min, n, max) ->
    let off = put_id (buf, off) MSG_KEX_4 in
    let off = put_uint32 (buf, off) min in
    let off = put_uint32 (buf, off) n in
    put_uint32 (buf, off) max
  | Msg_kexdh_gex_group (p, g) ->
    let off = put_id (buf, off) MSG_KEX_1 in
    let off = put_mpint (buf, off) p in
    put_mpint (buf, off) g
  | Msg_kexdh_gex_init e ->
    let off = put_id (buf, off) MSG_KEX_2 in
    put_mpint (buf, off) e
  | Msg_kexdh_gex_reply (k_s, f, signature) ->
    let off = put_id (buf, off) MSG_KEX_3 in
    let off = put_pubkey (buf, off) k_s in
    let off = put_mpint (buf, off) f in
    put_signature (buf, off) signature
  | Msg_kex _ -> assert false
  | Msg_userauth_request (user, service, auth_method) ->
    let off = put_id (buf, off) MSG_USERAUTH_REQUEST in
    let off = put_string (buf, off) user in
    let off = put_string (buf, off) service in
    (match auth_method with
     | Pubkey (sig_alg_raw, pubkey_raw, signature) ->
       let off = put_string (buf, off) "publickey" in
       let off = put_bool (buf, off) (Option.is_some signature) in
       let off = put_string (buf, off) sig_alg_raw in
       let off = put_string (buf, off) pubkey_raw in
       (match signature with
        | None -> off
        | Some signature -> put_signature_raw (buf, off) signature)
     | Password (password, oldpassword) ->
       let off = put_string (buf, off) "password" in
       (match oldpassword with
        | None ->
          let off = put_bool (buf, off) false in
          put_string (buf, off) password
        | Some oldpassword ->
          let off = put_bool (buf, off) true in
          let off = put_string (buf, off) oldpassword in
          put_string (buf, off) password)
     | Keyboard_interactive (lopt, submeths) ->
       let off = put_string (buf, off) "keyboard-interactive" in
       let off = put_string (buf, off) (Option.value ~default:"" lopt) in
       put_string (buf, off) (String.concat "," submeths)
     | Authnone -> put_string (buf, off) "none")
  | Msg_userauth_failure (nl, psucc) ->
    let off = put_id (buf, off) MSG_USERAUTH_FAILURE in
    let off = put_nl (buf, off) nl in
    put_bool (buf, off) psucc
  | Msg_userauth_success ->
    put_id (buf, off) MSG_USERAUTH_SUCCESS
  | Msg_userauth_banner (message, lang) ->
    let off = put_id (buf, off) MSG_USERAUTH_BANNER in
    let off = put_string (buf, off) message in
    put_string (buf, off) lang
  | Msg_userauth_pk_ok pubkey ->
    let off = put_id (buf, off) MSG_USERAUTH_1 in
    let off = put_string (buf, off) (Hostkey.sshname pubkey) in
    put_pubkey (buf, off) pubkey
  | Msg_userauth_info_request (name, instruction, lang, prompts) ->
    let off = put_id (buf, off) MSG_USERAUTH_1 in
    let off = put_string (buf, off) name in
    let off = put_string (buf, off) instruction in
    let off = put_string (buf, off) lang in
    let off = put_uint32 (buf, off) (Int32.of_int (List.length prompts)) in
    List.fold_left (fun off (prompt, echo) ->
        let off = put_string (buf, off) prompt in
        put_bool (buf, off) echo)
      off prompts
  | Msg_userauth_info_response passwords ->
    let off = put_id (buf, off) MSG_USERAUTH_2 in
    let off = put_uint32 (buf, off) (Int32.of_int (List.length passwords)) in
    List.fold_left (fun off password ->
        put_string (buf, off) password)
      off passwords
  | Msg_userauth_1 _ -> assert false
  | Msg_userauth_2 _ -> assert false
  | Msg_global_request (request, want_reply, global_request) ->
    let off = put_id (buf, off) MSG_GLOBAL_REQUEST in
    let off = put_string (buf, off) request in
    let off = put_bool (buf, off) want_reply in
    (match global_request with
     | Tcpip_forward (address, port) ->
       let off = put_string (buf, off) address in
       put_uint32 (buf, off) port
     | Cancel_tcpip_forward (address, port) ->
       let off = put_string (buf, off) address in
       put_uint32 (buf, off) port
     | Unknown_request _ -> assert false)
  | Msg_request_success (req_data) ->
    let off = put_id (buf, off) MSG_REQUEST_SUCCESS in
    (match req_data with
     | Some data -> put_string (buf, off) data
     | None -> off)
  | Msg_request_failure ->
    put_id (buf, off) MSG_REQUEST_FAILURE
  | Msg_channel_open (channel, init_win, max_pkt, data) ->
    let request = match data with
      | Session -> "session"
      | X11 _ -> "x11"
      | Forwarded_tcpip _ -> "forwarded-tcpip"
      | Direct_tcpip _ -> "direct-tcpip"
      | Raw_data _ -> invalid_arg "Unknown channel type"
    in
    let off = put_id (buf, off) MSG_CHANNEL_OPEN in
    let off = put_string (buf, off) request in
    let off = put_uint32 (buf, off) channel in
    let off = put_uint32 (buf, off) init_win in
    let off = put_uint32 (buf, off) max_pkt in
    put_channel_data (buf, off) data
  | Msg_channel_open_confirmation (recp_channel, send_channel,
                                   init_win, max_pkt, data) ->
    let off = put_id (buf, off) MSG_CHANNEL_OPEN_CONFIRMATION in
    let off = put_uint32 (buf, off) recp_channel in
    let off = put_uint32 (buf, off) send_channel in
    let off = put_uint32 (buf, off) init_win in
    let off = put_uint32 (buf, off) max_pkt in
    put_raw (buf, off) data
  | Msg_channel_open_failure (recp_channel, reason, desc, lang) ->
    let off = put_id (buf, off) MSG_CHANNEL_OPEN_FAILURE in
    let off = put_uint32 (buf, off) recp_channel in
    let off = put_uint32 (buf, off) reason in
    let off = put_string (buf, off) desc in
    put_string (buf, off) lang
  | Msg_channel_window_adjust (channel, n) ->
    let off = put_id (buf, off) MSG_CHANNEL_WINDOW_ADJUST in
    let off = put_uint32 (buf, off) channel in
    put_uint32 (buf, off) n
  | Msg_channel_data (channel, data) ->
    let off = put_id (buf, off) MSG_CHANNEL_DATA in
    let off = put_uint32 (buf, off) channel in
    put_string (buf, off) data
  | Msg_channel_extended_data (channel, data_type, data) ->
    let off = put_id (buf, off) MSG_CHANNEL_EXTENDED_DATA in
    let off = put_uint32 (buf, off) channel in
    let off = put_uint32 (buf, off) data_type in
    put_string (buf, off) data
  | Msg_channel_eof channel ->
    let off = put_id (buf, off) MSG_CHANNEL_EOF in
    put_uint32 (buf, off) channel
  | Msg_channel_close channel ->
    let off = put_id (buf, off) MSG_CHANNEL_CLOSE in
    put_uint32 (buf, off) channel
  | Msg_channel_request (channel, want_reply, data) ->
    let request = match data with
      | Pty_req _ -> "pty-req"
      | X11_req _ -> "x11-req"
      | Env _ -> "env"
      | Shell -> "shell"
      | Exec _ -> "exec"
      | Subsystem _ -> "subsystem"
      | Window_change _ -> "window-change"
      | Xon_xoff _ -> "xon-xoff"
      | Signal _ -> "signal"
      | Exit_status _ -> "exit-status"
      | Exit_signal _ -> "exit-signal"
      | Raw_data _ -> invalid_arg "Unknown channel request type"
    in
    let off = put_id (buf, off) MSG_CHANNEL_REQUEST in
    let off = put_uint32 (buf, off) channel in
    let off = put_string (buf, off) request in
    let off = put_bool (buf, off) want_reply in
    (match data with
     | Pty_req (term_env, width_char, height_row, width_px, height_px,
                term_modes) ->
       let off = put_string (buf, off) term_env in
       let off = put_uint32 (buf, off) width_char in
       let off = put_uint32 (buf, off) height_row in
       let off = put_uint32 (buf, off) width_px in
       let off = put_uint32 (buf, off) height_px in
       put_string (buf, off) term_modes
     | X11_req (single_con, x11_auth_proto, x11_auth_cookie, x11_screen_nr) ->
       let off = put_bool (buf, off) single_con in
       let off = put_string (buf, off) x11_auth_proto in
       let off = put_string (buf, off) x11_auth_cookie in
       put_uint32 (buf, off) x11_screen_nr
     | Env (name, value) ->
       let off = put_string (buf, off) name in
       put_string (buf, off) value
     | Shell -> off
     | Exec command -> put_string (buf, off) command
     | Subsystem name -> put_string (buf, off) name
     | Window_change (width_char, height_row, width_px, height_px) ->
       let off = put_uint32 (buf, off) width_char in
       let off = put_uint32 (buf, off) height_row in
       let off = put_uint32 (buf, off) width_px in
       put_uint32 (buf, off) height_px
     | Xon_xoff client_can_do -> put_bool (buf, off) client_can_do
     | Signal name -> put_string (buf, off) name
     | Exit_status status -> put_uint32 (buf, off) status
     | Exit_signal (name, core_dumped, message, lang) ->
       let off = put_string (buf, off) name in
       let off = put_bool (buf, off) core_dumped in
       let off = put_string (buf, off) message in
       put_string (buf, off) lang
     | Raw_data _ -> invalid_arg "Unknown channel request type")
  | Msg_channel_success channel ->
    let off = put_id (buf, off) MSG_CHANNEL_SUCCESS in
    put_uint32 (buf, off) channel
  | Msg_channel_failure channel ->
    let off = put_id (buf, off) MSG_CHANNEL_FAILURE in
    put_uint32 (buf, off) channel
  | Msg_version version ->  (* Mocked up version message *)
    put_raw (buf, off) (version ^ "\r\n")

let get_version buf =
  (* Fetches next line, returns maybe a string and the remainder of buf *)
  let fetchline buf =
    if String.length buf < 1 then
      None
    else
      let n = try String.index buf '\n' with Not_found -> 0 in
      if n = 0 then
        None
      else
        let off = if String.get buf (pred n) = '\r' then 1 else 0 in
        let line = String.sub buf 0 (n - off) in
        let line_len = String.length line in
        let v = String.sub buf (line_len + 1 + off) (String.length buf - line_len - 1 - off) in
        Some (line, v)
  in
  (* Extract SSH version from line *)
  let processline line =
    let line_len = String.length line in
    if line_len < 4 || not String.(equal (sub line 0 4) "SSH-") then
      Ok None
    else if line_len < 9 then
      Error "Version line is too short"
    else
      (* Strip the comments *)
      let version_line =
        try
          String.sub line 0 (String.index line ' ')
        with Not_found -> line
      in
      let tokens = String.split_on_char '-' version_line in
      if List.length tokens < 3 then
        Error ("Can't parse version line: " ^ version_line)
      else
        let version = List.nth tokens 1 in
        if String.equal version "2.0" then
          Ok (Some line)
        else
          Error ("Bad version " ^ version)
  in
  (* Scan all lines until an error or SSH version is found *)
  let rec scan buf =
    match fetchline buf with
    | None -> if String.length buf > 1024 then
        Error "Buffer is too big"
      else
        Ok (None, buf)
    | Some (line, buf) ->
      let* v = processline line in
      match v with
      | Some peer_version -> Ok (Some peer_version, buf)
      | None ->
        if String.length buf > 2 then
          scan buf
        else
          Ok (None, buf)
  in
  scan buf
