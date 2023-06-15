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

let get_uint32 buf =
  trap_error (fun () ->
      Cstruct.BE.get_uint32 buf 0, Cstruct.shift buf 4)

let put_uint32 = Dbuf.put_uint32_be

let get_uint8 buf =
  trap_error (fun () ->
      Cstruct.get_uint8 buf 0, Cstruct.shift buf 1)

let put_uint8 = Dbuf.put_uint8

let get_bool buf =
  let* b, buf = get_uint8 buf in
  Ok (b <> 0, buf)

let put_bool b t =
  let x = if b then 1 else 0 in
  Dbuf.put_uint8 x t

let get_string buf =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      Ssh.guard_sshlen_exn len;
      (Cstruct.to_string buf ~off:4 ~len), Cstruct.shift buf (len + 4))

let put_string s t =
  let len = String.length s in
  let t = put_uint32 (Int32.of_int len) t in
  let t = Dbuf.guard_space len t in
  Cstruct.blit_from_string s 0 t.Dbuf.cbuf t.Dbuf.coff len;
  Dbuf.shift len t

let get_cstring buf =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      Ssh.guard_sshlen_exn len;
      Cstruct.split (Cstruct.shift buf 4) len)

let put_cstring s t =
  let len = Cstruct.length s in
  let t = put_uint32 (Int32.of_int len) t in
  let t = Dbuf.guard_space len t in
  Cstruct.blit s 0 t.Dbuf.cbuf t.Dbuf.coff len;
  Dbuf.shift len t

let put_raw buf t =
  let len = Cstruct.length buf in
  let t = Dbuf.guard_space len t in
  Cstruct.blit buf 0 t.Dbuf.cbuf t.Dbuf.coff len;
  Dbuf.shift len t

let put_random len t =
  put_raw (Mirage_crypto_rng.generate len) t

let get_mpint ?(signed = true) buf =
  trap_error (fun () ->
      match ((Cstruct.BE.get_uint32 buf 0) |> Int32.to_int) with
      | 0 -> Z.zero, Cstruct.shift buf 4
      | len ->
        Ssh.guard_sshlen_exn len;
        let mpbuf = Cstruct.sub buf 4 len in
        let msb = Cstruct.get_uint8 mpbuf 0 in
        if signed && (msb land 0x80) <> 0 then
          invalid_arg "Negative mpint"
        else
          (* of_cstruct_be strips leading zeros for us *)
          Mirage_crypto_pk.Z_extra.of_cstruct_be mpbuf,
          Cstruct.shift buf (len + 4))

let put_mpint ?(signed = true) mpint t =
  let mpbuf = Mirage_crypto_pk.Z_extra.to_cstruct_be mpint in
  let mplen = Cstruct.length mpbuf in
  let t =
    if signed && mplen > 0 &&
       ((Cstruct.get_uint8 mpbuf 0) land 0x80) <> 0 then
      put_uint32 (Int32.of_int (succ mplen)) t |>
      put_uint8 0
    else
      put_uint32 (Int32.of_int mplen) t
  in
  put_raw mpbuf t

let get_message_id buf =
  trap_error (fun () ->
      let id = (Cstruct.get_uint8 buf 0) in
      match Ssh.int_to_message_id id with
      | None -> invalid_arg (sprintf "Unknown message id %d" id)
      | Some msgid -> msgid, (Cstruct.shift buf 1))

let put_message_id id buf =
  put_uint8 (Ssh.message_id_to_int id) buf

let get_nl buf =
  let* s, buf = get_string buf in
  Ok ((String.split_on_char ',' s), buf)

let put_nl nl t =
  put_string (String.concat "," nl) t

let blob_of_pubkey pk =
  let buf = put_string (Hostkey.sshname pk) (Dbuf.create ()) in
  let buf' =
    match pk with
    | Hostkey.Rsa_pub rsa ->
      let open Mirage_crypto_pk.Rsa in
      put_mpint rsa.e buf |>
      put_mpint rsa.n
    | Hostkey.Ed25519_pub pub ->
      let pub_cs = Mirage_crypto_ec.Ed25519.pub_to_cstruct pub in
      put_string (Cstruct.to_string pub_cs) buf
  in
  Dbuf.to_cstruct buf'

let pubkey_of_blob blob =
  let* key_type, blob = Result.map_error (fun s -> `Msg s) (get_string blob) in
  match key_type with
  | "ssh-rsa" ->
    let* e, blob = Result.map_error (fun s -> `Msg s) (get_mpint blob) in
    let* n, _ = Result.map_error (fun s -> `Msg s) (get_mpint blob) in
    let* pub = Mirage_crypto_pk.Rsa.pub ~e ~n in
    Ok (Hostkey.Rsa_pub pub)
  | "ssh-ed25519" ->
    let* pub, _ = Result.map_error (fun s -> `Msg s) (get_string blob) in
    let cs = Cstruct.of_string pub in
    let* pubkey =
      Result.map_error
        (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
        (Mirage_crypto_ec.Ed25519.pub_of_cstruct cs)
    in
    Ok (Hostkey.Ed25519_pub pubkey)
  | k -> Error (`Unsupported k)

let pubkey_of_blob_error_as_string blob =
    Result.map_error
      (function `Msg s -> s | `Unsupported alg -> "unsupported algorithm: " ^ alg)
      (pubkey_of_blob blob)

(* Prefer using get_pubkey_alg always *)
let get_pubkey_any buf =
  let* blob, buf = get_cstring buf in
  let* pubkey = pubkey_of_blob_error_as_string blob in
  Ok (pubkey, buf)

(* Always use get_pubkey_alg since it returns Unknown if key_alg mismatches *)
let get_pubkey key_alg buf =
  let* pubkey, buf = get_pubkey_any buf in
  if Hostkey.comptible_alg pubkey key_alg then
    Ok (pubkey, buf)
  else
    Error ("public key algorithm not supported " ^ key_alg)

let put_pubkey pubkey t =
  put_cstring (blob_of_pubkey pubkey) t

let pubkey_of_openssh buf =
  let s = Cstruct.to_string buf in
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
  let* key = pubkey_of_blob_error_as_string (Cstruct.of_string blob) in
  let* () = guard (Hostkey.sshname key = key_type) "Key type mismatch" in
  Ok key

let openssh_of_pubkey key =
  let key_buf = blob_of_pubkey key |> Cstruct.to_string |> Base64.encode_string in
  String.concat "" [ Hostkey.sshname key ; " "; key_buf; " awa-ssh\n" ]
  |> Cstruct.of_string

let privkey_of_pem buf =
  let* p = X509.Private_key.decode_pem buf in
  match p with
  | `RSA key -> Ok (Hostkey.Rsa_priv key)
  | `ED25519 key -> Ok (Hostkey.Ed25519_priv key)
  | _ -> Error (`Msg "unsupported private key")

let privkey_of_openssh buf =
  (* as defined in https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/plain *)
  let id s =
    let dash = "-----" in
    dash ^ (if s then "BEGIN" else "END") ^ " OPENSSH PRIVATE KEY" ^ dash
  in
  let data = Cstruct.to_string buf in
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
  let cs = Cstruct.of_string data in
  let auth_magic = Cstruct.of_string "openssh-key-v1\000" in
  let pre, cs = Cstruct.split cs (Cstruct.length auth_magic) in
  let* () = guard (Cstruct.equal pre auth_magic) "bad auth magic" in
  let* cipher, cs = get_string cs in
  let* () = guard (String.equal cipher "none") "only unencrypted private keys supported" in
  let* kdf, cs = get_string cs in
  let* () = guard (String.equal kdf "none") "only unencrypted private keys supported" in
  let* kdfopts, cs = get_string cs in
  let* () = guard (String.equal kdfopts "") "only no kdfoptions supported" in
  let* keys, cs = get_uint32 cs in
  let* () = guard (keys = 1l) "only one key supported" in
  let* pklen, cs = get_uint32 cs in
  let* _plen, priv = get_uint32 (Cstruct.shift cs (Int32.to_int pklen)) in
  (* 64 bit checkint - useful when crypted *)
  let* keytype, cs = get_string (Cstruct.shift priv 8) in
  match keytype with
  | "ssh-ed25519" ->
    let* _pub, cs = get_cstring cs in
    let* priv, cs = get_cstring cs in
    let* comment, _padding = get_string cs in
    let priv = Cstruct.sub priv 0 32 in
    let* priv_key =
      Result.map_error
        (Fmt.to_to_string Mirage_crypto_ec.pp_error)
        (Mirage_crypto_ec.Ed25519.priv_of_cstruct priv)
    in
    Ok (Hostkey.Ed25519_priv priv_key, comment)
  | "ssh-rsa" ->
    let* n, cs = get_mpint cs in
    let* e, cs = get_mpint cs in
    let* d, cs = get_mpint cs in
    let* q', cs = get_mpint cs in
    let* p, cs = get_mpint cs in
    let* q, cs = get_mpint cs in
    let* comment, _padding = get_string cs in
    let dp = Z.(d mod (pred p)) and dq = Z.(d mod (pred q)) in
    let* p =
      Result.map_error
        (function `Msg m -> m)
        (Mirage_crypto_pk.Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q')
    in
    Ok (Hostkey.Rsa_priv p, comment)
  | x -> Error ("unsupported key type " ^ x)

let put_kexinit kex t =
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
  let t = put_raw kex.cookie t in
  List.fold_left (fun buf nl -> put_nl nl buf) t nll |>
  put_bool kex.first_kex_packet_follows |>
  put_uint32 Int32.zero

let blob_of_kexinit kex =
  put_message_id Ssh.MSG_KEXINIT (Dbuf.create ()) |>
  put_kexinit kex |> Dbuf.to_cstruct

let rec put_extensions extensions dbuf =
  match extensions with
  | [] -> dbuf
  | Ssh.Extension { name; value } :: extensions ->
    put_string name dbuf |>
    put_string value |>
    put_extensions extensions

let get_signature_raw buf =
  let* blob, _ = get_cstring buf in
  let* sig_alg, blob = get_string blob in
  let* key_sig, _ = get_cstring blob in
  Ok (sig_alg, key_sig)

let get_signature buf =
  Result.bind
    (get_signature_raw buf)
    (fun (sig_alg, key_sig) ->
       let* sig_alg = Hostkey.alg_of_string sig_alg in
       Ok (sig_alg, key_sig))

let put_signature_raw (alg, signature) t =
  let blob =
    put_string alg (Dbuf.create ()) |>
    put_cstring signature |>
    Dbuf.to_cstruct
  in
  put_cstring blob t

let put_signature (alg, signature) t =
  put_signature_raw (Hostkey.alg_to_string alg, signature) t

let put_channel_data channel_data buf =
  let open Ssh in
  match channel_data with
  | Session -> buf
  | X11 (address, port) ->
    put_string address buf |>
    put_uint32 port
  | Forwarded_tcpip (con_addr, con_port, origin_addr, origin_port) ->
    put_string con_addr buf |>
    put_uint32 con_port |>
    put_string origin_addr |>
    put_uint32 origin_port
  | Direct_tcpip (addr, port, origin_addr, origin_port) ->
    put_string addr buf |>
    put_uint32 port |>
    put_string origin_addr |>
    put_uint32 origin_port
  | Raw_data data -> put_raw data buf

let blob_of_channel_data channel_data =
  (* XXX Dbuf.create() allocates 1KB for just a few bytes *)
  put_channel_data channel_data (Dbuf.create ()) |> Dbuf.to_cstruct

let get_message buf =
  let open Ssh in
  let msgbuf = buf in
  let* msgid, buf = get_message_id buf in
  match msgid with
  | MSG_DISCONNECT ->
    let* code, buf = get_uint32 buf in
    let* desc, buf = get_string buf in
    let* lang, _ = get_string buf in
    Ok (Msg_disconnect (int_to_disconnect_code code, desc, lang))
  | MSG_IGNORE ->
    let* x, _ = get_string buf in
    Ok (Msg_ignore x)
  | MSG_UNIMPLEMENTED ->
    let* x, _ = get_uint32 buf in
    Ok (Msg_unimplemented x)
  | MSG_DEBUG ->
    let* always_display, buf = get_bool buf in
    let* message, buf = get_string buf in
    let* lang, _ = get_string buf in
    Ok (Msg_debug (always_display, message, lang))
  | MSG_SERVICE_REQUEST ->
    let* x, _ = get_string buf in
    Ok (Msg_service_request x)
  | MSG_SERVICE_ACCEPT ->
    let* x, _ = get_string buf in
    Ok (Msg_service_accept x)
  | MSG_KEXINIT ->
    let cookiebegin = buf in
    (* Jump over cookie *)
    let* buf = cs_safe_shift buf 16 in
    let* kex_algs, buf = get_nl buf in
    let* server_host_key_algs, buf = get_nl buf in
    let* encryption_algs_ctos, buf = get_nl buf in
    let* encryption_algs_stoc, buf = get_nl buf in
    let* mac_algs_ctos, buf = get_nl buf in
    let* mac_algs_stoc, buf = get_nl buf in
    let* compression_algs_ctos, buf = get_nl buf in
    let* compression_algs_stoc, buf = get_nl buf in
    let* languages_ctos, buf = get_nl buf in
    let* languages_stoc, buf = get_nl buf in
    let* first_kex_packet_follows, _ = get_bool buf in
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
          { cookie = Cstruct.sub cookiebegin 0 16;
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
            rawkex = msgbuf })
  | MSG_EXT_INFO ->
    let* nr_extensions, buf = get_uint32 buf in
    let* nr_extensions = match Int32.unsigned_to_int nr_extensions with
      | None -> Error "Ridiculous number of extensions advertised"
      | Some n -> Ok n
    in
    let rec loop buf n acc =
      if n = 0 then
        Ok (Msg_ext_info (List.rev acc))
      else
        let* name, buf = get_string buf in
        let* value, buf = get_string buf in
        loop buf (pred n) (Extension { name; value } :: acc)
    in
    loop buf nr_extensions []
  | MSG_NEWKEYS ->
    Ok Msg_newkeys
  | MSG_KEX_0 | MSG_KEX_1 | MSG_KEX_2 | MSG_KEX_3 | MSG_KEX_4 ->
    Ok (Msg_kex (msgid, buf))
  | MSG_USERAUTH_REQUEST ->
    let* user, buf = get_string buf in
    let* service, buf = get_string buf in
    let* auth_method, buf = get_string buf in
    let* auth_method, _ =
      match auth_method with
      | "publickey" ->
        let* has_sig, buf = get_bool buf in
        let* sig_alg_raw, buf = get_string buf in
        let* pubkey_raw, buf = get_cstring buf in
        if has_sig then
          let* signature = get_signature_raw buf in
          Ok (Pubkey (sig_alg_raw, pubkey_raw, Some signature), buf)
        else
          Ok (Pubkey (sig_alg_raw, pubkey_raw, None), buf)
      | "password" ->
        let* has_old, buf = get_bool buf in
        if has_old then
          let* oldpassword, buf = get_string buf in
          let* password, buf = get_string buf in
          Ok (Password (password, Some oldpassword), buf)
        else
          let* password, buf = get_string buf in
          Ok (Password (password, None), buf)
      | "keyboard-interactive" ->
        let* language, buf = get_string buf in
        let* submethods, buf = get_string buf in
        let lang_opt = if String.length language = 0 then None else Some language
        and submethods = String.split_on_char ',' submethods
        in
        Ok (Keyboard_interactive (lang_opt, submethods), buf)
      | "none" -> Ok (Authnone, buf)
      | _ -> Error ("Unknown method " ^ auth_method)
    in
    Ok (Msg_userauth_request (user, service, auth_method))
  | MSG_USERAUTH_FAILURE ->
    let* nl, buf = get_nl buf in
    let* psucc, _ = get_bool buf in
    Ok (Msg_userauth_failure (nl, psucc))
  | MSG_USERAUTH_SUCCESS -> Ok Msg_userauth_success
  | MSG_USERAUTH_1 -> Ok (Msg_userauth_1 buf)
  | MSG_USERAUTH_2 -> Ok (Msg_userauth_2 buf)
  | MSG_USERAUTH_BANNER ->
    let* s1, buf = get_string buf in
    let* s2, _ = get_string buf in
    Ok (Msg_userauth_banner (s1, s2))
  | MSG_GLOBAL_REQUEST ->
    let* request, buf = get_string buf in
    let* want_reply, buf = get_bool buf in
    let* global_request, _ =
      match request with
      | "tcpip-forward" ->
        let* address, buf = get_string buf in
        let* port, buf = get_uint32 buf in
        Ok (Tcpip_forward (address, port), buf)
      | "cancel-tcpip-forward" ->
        let* address, buf = get_string buf in
        let* port, buf = get_uint32 buf in
        Ok (Cancel_tcpip_forward (address, port), buf)
      | _ ->
        let* data, buf = get_string buf in
        Ok (Unknown_request data, buf)
    in
    Ok (Msg_global_request (request, want_reply, global_request))
  | MSG_REQUEST_SUCCESS ->
    let req_data = if Cstruct.length buf > 0 then Some buf else None in
    Ok (Msg_request_success req_data)
  | MSG_REQUEST_FAILURE -> Ok Msg_request_failure
  | MSG_CHANNEL_OPEN ->
    let* request, buf = get_string buf in
    let* send_channel, buf = get_uint32 buf in
    let* init_win, buf = get_uint32 buf in
    let* max_pkt, buf = get_uint32 buf in
    (match request with
     | "session" ->
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt, Session))
     | "x11" ->
       let* address, buf = get_string buf in
       let* port, _ = get_uint32 buf in
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              (X11 (address, port))))
     | "forwarded-tcpip" ->
       let* con_address, buf = get_string buf in
       let* con_port, buf = get_uint32 buf in
       let* origin_address, buf = get_string buf in
       let* origin_port, _ = get_uint32 buf in
       Ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              Forwarded_tcpip (con_address, con_port, origin_address,
                               origin_port)))
     | _ -> Error ("Unknown channel open " ^ request))
  | MSG_CHANNEL_OPEN_CONFIRMATION ->
    let* recp_channel, buf = get_uint32 buf in
    let* send_channel, buf = get_uint32 buf in
    let* init_win, buf = get_uint32 buf in
    let* max_pkt, buf = get_uint32 buf in
    (*
     * The protocol does not tell us which channel type this is, so we can't
     * give the caller a good type for channel open and must return Raw_data.
     * We must provide the caller a function to make the conversion.
     *)
    Ok (Msg_channel_open_confirmation
          (recp_channel, send_channel,
           init_win, max_pkt,
           buf))
  | MSG_CHANNEL_OPEN_FAILURE ->
    let* recp_channel, buf = get_uint32 buf in
    let* reason, buf = get_uint32 buf in
    let* desc, buf = get_string buf in
    let* lang, _ = get_string buf in
    Ok (Msg_channel_open_failure (recp_channel, reason, desc, lang))
  | MSG_CHANNEL_WINDOW_ADJUST ->
    let* channel, buf = get_uint32 buf in
    let* n, _ = get_uint32 buf in
    Ok (Msg_channel_window_adjust (channel, n))
  | MSG_CHANNEL_DATA ->
    let* channel, buf = get_uint32 buf in
    let* data, _ = get_cstring buf in
    Ok (Msg_channel_data (channel, data))
  | MSG_CHANNEL_EXTENDED_DATA ->
    let* channel, buf = get_uint32 buf in
    let* data_type, buf = get_uint32 buf in
    let* data, _ = get_cstring buf in
    Ok (Msg_channel_extended_data (channel, data_type, data))
  | MSG_CHANNEL_EOF ->
    let* channel, _ = get_uint32 buf in
    Ok (Msg_channel_eof channel)
  | MSG_CHANNEL_CLOSE ->
    let* channel, _ = get_uint32 buf in
    Ok (Msg_channel_close channel)
  | MSG_CHANNEL_REQUEST ->
    let* channel, buf = get_uint32 buf in
    let* request, buf = get_string buf in
    let* want_reply, buf = get_bool buf in
    (match request with
     | "pty-req" ->
       let* term_env, buf = get_string buf in
       let* width_char, buf = get_uint32 buf in
       let* height_row, buf = get_uint32 buf in
       let* width_px, buf = get_uint32 buf in
       let* height_px, buf = get_uint32 buf in
       let* term_modes, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Pty_req (term_env, width_char, height_row,
                                         width_px, height_px, term_modes)))
     | "x11-req" ->
       let* single_con, buf = get_bool buf in
       let* x11_auth_proto, buf = get_string buf in
       let* x11_auth_cookie, buf = get_string buf in
       let* x11_screen_nr, _ = get_uint32 buf in
       Ok (Msg_channel_request (channel, want_reply,
                                X11_req (single_con, x11_auth_proto,
                                         x11_auth_cookie, x11_screen_nr)))
     | "env" ->
       let* name, buf = get_string buf in
       let* value, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Env (name, value)))
     | "exec" ->
       let* command, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Exec (command)))
     | "shell" -> Ok (Msg_channel_request (channel, want_reply, Shell))
     | "subsystem" ->
       let* name, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Subsystem (name)))
     | "window-change" ->
       let* width_char, buf = get_uint32 buf in
       let* height_row, buf = get_uint32 buf in
       let* width_px, buf = get_uint32 buf in
       let* height_px, _ = get_uint32 buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Window_change (width_char, height_row,
                                               width_px, height_px)))
     | "xon-xoff" ->
       let* client_can_do, _ = get_bool buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Xon_xoff (client_can_do)))
     | "signal" ->
       let* name, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Signal (name)))
     | "exit-status" ->
       let* status, _ = get_uint32 buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Exit_status (status)))
     | "exit-signal" ->
       let* name, buf = get_string buf in
       let* core_dumped, buf = get_bool buf in
       let* message, buf = get_string buf in
       let* lang, _ = get_string buf in
       Ok (Msg_channel_request (channel, want_reply,
                                Exit_signal (name, core_dumped, message, lang)))
     | _ -> Error ("Unknown channel request " ^ request))
  | MSG_CHANNEL_SUCCESS ->
    let* channel, _ = get_uint32 buf in
    Ok (Msg_channel_success channel)
  | MSG_CHANNEL_FAILURE ->
    let* channel, _ = get_uint32 buf in
    Ok (Msg_channel_failure channel)
  | MSG_VERSION ->
    Error "got MSG_VERSION"

let dh_kexdh_of_kex id buf =
  (* for common DH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    let* e, _ = get_mpint buf in
    Ok (Msg_kexdh_init e)
  | MSG_KEX_1 ->
    let* k_s, buf = get_pubkey_any buf in
    let* f, buf = get_mpint buf in
    let* key_sig = get_signature buf in
    Ok (Msg_kexdh_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let dh_kexecdh_of_kex id buf =
  (* for ECDH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    let* e, _ = get_mpint ~signed:false buf in
    Ok (Msg_kexecdh_init e)
  | MSG_KEX_1 ->
    let* k_s, buf = get_pubkey_any buf in
    let* f, buf = get_mpint ~signed:false buf in
    let* key_sig = get_signature buf in
    Ok (Msg_kexecdh_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let dh_kexdh_gex_of_kex id buf =
  (* for RFC 4419 GEX *)
  let open Ssh in
  match id with
  | MSG_KEX_4 ->
    let* min, buf = get_uint32 buf in
    let* n, buf = get_uint32 buf in
    let* max, _ = get_uint32 buf in
    Ok (Msg_kexdh_gex_request (min, n, max))
  | MSG_KEX_1 ->
    let* p, buf = get_mpint buf in
    let* g, _ = get_mpint buf in
    Ok (Msg_kexdh_gex_group (p, g))
  | MSG_KEX_2 ->
    let* e, _ = get_mpint buf in
    Ok (Msg_kexdh_gex_init e)
  | MSG_KEX_3 ->
    let* k_s, buf = get_pubkey_any buf in
    let* f, buf = get_mpint buf in
    let* key_sig = get_signature buf in
    Ok (Msg_kexdh_gex_reply (k_s, f, key_sig))
  | _ -> Error "unsupported KEX message"

let userauth_pk_ok buf =
  let* key_alg, buf = get_string buf in
  let* pubkey, _ = get_pubkey key_alg buf in
  Ok (Ssh.Msg_userauth_pk_ok pubkey)

let userauth_info_request buf =
  let* name, buf = get_string buf in
  let* instruction, buf = get_string buf in
  let* lang, buf = get_string buf in
  let* num_prompts, buf = get_uint32 buf in
  let rec collect_prompts buf acc = function
    | 0 -> Ok (List.rev acc)
    | n ->
      let* prompt, buf = get_string buf in
      let* echo, buf = get_bool buf in
      collect_prompts buf ((prompt, echo) :: acc) (n - 1)
  in
  let* prompts = collect_prompts buf [] (Int32.to_int num_prompts) in
  Ok (Ssh.Msg_userauth_info_request (name, instruction, lang, prompts))

let put_message msg buf =
  let open Ssh in
  let put_id = put_message_id in (* save some columns *)
  match msg with
  | Msg_disconnect (code, desc, lang) ->
    put_id MSG_DISCONNECT buf |>
    put_uint32 (disconnect_code_to_int code) |>
    put_string desc |>
    put_string lang
  | Msg_ignore s ->
    put_id MSG_IGNORE buf |>
    put_string s
  | Msg_unimplemented x ->
    put_id MSG_UNIMPLEMENTED buf |>
    put_uint32 x
  | Msg_debug (always_display, message, lang) ->
    put_id MSG_DEBUG buf |>
    put_bool always_display |>
    put_string message |>
    put_string lang
  | Msg_service_request s ->
    put_id MSG_SERVICE_REQUEST buf |>
    put_string s
  | Msg_service_accept s ->
    put_id MSG_SERVICE_ACCEPT buf |>
    put_string s
  | Msg_kexinit kex ->
    put_id MSG_KEXINIT buf |>
    put_kexinit kex
  | Msg_ext_info extensions ->
    let nr_extensions = List.length extensions in
    put_id MSG_EXT_INFO buf |>
    (* XXX: overflow *)
    put_uint32 (Int32.of_int nr_extensions) |>
    put_extensions extensions
  | Msg_newkeys ->
    put_id MSG_NEWKEYS buf
  | Msg_kexdh_init e ->
    put_id MSG_KEX_0 buf |>
    put_mpint e
  | Msg_kexdh_reply (k_s, f, signature) ->
    put_id MSG_KEX_1 buf |>
    put_pubkey k_s |>
    put_mpint f |>
    put_signature signature
  | Msg_kexecdh_init e ->
    put_id MSG_KEX_0 buf |>
    put_mpint ~signed:false e
  | Msg_kexecdh_reply (k_s, f, signature) ->
    put_id MSG_KEX_1 buf |>
    put_pubkey k_s |>
    put_mpint ~signed:false f |>
    put_signature signature
  | Msg_kexdh_gex_request (min, n, max) ->
    put_id MSG_KEX_4 buf |>
    put_uint32 min |>
    put_uint32 n |>
    put_uint32 max
  | Msg_kexdh_gex_group (p, g) ->
    put_id MSG_KEX_1 buf |>
    put_mpint p |>
    put_mpint g
  | Msg_kexdh_gex_init e ->
    put_id MSG_KEX_2 buf |>
    put_mpint e
  | Msg_kexdh_gex_reply (k_s, f, signature) ->
    put_id MSG_KEX_3 buf |>
    put_pubkey k_s |>
    put_mpint f |>
    put_signature signature
  | Msg_kex _ -> assert false
  | Msg_userauth_request (user, service, auth_method) ->
    let buf = put_id MSG_USERAUTH_REQUEST buf |>
              put_string user |>
              put_string service
    in
    (match auth_method with
     | Pubkey (sig_alg_raw, pubkey_raw, signature) ->
       let buf =
         put_string "publickey" buf |>
         put_bool (is_some signature) |>
         put_string sig_alg_raw |>
         put_cstring pubkey_raw
       in
       (match signature with
        | None -> buf
        | Some signature -> put_signature_raw signature buf)
     | Password (password, oldpassword) ->
       let buf = put_string "password" buf in
       (match oldpassword with
        | None ->
          put_bool false buf |>
          put_string password
        | Some oldpassword ->
          put_bool true buf |>
          put_string oldpassword |>
          put_string password)
     | Keyboard_interactive (lopt, submeths) ->
       let buf = put_string "keyboard-interactive" buf in
       let buf = put_string (Option.value ~default:"" lopt) buf in
       put_string (String.concat "," submeths) buf
     | Authnone -> put_string "none" buf)
  | Msg_userauth_failure (nl, psucc) ->
    put_id MSG_USERAUTH_FAILURE buf |>
    put_nl nl |>
    put_bool psucc
  | Msg_userauth_success ->
    put_id MSG_USERAUTH_SUCCESS buf
  | Msg_userauth_banner (message, lang) ->
    put_id MSG_USERAUTH_BANNER buf |>
    put_string message |>
    put_string lang
  | Msg_userauth_pk_ok pubkey ->
    put_id MSG_USERAUTH_1 buf |>
    put_string (Hostkey.sshname pubkey) |>
    put_pubkey pubkey
  | Msg_userauth_info_request (name, instruction, lang, prompts) ->
    let buf =
      put_id MSG_USERAUTH_1 buf |>
      put_string name |>
      put_string instruction |>
      put_string lang |>
      put_uint32 (Int32.of_int (List.length prompts))
    in
    List.fold_left (fun buf (prompt, echo) ->
        put_string prompt buf |>
        put_bool echo)
      buf prompts
  | Msg_userauth_info_response passwords ->
    let buf =
      put_id MSG_USERAUTH_2 buf |>
      put_uint32 (Int32.of_int (List.length passwords))
    in
    List.fold_left (fun buf password ->
        put_string password buf)
      buf passwords
  | Msg_userauth_1 _ -> assert false
  | Msg_userauth_2 _ -> assert false
  | Msg_global_request (request, want_reply, global_request) ->
    let buf = put_id MSG_GLOBAL_REQUEST buf |>
              put_string request |>
              put_bool want_reply
    in
    (match global_request with
     | Tcpip_forward (address, port) ->
       put_string address buf |>
       put_uint32 port
     | Cancel_tcpip_forward (address, port) ->
       put_string address buf |>
       put_uint32 port
     | Unknown_request _ -> assert false)
  | Msg_request_success (req_data) ->
    let buf = put_id MSG_REQUEST_SUCCESS buf in
    (match req_data with
     | Some data -> put_cstring data buf
     | None -> buf)
  | Msg_request_failure ->
    put_id MSG_REQUEST_FAILURE buf
  | Msg_channel_open (channel, init_win, max_pkt, data) ->
    let request = match data with
      | Session -> "session"
      | X11 _ -> "x11"
      | Forwarded_tcpip _ -> "forwarded-tcpip"
      | Direct_tcpip _ -> "direct-tcpip"
      | Raw_data _ -> invalid_arg "Unknown channel type"
    in
    put_id MSG_CHANNEL_OPEN buf |>
    put_string request |>
    put_uint32 channel |>
    put_uint32 init_win |>
    put_uint32 max_pkt |>
    put_channel_data data
  | Msg_channel_open_confirmation (recp_channel, send_channel,
                                   init_win, max_pkt, data) ->
    put_id MSG_CHANNEL_OPEN_CONFIRMATION buf |>
    put_uint32 recp_channel |>
    put_uint32 send_channel |>
    put_uint32 init_win |>
    put_uint32 max_pkt |>
    put_raw data
  | Msg_channel_open_failure (recp_channel, reason, desc, lang) ->
    put_id MSG_CHANNEL_OPEN_FAILURE buf |>
    put_uint32 recp_channel |>
    put_uint32 reason |>
    put_string desc |>
    put_string lang
  | Msg_channel_window_adjust (channel, n) ->
    put_id MSG_CHANNEL_WINDOW_ADJUST buf |>
    put_uint32 channel |>
    put_uint32 n
  | Msg_channel_data (channel, data) ->
    put_id MSG_CHANNEL_DATA buf |>
    put_uint32 channel |>
    put_cstring data
  | Msg_channel_extended_data (channel, data_type, data) ->
    put_id MSG_CHANNEL_EXTENDED_DATA buf |>
    put_uint32 channel |>
    put_uint32 data_type |>
    put_cstring data
  | Msg_channel_eof channel ->
    put_id MSG_CHANNEL_EOF buf |>
    put_uint32 channel
  | Msg_channel_close channel ->
    put_id MSG_CHANNEL_CLOSE buf |>
    put_uint32 channel
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
    let buf = put_id MSG_CHANNEL_REQUEST buf |>
              put_uint32 channel |>
              put_string request |>
              put_bool want_reply
    in
    (match data with
     | Pty_req (term_env, width_char, height_row, width_px, height_px,
                term_modes) ->
       put_string term_env buf |>
       put_uint32 width_char |>
       put_uint32 height_row |>
       put_uint32 width_px |>
       put_uint32 height_px |>
       put_string term_modes
     | X11_req (single_con, x11_auth_proto, x11_auth_cookie, x11_screen_nr) ->
       put_bool single_con buf |>
       put_string x11_auth_proto |>
       put_string x11_auth_cookie |>
       put_uint32 x11_screen_nr
     | Env (name, value) ->
       put_string name buf|>
       put_string value
     | Shell -> buf
     | Exec command -> put_string command buf
     | Subsystem name -> put_string name buf
     | Window_change (width_char, height_row, width_px, height_px) ->
       put_uint32 width_char buf |>
       put_uint32 height_row |>
       put_uint32 width_px |>
       put_uint32 height_px
     | Xon_xoff client_can_do -> put_bool client_can_do buf
     | Signal name -> put_string name buf
     | Exit_status status -> put_uint32 status buf
     | Exit_signal (name, core_dumped, message, lang) ->
       put_string name buf |>
       put_bool core_dumped |>
       put_string message |>
       put_string lang
     | Raw_data _ -> invalid_arg "Unknown channel request type")
  | Msg_channel_success channel ->
    put_id MSG_CHANNEL_SUCCESS buf |>
    put_uint32 channel
  | Msg_channel_failure channel ->
    put_id MSG_CHANNEL_FAILURE buf |>
    put_uint32 channel
  | Msg_version version ->  (* Mocked up version message *)
    put_raw (Cstruct.of_string (version ^ "\r\n")) buf

let get_version buf =
  (* Fetches next line, returns maybe a string and the remainder of buf *)
  let fetchline buf =
    if Cstruct.length buf < 1 then
      None
    else
      let s = Cstruct.to_string buf in
      let n = try String.index s '\n' with Not_found -> 0 in
      if n = 0 then
        None
      else
        let off = if String.get s (pred n) = '\r' then 1 else 0 in
        let line = String.sub s 0 (n - off) in
        let line_len = String.length line in
        let v = Cstruct.shift buf (line_len + 1 + off) in
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
    | None -> if Cstruct.length buf > 1024 then
        Error "Buffer is too big"
      else
        Ok (None, buf)
    | Some (line, buf) ->
      let* v = processline line in
      match v with
      | Some peer_version -> Ok (Some peer_version, buf)
      | None ->
        if Cstruct.length buf > 2 then
          scan buf
        else
          Ok (None, buf)
  in
  scan buf

