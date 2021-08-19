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

open Rresult.R
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
  get_uint8 buf >>= fun (b, buf) ->
  ok (b <> 0, buf)

let put_bool b t =
  let x = if b then 1 else 0 in
  Dbuf.put_uint8 x t

let get_string buf =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      Ssh.guard_sshlen_exn len;
      (Cstruct.copy buf 4 len), Cstruct.shift buf (len + 4))

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
  get_string buf >>= fun (s, buf) ->
  ok ((String.split_on_char ',' s), buf)

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
  get_string blob >>= fun (key_alg, blob) ->
  match key_alg with
  | "ssh-rsa" ->
    get_mpint blob >>= fun (e, blob) ->
    get_mpint blob >>= fun (n, _) ->
    reword_error (function `Msg m -> m)
      (Mirage_crypto_pk.Rsa.pub ~e ~n) >>= fun pub ->
    ok (Hostkey.Rsa_pub pub)
  | "ssh-ed25519" ->
    get_string blob >>= fun (pub, _) ->
    let cs = Cstruct.of_string pub in
    reword_error (Fmt.to_to_string Mirage_crypto_ec.pp_error)
      (Mirage_crypto_ec.Ed25519.pub_of_cstruct cs) >>= fun pubkey ->
    ok (Hostkey.Ed25519_pub pubkey)
  | k -> Error ("unsupported key algorithm: " ^ k)

(* Prefer using get_pubkey_alg always *)
let get_pubkey_any buf =
  get_cstring buf >>= fun (blob, buf) ->
  pubkey_of_blob blob >>= fun pubkey ->
  ok (pubkey, buf)

(* Always use get_pubkey_alg since it returns Unknown if key_alg mismatches *)
let get_pubkey key_alg buf =
  get_pubkey_any buf >>= fun (pubkey, buf) ->
  if Hostkey.comptible_alg pubkey key_alg then
    ok (pubkey, buf)
  else
    Error ("public key algorithm not supported " ^ key_alg)

let put_pubkey pubkey t =
  put_cstring (blob_of_pubkey pubkey) t

let pubkey_of_openssh buf =
  let s = Cstruct.to_string buf in
  let tokens = String.split_on_char ' ' s in
  guard (List.length tokens = 3) "Invalid format" >>= fun () ->
  let key_type = List.nth tokens 0 in
  let key_buf = List.nth tokens 1 in
  (* let key_comment = List.nth tokens 2 in *)
  reword_error (function `Msg m -> m)
    (Base64.decode key_buf) >>= fun blob ->
  (* NOTE: can't use get_pubkey here, there is no string blob *)
  pubkey_of_blob (Cstruct.of_string blob) >>= fun key ->
  guard (Hostkey.sshname key = key_type) "Key type mismatch" >>= fun () ->
  ok key

let openssh_of_pubkey key =
  let key_buf = blob_of_pubkey key |> Cstruct.to_string |> Base64.encode_string in
  String.concat "" [ Hostkey.sshname key ; " "; key_buf; " awa-ssh\n" ]
  |> Cstruct.of_string

let privkey_of_pem buf =
  X509.Private_key.decode_pem buf >>= function
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
  (match String.split_on_char '\n' data with
   | hd :: data ->
     begin match List.rev data with
       | "" :: last :: data' | last :: data' ->
         let data = String.concat "" (List.rev data') in
         if String.equal hd (id true) && String.equal last (id false) then
           Rresult.R.reword_error (function `Msg m -> m ) (Base64.decode data)
         else
           Error "not an OpenSSH private key"
       | [] -> Error "not a valid OpenSSH private key"
     end
   | [] -> Error "invalid OpenSSH private key") >>= fun data ->
  let cs = Cstruct.of_string data in
  let auth_magic = Cstruct.of_string "openssh-key-v1\000" in
  let pre, cs = Cstruct.split cs (Cstruct.length auth_magic) in
  guard (Cstruct.equal pre auth_magic) "bad auth magic" >>= fun () ->
  get_string cs >>= fun (cipher, cs) ->
  guard (String.equal cipher "none") "only unencrypted private keys supported" >>= fun () ->
  get_string cs >>= fun (kdf, cs) ->
  guard (String.equal kdf "none") "only unencrypted private keys supported" >>= fun () ->
  get_string cs >>= fun (kdfopts, cs) ->
  guard (String.equal kdfopts "") "only no kdfoptions supported" >>= fun () ->
  get_uint32 cs >>= fun (keys, cs) ->
  guard (keys = 1l) "only one key supported" >>= fun () ->
  get_uint32 cs >>= fun (pklen, cs) ->
  get_uint32 (Cstruct.shift cs (Int32.to_int pklen)) >>= fun (_plen, priv) ->
  (* 64 bit checkint - useful when crypted *)
  get_string (Cstruct.shift priv 8) >>= fun (keytype, cs) ->
  match keytype with
  | "ssh-ed25519" ->
    get_cstring cs >>= fun (_pub, cs) ->
    get_cstring cs >>= fun (priv, cs) ->
    get_string cs >>= fun (comment, _padding) ->
    let priv = Cstruct.sub priv 0 32 in
    reword_error (Fmt.to_to_string Mirage_crypto_ec.pp_error)
      (Mirage_crypto_ec.Ed25519.priv_of_cstruct priv) >>= fun priv_key ->
    Ok (Hostkey.Ed25519_priv priv_key, comment)
  | "ssh-rsa" ->
    get_mpint cs >>= fun (n, cs) ->
    get_mpint cs >>= fun (e, cs) ->
    get_mpint cs >>= fun (d, cs) ->
    get_mpint cs >>= fun (q', cs) ->
    get_mpint cs >>= fun (p, cs) ->
    get_mpint cs >>= fun (q, cs) ->
    get_string cs >>= fun (comment, _padding) ->
    let dp = Z.(d mod (pred p)) and dq = Z.(d mod (pred q)) in
    Rresult.R.reword_error (function `Msg m -> m)
      (Mirage_crypto_pk.Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q') >>= fun p ->
    Ok (Hostkey.Rsa_priv p, comment)
  | x -> Error ("unsupported key type " ^ x)

let put_kexinit kex t =
  let open Ssh in
  let nll = [ kex.kex_algs;
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

let get_signature buf =
  get_cstring buf >>= fun (blob, _) ->
  get_string blob >>= fun (key_alg, blob) ->
  Hostkey.alg_of_string key_alg >>= fun key_alg ->
  get_cstring blob >>= fun (key_sig, _) ->
  ok (key_alg, key_sig)

let put_signature (alg, signature) t =
  let blob =
    put_string (Hostkey.alg_to_string alg) (Dbuf.create ()) |>
    put_cstring signature |>
    Dbuf.to_cstruct
  in
  put_cstring blob t

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
  get_message_id buf >>= fun (msgid, buf) ->
  match msgid with
  | MSG_DISCONNECT ->
    get_uint32 buf >>= fun (code, buf) ->
    get_string buf >>= fun (desc, buf) ->
    get_string buf >>= fun (lang, _) ->
    ok (Msg_disconnect (int_to_disconnect_code code, desc, lang))
  | MSG_IGNORE ->
    get_string buf >>= fun (x, _) ->
    ok (Msg_ignore x)
  | MSG_UNIMPLEMENTED ->
    get_uint32 buf >>= fun (x, _) ->
    ok (Msg_unimplemented x)
  | MSG_DEBUG ->
    get_bool buf >>= fun (always_display, buf) ->
    get_string buf >>= fun (message, buf) ->
    get_string buf >>= fun (lang, _) ->
    ok (Msg_debug (always_display, message, lang))
  | MSG_SERVICE_REQUEST ->
    get_string buf >>= fun (x, _) ->
    ok (Msg_service_request x)
  | MSG_SERVICE_ACCEPT ->
    get_string buf >>= fun (x, _) ->
    ok (Msg_service_accept x)
  | MSG_KEXINIT ->
    let cookiebegin = buf in
    (* Jump over cookie *)
    cs_safe_shift buf 16 >>= fun buf ->
    get_nl buf >>= fun (kex_algs, buf) ->
    get_nl buf >>= fun (server_host_key_algs, buf) ->
    get_nl buf >>= fun (encryption_algs_ctos, buf) ->
    get_nl buf >>= fun (encryption_algs_stoc, buf) ->
    get_nl buf >>= fun (mac_algs_ctos, buf) ->
    get_nl buf >>= fun (mac_algs_stoc, buf) ->
    get_nl buf >>= fun (compression_algs_ctos, buf) ->
    get_nl buf >>= fun (compression_algs_stoc, buf) ->
    get_nl buf >>= fun (languages_ctos, buf) ->
    get_nl buf >>= fun (languages_stoc, buf) ->
    get_bool buf >>= fun (first_kex_packet_follows, _) ->
    ok (Msg_kexinit
          { cookie = Cstruct.sub cookiebegin 0 16;
            kex_algs;
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
  | MSG_NEWKEYS ->
    ok Msg_newkeys
  | MSG_KEX_0 | MSG_KEX_1 | MSG_KEX_2 | MSG_KEX_3 | MSG_KEX_4 ->
    ok (Msg_kex (msgid, buf))
  | MSG_USERAUTH_REQUEST ->
    get_string buf >>= fun (user, buf) ->
    get_string buf >>= fun (service, buf) ->
    get_string buf >>= fun (auth_method, buf) ->
    (match auth_method with
     | "publickey" ->
       get_bool buf >>= fun (has_sig, buf) ->
       get_string buf >>= fun (key_alg, buf) ->
       get_pubkey key_alg buf >>= fun (pubkey, buf) ->
       if has_sig then
         get_signature buf >>= fun key_sig ->
         ok (Pubkey (pubkey, Some key_sig), buf)
       else
         ok (Pubkey (pubkey, None), buf)
     | "password" ->
       get_bool buf >>= fun (has_old, buf) ->
       if has_old then
         get_string buf >>= fun (oldpassword, buf) ->
         get_string buf >>= fun (password, buf) ->
         ok (Password (password, Some oldpassword), buf)
       else
         get_string buf >>= fun (password, buf) ->
         ok (Password (password, None), buf)
     | "hostbased" ->
       get_string buf >>= fun (key_alg, buf) ->
       get_cstring buf >>= fun (key_blob, buf) ->
       get_string buf >>= fun (hostname, buf) ->
       get_string buf >>= fun (hostuser, buf) ->
       get_cstring buf >>= fun (hostsig, buf) ->
       ok (Hostbased (key_alg, key_blob, hostname, hostuser, hostsig), buf)
     | "none" -> ok (Authnone, buf)
     | _ -> error ("Unknown method " ^ auth_method))
    >>= fun (auth_method, _) ->
    ok (Msg_userauth_request (user, service, auth_method))
  | MSG_USERAUTH_FAILURE ->
    get_nl buf >>= fun (nl, buf) ->
    get_bool buf >>= fun (psucc, _) ->
    ok (Msg_userauth_failure (nl, psucc))
  | MSG_USERAUTH_SUCCESS -> ok Msg_userauth_success
  | MSG_USERAUTH_PK_OK ->
    get_string buf >>= fun (key_alg, buf) ->
    get_pubkey key_alg buf >>= fun (pubkey, _) ->
    ok (Msg_userauth_pk_ok pubkey)
  | MSG_USERAUTH_BANNER ->
    get_string buf >>= fun (s1, buf) ->
    get_string buf >>= fun (s2, _) ->
    ok (Msg_userauth_banner (s1, s2))
  | MSG_GLOBAL_REQUEST ->
    get_string buf >>= fun (request, buf) ->
    get_bool buf >>= fun (want_reply, buf) ->
    (match request with
     | "tcpip-forward" ->
       get_string buf >>= fun (address, buf) ->
       get_uint32 buf >>= fun (port, buf) ->
       ok (Tcpip_forward (address, port), buf)
     | "cancel-tcpip-forward" ->
       get_string buf >>= fun (address, buf) ->
       get_uint32 buf >>= fun (port, buf) ->
       ok (Cancel_tcpip_forward (address, port), buf)
     | _ ->
       get_string buf >>= fun (data, buf) ->
       ok (Unknown_request data, buf))
    >>= fun (global_request, _) ->
    ok (Msg_global_request (request, want_reply, global_request))
  | MSG_REQUEST_SUCCESS ->
    let req_data = if Cstruct.length buf > 0 then Some buf else None in
    ok (Msg_request_success req_data)
  | MSG_REQUEST_FAILURE -> ok Msg_request_failure
  | MSG_CHANNEL_OPEN ->
    get_string buf >>= fun (request, buf) ->
    get_uint32 buf >>= fun (send_channel, buf) ->
    get_uint32 buf >>= fun (init_win, buf) ->
    get_uint32 buf >>= fun (max_pkt, buf) ->
    (match request with
     | "session" ->
       ok (Msg_channel_open
             (send_channel, init_win, max_pkt, Session))
     | "x11" ->
       get_string buf >>= fun (address, buf) ->
       get_uint32 buf >>= fun (port, _) ->
       ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              (X11 (address, port))))
     | "forwarded-tcpip" ->
       get_string buf >>= fun (con_address, buf) ->
       get_uint32 buf >>= fun (con_port, buf) ->
       get_string buf >>= fun (origin_address, buf) ->
       get_uint32 buf >>= fun (origin_port, _) ->
       ok (Msg_channel_open
             (send_channel, init_win, max_pkt,
              Forwarded_tcpip (con_address, con_port, origin_address,
                               origin_port)))
     | _ -> error ("Unknown channel open " ^ request))
  | MSG_CHANNEL_OPEN_CONFIRMATION ->
    get_uint32 buf >>= fun (recp_channel, buf) ->
    get_uint32 buf >>= fun (send_channel, buf) ->
    get_uint32 buf >>= fun (init_win, buf) ->
    get_uint32 buf >>= fun (max_pkt, buf) ->
    (*
     * The protocol does not tell us which channel type this is, so we can't
     * give the caller a good type for channel open and must return Raw_data.
     * We must provide the caller a function to make the conversion.
     *)
    ok (Msg_channel_open_confirmation
          (recp_channel, send_channel,
           init_win, max_pkt,
           buf))
  | MSG_CHANNEL_OPEN_FAILURE ->
    get_uint32 buf >>= fun (recp_channel, buf) ->
    get_uint32 buf >>= fun (reason, buf) ->
    get_string buf >>= fun (desc, buf) ->
    get_string buf >>= fun (lang, _) ->
    ok (Msg_channel_open_failure (recp_channel, reason, desc, lang))
  | MSG_CHANNEL_WINDOW_ADJUST ->
    get_uint32 buf >>= fun (channel, buf) ->
    get_uint32 buf >>= fun (n, _) ->
    ok (Msg_channel_window_adjust (channel, n))
  | MSG_CHANNEL_DATA ->
    get_uint32 buf >>= fun (channel, buf) ->
    get_cstring buf >>= fun (data, _) ->
    ok (Msg_channel_data (channel, data))
  | MSG_CHANNEL_EXTENDED_DATA ->
    get_uint32 buf >>= fun (channel, buf) ->
    get_uint32 buf >>= fun (data_type, buf) ->
    get_cstring buf >>= fun (data, _) ->
    ok (Msg_channel_extended_data (channel, data_type, data))
  | MSG_CHANNEL_EOF ->
    get_uint32 buf >>= fun (channel, _) ->
    ok (Msg_channel_eof channel)
  | MSG_CHANNEL_CLOSE ->
    get_uint32 buf >>= fun (channel, _) ->
    ok (Msg_channel_close channel)
  | MSG_CHANNEL_REQUEST ->
    get_uint32 buf >>= fun (channel, buf) ->
    get_string buf >>= fun (request, buf) ->
    get_bool buf >>= fun (want_reply, buf) ->
    (match request with
     | "pty-req" ->
       get_string buf >>= fun (term_env, buf) ->
       get_uint32 buf >>= fun (width_char, buf) ->
       get_uint32 buf >>= fun (height_row, buf) ->
       get_uint32 buf >>= fun (width_px, buf) ->
       get_uint32 buf >>= fun (height_px, buf) ->
       get_string buf >>= fun (term_modes, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Pty_req (term_env, width_char, height_row,
                                         width_px, height_px, term_modes)))
     | "x11-req" ->
       get_bool buf >>= fun (single_con, buf) ->
       get_string buf >>= fun (x11_auth_proto, buf) ->
       get_string buf >>= fun (x11_auth_cookie, buf) ->
       get_uint32 buf >>= fun (x11_screen_nr, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                X11_req (single_con, x11_auth_proto,
                                         x11_auth_cookie, x11_screen_nr)))
     | "env" ->
       get_string buf >>= fun (name, buf) ->
       get_string buf >>= fun (value, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Env (name, value)))
     | "exec" ->
       get_string buf >>= fun (command, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Exec (command)))
     | "shell" -> ok (Msg_channel_request (channel, want_reply, Shell))
     | "subsystem" ->
       get_string buf >>= fun (name, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Subsystem (name)))
     | "window-change" ->
       get_uint32 buf >>= fun (width_char, buf) ->
       get_uint32 buf >>= fun (height_row, buf) ->
       get_uint32 buf >>= fun (width_px, buf) ->
       get_uint32 buf >>= fun (height_px, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Window_change (width_char, height_row,
                                               width_px, height_px)))
     | "xon-xoff" ->
       get_bool buf >>= fun (client_can_do, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Xon_xoff (client_can_do)))
     | "signal" ->
       get_string buf >>= fun (name, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Signal (name)))
     | "exit-status" ->
       get_uint32 buf >>= fun (status, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Exit_status (status)))
     | "exit-signal" ->
       get_string buf >>= fun (name, buf) ->
       get_bool buf >>= fun (core_dumped, buf) ->
       get_string buf >>= fun (message, buf) ->
       get_string buf >>= fun (lang, _) ->
       ok (Msg_channel_request (channel, want_reply,
                                Exit_signal (name, core_dumped, message, lang)))
     | _ -> error ("Unknown channel request " ^ request))
  | MSG_CHANNEL_SUCCESS ->
    get_uint32 buf >>= fun (channel, _) ->
    ok (Msg_channel_success channel)
  | MSG_CHANNEL_FAILURE ->
    get_uint32 buf >>= fun (channel, _) ->
    ok (Msg_channel_failure channel)
  | MSG_VERSION ->
    error "got MSG_VERSION"

let dh_kexdh_of_kex id buf =
  (* for common DH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    get_mpint buf >>= fun (e, _) ->
    ok (Msg_kexdh_init e)
  | MSG_KEX_1 ->
    get_pubkey_any buf >>= fun (k_s, buf) ->
    get_mpint buf >>= fun (f, buf) ->
    get_signature buf >>= fun key_sig ->
    ok (Msg_kexdh_reply (k_s, f, key_sig))
  | _ -> error "unsupported KEX message"

let dh_kexecdh_of_kex id buf =
  (* for ECDH KEX *)
  let open Ssh in
  match id with
  | MSG_KEX_0 ->
    get_mpint ~signed:false buf >>= fun (e, _) ->
    ok (Msg_kexecdh_init e)
  | MSG_KEX_1 ->
    get_pubkey_any buf >>= fun (k_s, buf) ->
    get_mpint ~signed:false buf >>= fun (f, buf) ->
    get_signature buf >>= fun key_sig ->
    ok (Msg_kexecdh_reply (k_s, f, key_sig))
  | _ -> error "unsupported KEX message"

let dh_kexdh_gex_of_kex id buf =
  (* for RFC 4419 GEX *)
  let open Ssh in
  match id with
  | MSG_KEX_4 ->
    get_uint32 buf >>= fun (min, buf) ->
    get_uint32 buf >>= fun (n, buf) ->
    get_uint32 buf >>= fun (max, _) ->
    ok (Msg_kexdh_gex_request (min, n, max))
  | MSG_KEX_1 ->
    get_mpint buf >>= fun (p, buf) ->
    get_mpint buf >>= fun (g, _) ->
    ok (Msg_kexdh_gex_group (p, g))
  | MSG_KEX_2 ->
    get_mpint buf >>= fun (e, _) ->
    ok (Msg_kexdh_gex_init e)
  | MSG_KEX_3 ->
    get_pubkey_any buf >>= fun (k_s, buf) ->
    get_mpint buf >>= fun (f, buf) ->
    get_signature buf >>= fun key_sig ->
    ok (Msg_kexdh_gex_reply (k_s, f, key_sig))
  | _ -> error "unsupported KEX message"

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
     | Pubkey (pubkey, signature) ->
       let buf =
         let alg = match signature with
           | Some (alg, _) -> alg
           | None -> match pubkey with
             | Hostkey.Rsa_pub _ -> Hostkey.Rsa_sha1
             | Hostkey.Ed25519_pub _ -> Hostkey.Ed25519
         in
         put_string "publickey" buf |>
         put_bool (is_some signature) |>
         put_string (Hostkey.alg_to_string alg) |>
         put_pubkey pubkey
       in
       (match signature with
        | None -> buf
        | Some signature -> put_signature signature buf)
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
     | Hostbased (key_alg, key_blob, hostname, hostuser, hostsig) ->
       put_string "hostbased" buf |>
       put_string key_alg |>
       put_cstring key_blob |>
       put_string hostname |>
       put_string hostuser |>
       put_cstring hostsig
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
    put_id MSG_USERAUTH_PK_OK buf |>
    put_string (Hostkey.sshname pubkey) |>
    put_pubkey pubkey
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

(* XXX Maybe move this to Packet *)
let get_payload buf =
  let open Ssh in
  guard (Cstruct.length buf >= 5) "Buf too short" >>= fun () ->
  let pkt_len = get_pkt_hdr_pkt_len buf |> Int32.to_int in
  let pad_len = get_pkt_hdr_pad_len buf in
  guard (pkt_len > 0 && pkt_len < max_pkt_len) "Bogus pkt len" >>= fun () ->
  guard (pad_len < pkt_len) "Bogus pad len" >>= fun () ->
  guard (Cstruct.length buf = pkt_len + 4) "Bogus buf len" >>= fun () ->
  let payload_len = pkt_len - pad_len - 1 in
  guard (payload_len > 0) "Bogus payload_len" >>= fun () ->
  let payload = Cstruct.sub buf 5 payload_len in
  ok payload

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
      ok None
    else if line_len < 9 then
      error "Version line is too short"
    else
      (* Strip the comments *)
      let version_line =
        try
          String.sub line 0 (String.index line ' ')
        with Not_found -> line
      in
      let tokens = String.split_on_char '-' version_line in
      if List.length tokens < 3 then
        error ("Can't parse version line: " ^ version_line)
      else
        let version = List.nth tokens 1 in
        if String.equal version "2.0" then
          ok (Some line)
        else
          error ("Bad version " ^ version)
  in
  (* Scan all lines until an error or SSH version is found *)
  let rec scan buf =
    match fetchline buf with
    | None -> if Cstruct.length buf > 1024 then
        error "Buffer is too big"
      else
        ok (None, buf)
    | Some (line, buf) ->
      processline line >>= function
      | Some peer_version -> ok (Some peer_version, buf)
      | None ->
        if Cstruct.length buf > 2 then
          scan buf
        else
          ok (None, buf)
  in
  scan buf

