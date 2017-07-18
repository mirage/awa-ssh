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
      (Cstruct.set_len (Cstruct.shift buf 4) len,
       Cstruct.shift buf (len + 4)))

let put_cstring s t =
  let len = Cstruct.len s in
  let t = put_uint32 (Int32.of_int len) t in
  let t = Dbuf.guard_space len t in
  Cstruct.blit s 0 t.Dbuf.cbuf t.Dbuf.coff len;
  Dbuf.shift len t

let put_raw buf t =
  let len = Cstruct.len buf in
  let t = Dbuf.guard_space len t in
  Cstruct.blit buf 0 t.Dbuf.cbuf t.Dbuf.coff len;
  Dbuf.shift len t

let put_random len t =
  put_raw (Nocrypto.Rng.generate len) t

let get_mpint buf =
  trap_error (fun () ->
      match ((Cstruct.BE.get_uint32 buf 0) |> Int32.to_int) with
      | 0 -> Nocrypto.Numeric.Z.zero, Cstruct.shift buf 4
      | len ->
        Ssh.guard_sshlen_exn len;
        let mpbuf = Cstruct.sub buf 4 len in
        let msb = Cstruct.get_uint8 mpbuf 0 in
        if (msb land 0x80) <> 0 then
          invalid_arg "Negative mpint"
        else
          (* of_cstruct_be strips leading zeros for us *)
          Nocrypto.Numeric.Z.of_cstruct_be mpbuf,
          Cstruct.shift buf (len + 4))

let put_mpint mpint t =
  let mpbuf = Nocrypto.Numeric.Z.to_cstruct_be mpint in
  let mplen = Cstruct.len mpbuf in
  let t =
    if mplen > 0 &&
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
  ok ((Str.split (Str.regexp ",") s), buf)

let put_nl nl t =
  put_string (String.concat "," nl) t

let blob_of_pubkey = function
  | Hostkey.Rsa_pub rsa ->
    let open Nocrypto.Rsa in
    put_string "ssh-rsa" (Dbuf.create ()) |>
    put_mpint rsa.e |>
    put_mpint rsa.n |>
    Dbuf.to_cstruct
  | Hostkey.Unknown -> invalid_arg "Can't make blob of unknown key."

(* XXX need to express unknown better *)
let pubkey_of_blob blob =
  get_string blob >>= fun (key_alg, blob) ->
  match key_alg with
  | "ssh-rsa" ->
    get_mpint blob >>= fun (e, blob) ->
    get_mpint blob >>= fun (n, _) ->
    let pub = Nocrypto.Rsa.{e; n} in
    ok (Hostkey.Rsa_pub pub)
  | key_alg -> ok Hostkey.Unknown

(* Extracts the blob and converts to a pubkey *)
let get_pubkey buf =
  get_cstring buf >>= fun (blob, buf) ->
  pubkey_of_blob blob >>= fun pubkey ->
  ok (pubkey, buf)

let put_pubkey pubkey t =
  put_cstring (blob_of_pubkey pubkey) t

let pubkey_of_openssh buf =
  let s = Cstruct.to_string buf in
  let tokens = Str.split (Str.regexp " ") s in
  guard (List.length tokens = 3) "Invalid format" >>= fun () ->
  let key_type = List.nth tokens 0 in
  let key_buf = Cstruct.of_string (List.nth tokens 1) in
  (* let key_comment = List.nth tokens 2 in *)
  guard_some (Nocrypto.Base64.decode key_buf) "Can't decode key blob"
  >>= fun blob ->
  pubkey_of_blob blob >>= fun key ->
  guard (key <> Hostkey.Unknown) "Unknown hostkey" >>= fun () ->
  guard (Hostkey.sshname key = key_type) "Key type mismatch" >>= fun () ->
  ok key

let openssh_of_pubkey key =
  let key_buf = Nocrypto.Base64.encode (blob_of_pubkey key) in
  Cstruct.concat
    [ Cstruct.of_string (Hostkey.sshname key ^ " ");
      key_buf;
      Cstruct.of_string " awa-ssh\n" ]

let privkey_of_pem buf =
  trap_error (fun () ->
      match X509.Encoding.Pem.Private_key.of_pem_cstruct1 buf with
        X509.Encoding.Pem.(`RSA key) -> Hostkey.Rsa_priv key)

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
  put_message_id Ssh.SSH_MSG_KEXINIT (Dbuf.create ()) |>
  put_kexinit kex |> Dbuf.to_cstruct

let get_signature buf =
  get_cstring buf >>= fun (blob, buf) ->
  get_string blob >>= fun (key_alg, blob) ->
  get_cstring blob >>= fun (key_sig, _) ->
  ok (key_alg, key_sig)

let put_signature pubkey signature t =
  let blob =
    put_string (Hostkey.sshname pubkey) (Dbuf.create ()) |>
    put_cstring signature |>
    Dbuf.to_cstruct
  in
  put_cstring blob t

let get_message buf =
  let open Ssh in
  let msgbuf = buf in
  get_message_id buf >>= fun (msgid, buf) ->
  let unimplemented () =
    (* XXX should send SSH_MSG_UNIMPLEMENTED *)
    error (sprintf "Message %d unimplemented" (message_id_to_int msgid))
  in
  match msgid with
  | SSH_MSG_DISCONNECT ->
    get_uint32 buf >>= fun (code, buf) ->
    get_string buf >>= fun (desc, buf) ->
    get_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_disconnect (int_to_disconnect_code code, desc, lang))
  | SSH_MSG_IGNORE ->
    get_string buf >>= fun (x, buf) ->
    ok (Ssh_msg_ignore x)
  | SSH_MSG_UNIMPLEMENTED ->
    get_uint32 buf >>= fun (x, buf) ->
    ok (Ssh_msg_unimplemented x)
  | SSH_MSG_DEBUG ->
    get_bool buf >>= fun (always_display, buf) ->
    get_string buf >>= fun (message, buf) ->
    get_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_debug (always_display, message, lang))
  | SSH_MSG_SERVICE_REQUEST ->
    get_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_request x)
  | SSH_MSG_SERVICE_ACCEPT ->
    get_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_accept x)
  | SSH_MSG_KEXINIT ->
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
    get_bool buf >>= fun (first_kex_packet_follows, buf) ->
    ok (Ssh_msg_kexinit
          { cookie = Cstruct.set_len cookiebegin 16;
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
            input_buf = Some msgbuf })
  | SSH_MSG_NEWKEYS -> ok Ssh_msg_newkeys
  | SSH_MSG_KEXDH_INIT -> get_mpint buf >>= fun (e, buf) ->
    ok (Ssh_msg_kexdh_init e)
  | SSH_MSG_KEXDH_REPLY ->
    get_pubkey buf >>= fun (k_s, buf) ->
    get_mpint buf >>= fun (f, buf) ->
    get_signature buf >>= fun (key_alg, key_sig) ->
    guard (key_alg = Hostkey.sshname k_s)
      "Signature type doesn't match key type"
    >>= fun () ->
    ok (Ssh_msg_kexdh_reply (k_s, f, key_sig))
  | SSH_MSG_USERAUTH_REQUEST ->
    get_string buf >>= fun (user, buf) ->
    get_string buf >>= fun (service, buf) ->
    get_string buf >>= fun (auth_method, buf) ->
    (match auth_method with
     | "publickey" ->
       get_bool buf >>= fun (has_sig, buf) ->
       get_string buf >>= fun (key_alg, buf) ->
       get_pubkey buf >>= fun (pubkey, buf) ->
       if has_sig then
         get_signature buf >>= fun (key_alg, key_sig) ->
         ok (Pubkey (key_alg, pubkey, Some key_sig), buf)
       else
         ok (Pubkey (key_alg, pubkey, None), buf)
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
     | auth_metod -> error ("Unknown method " ^ auth_method))
    >>= fun (auth_method, buf) ->
    ok (Ssh_msg_userauth_request (user, service, auth_method))
  | SSH_MSG_USERAUTH_FAILURE ->
    get_nl buf >>= fun (nl, buf) ->
    get_bool buf >>= fun (psucc, buf) ->
    ok (Ssh_msg_userauth_failure (nl, psucc))
  | SSH_MSG_USERAUTH_SUCCESS -> ok Ssh_msg_userauth_success
  | SSH_MSG_USERAUTH_PK_OK ->
    get_string buf >>= fun (key_alg, buf) ->
    get_pubkey buf >>= fun (pubkey, buf) ->
    ok (Ssh_msg_userauth_pk_ok pubkey)
  | SSH_MSG_USERAUTH_BANNER ->
    get_string buf >>= fun (s1, buf) ->
    get_string buf >>= fun (s2, buf) ->
    ok (Ssh_msg_userauth_banner (s1, s2))
  | SSH_MSG_GLOBAL_REQUEST -> unimplemented ()
  | SSH_MSG_REQUEST_SUCCESS -> unimplemented ()
  | SSH_MSG_REQUEST_FAILURE -> ok Ssh_msg_request_failure
  | SSH_MSG_CHANNEL_OPEN -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_FAILURE -> ok Ssh_msg_channel_open_failure
  | SSH_MSG_CHANNEL_WINDOW_ADJUST ->
    get_uint32 buf >>= fun (channel, buf) ->
    get_uint32 buf >>= fun (n, buf) ->
    ok (Ssh_msg_channel_window_adjust (channel, n))
  | SSH_MSG_CHANNEL_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EXTENDED_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EOF ->
    get_uint32 buf >>= fun (channel, buf) ->
    ok (Ssh_msg_channel_eof channel)
  | SSH_MSG_CHANNEL_CLOSE ->
    get_uint32 buf >>= fun (channel, buf) ->
    ok (Ssh_msg_channel_close channel)
  | SSH_MSG_CHANNEL_REQUEST -> unimplemented ()
  | SSH_MSG_CHANNEL_SUCCESS ->
    get_uint32 buf >>= fun (channel, buf) ->
    ok (Ssh_msg_channel_success channel)
  | SSH_MSG_CHANNEL_FAILURE ->
    get_uint32 buf >>= fun (channel, buf) ->
    ok (Ssh_msg_channel_failure channel)
  | SSH_MSG_VERSION ->
    error "got SSH_MSG_VERSION"

let put_message msg buf =
  let open Ssh in
  let unimplemented () = failwith "implement me" in
  let guard p e = if not p then invalid_arg e in
  let put_id = put_message_id in (* save some columns *)
  match msg with
    | Ssh_msg_disconnect (code, desc, lang) ->
      put_id SSH_MSG_DISCONNECT buf |>
      put_uint32 (disconnect_code_to_int code) |>
      put_string desc |>
      put_string lang
    | Ssh_msg_ignore s ->
      put_id SSH_MSG_IGNORE buf |>
      put_string s
    | Ssh_msg_unimplemented x ->
      put_id SSH_MSG_UNIMPLEMENTED buf |>
      put_uint32 x
    | Ssh_msg_debug (always_display, message, lang) ->
      put_id SSH_MSG_DEBUG buf |>
      put_bool always_display |>
      put_string message |>
      put_string lang
    | Ssh_msg_service_request s ->
      put_id SSH_MSG_SERVICE_REQUEST buf |>
      put_string s
    | Ssh_msg_service_accept s ->
      put_id SSH_MSG_SERVICE_ACCEPT buf |>
      put_string s
    | Ssh_msg_kexinit kex ->
      put_id SSH_MSG_KEXINIT buf |>
      put_kexinit kex
    | Ssh_msg_newkeys ->
      put_id SSH_MSG_NEWKEYS buf
    | Ssh_msg_kexdh_init e ->
      put_id SSH_MSG_KEXDH_INIT buf |>
      put_mpint e
    | Ssh_msg_kexdh_reply (k_s, f, signature) ->
      put_id SSH_MSG_KEXDH_REPLY buf |>
      put_pubkey k_s |>
      put_mpint f |>
      put_signature k_s signature
    | Ssh_msg_userauth_request (user, service, auth_method) ->
      let buf = put_id SSH_MSG_USERAUTH_REQUEST buf |>
                put_string user |>
                put_string service
      in
      (match auth_method with
       | Pubkey (key_alg, pubkey, signature) ->
         let buf = put_string "publickey" buf |>
                   put_bool (is_some signature) |>
                   put_string key_alg |>
                   put_pubkey pubkey
         in
         (match signature with
          | None -> buf
          | Some signature -> put_signature pubkey signature buf)
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
    | Ssh_msg_userauth_failure (nl, psucc) ->
      put_id SSH_MSG_USERAUTH_FAILURE buf |>
      put_nl nl |>
      put_bool psucc
    | Ssh_msg_userauth_success ->
      put_id SSH_MSG_USERAUTH_SUCCESS buf
    | Ssh_msg_userauth_banner (message, lang) ->
      put_id SSH_MSG_USERAUTH_BANNER buf |>
      put_string message |>
      put_string lang
    | Ssh_msg_userauth_pk_ok pubkey ->
      guard (pubkey <> Hostkey.Unknown) "Unknown key";
      put_id SSH_MSG_USERAUTH_PK_OK buf |>
      put_string (Hostkey.sshname pubkey) |>
      put_pubkey pubkey
    | Ssh_msg_global_request -> unimplemented ()
    | Ssh_msg_request_success -> unimplemented ()
    | Ssh_msg_request_failure ->
      put_id SSH_MSG_REQUEST_FAILURE buf
    | Ssh_msg_channel_open -> unimplemented ()
    | Ssh_msg_channel_open_confirmation -> unimplemented ()
    | Ssh_msg_channel_open_failure ->
      put_id SSH_MSG_CHANNEL_OPEN_FAILURE buf
    | Ssh_msg_channel_window_adjust (channel, n) ->
      put_id SSH_MSG_CHANNEL_WINDOW_ADJUST buf |>
      put_uint32 channel |>
      put_uint32 n
    | Ssh_msg_channel_data -> unimplemented ()
    | Ssh_msg_channel_extended_data -> unimplemented ()
    | Ssh_msg_channel_eof channel ->
      put_id SSH_MSG_CHANNEL_EOF buf |>
      put_uint32 channel
    | Ssh_msg_channel_close channel ->
      put_id SSH_MSG_CHANNEL_CLOSE buf |>
      put_uint32 channel
    | Ssh_msg_channel_request -> unimplemented ()
    | Ssh_msg_channel_success channel ->
      put_id SSH_MSG_CHANNEL_SUCCESS buf |>
      put_uint32 channel
    | Ssh_msg_channel_failure channel ->
      put_id SSH_MSG_CHANNEL_FAILURE buf |>
      put_uint32 channel
    | Ssh_msg_version version ->  (* Mocked up version message *)
      put_raw (Cstruct.of_string (version ^ "\r\n")) buf

(* Useful for testing *)
let buf_of_message m =
  put_message m (Dbuf.create ()) |> Dbuf.to_cstruct

(* XXX Maybe move this to Packet *)
let get_payload buf =
  let open Ssh in
  guard ((Cstruct.len buf) >= 5) "Buf too short"
  >>= fun () ->
  let pkt_len = get_pkt_hdr_pkt_len buf |> Int32.to_int in
  let pad_len = get_pkt_hdr_pad_len buf in
  guard (pkt_len > 0 && pkt_len < max_pkt_len) "Bogus pkt len"
  >>= fun () ->
  guard (pad_len < pkt_len) "Bogus pad len"
  >>= fun () ->
  guard ((Cstruct.len buf) = (pkt_len + 4)) "Bogus buf len"
  >>= fun () ->
  let payload_len = pkt_len - pad_len - 1 in
  guard (payload_len > 0) "Bogus payload_len"
  >>= fun () ->
  let payload = Cstruct.shift buf 5 in
  let payload = Cstruct.set_len payload payload_len in
  ok payload

let get_version buf =
  (* Fetches next line, returns maybe a string and the remainder of buf *)
  let fetchline buf =
    if (Cstruct.len buf) < 2 then
      None
    else
      let s = Cstruct.to_string buf in
      let n = try String.index s '\n' with Not_found -> 0 in
      if n = 0 || ((String.get s (pred n)) <> '\r')  then
        None
      else
        let line = String.sub s 0 (pred n) in
        let line_len = String.length line in
        Some (line, Cstruct.shift buf (line_len + 2))
  in
  (* Extract SSH version from line *)
  let processline line =
    let line_len = String.length line in
    if line_len < 4 || String.sub line 0 4 <> "SSH-" then
      ok None
    else if line_len < 9 then
      error "Version line is too short"
    else
      (* Strip the comments *)
      let version_line = try
          String.sub line 0 (String.index line ' ')
        with Not_found -> line
      in
      let tokens = Str.split_delim (Str.regexp "-") version_line in
      if List.length tokens <> 3 then
        error "Can't parse version line"
      else
        let version = List.nth tokens 1 in
        if version <> "2.0" then
          error ("Bad version " ^ version)
        else
          ok (Some version_line)
  in
  (* Scan all lines until an error or SSH version is found *)
  let rec scan buf =
    match fetchline buf with
    | None -> if (Cstruct.len buf) > 1024 then
        error "Buffer is too big"
      else
        ok (None, buf)
    | Some (line, buf) ->
      processline line >>= function
      | Some peer_version -> ok (Some peer_version, buf)
      | None ->
        if (Cstruct.len buf) > 2 then
          scan buf
        else
          ok (None, buf)
  in
  scan buf

