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

let get_message_id buf =
  trap_error (fun () ->
      let id = (Cstruct.get_uint8 buf 0) in
      match Ssh.int_to_message_id id with
      | None -> invalid_arg (sprintf "Unknown message id %d" id)
      | Some msgid -> msgid, (Cstruct.shift buf 1)) ()

let get_string buf =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      Ssh.guard_sshlen_exn len;
      (Cstruct.copy buf 4 len), Cstruct.shift buf (len + 4)) ()

let get_cstring buf =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      Ssh.guard_sshlen_exn len;
      (Cstruct.set_len (Cstruct.shift buf 4) len,
       Cstruct.shift buf (len + 4))) ()

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
          Cstruct.shift buf (len + 4)) ()

let get_key buf =
  get_string buf >>= fun (key, buf) ->
  guard (key = "ssh-rsa") "Bad key type" >>= fun () ->
  get_mpint buf >>= fun (e, buf) ->
  get_mpint buf >>= fun (n, buf) ->
  ok (Nocrypto.Rsa.{e; n}, buf)

let get_uint32 buf =
  trap_error (fun () ->
      Cstruct.BE.get_uint32 buf 0, Cstruct.shift buf 4) ()

let get_bool buf =
  trap_error (fun () ->
      (Cstruct.get_uint8 buf 0) <> 0, Cstruct.shift buf 1) ()

let get_nl buf =
  get_string buf >>= fun (s, buf) ->
  ok ((Str.split (Str.regexp ",") s), buf)

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
    get_cstring buf >>= fun (blob, buf) ->
    get_key blob >>= fun (k_s, blob) ->
    get_mpint buf >>= fun (f, buf) ->
    get_cstring buf >>= fun (sigblob, buf) ->
    get_string sigblob >>= fun (ktype, sigblob) ->
    guard (ktype = "ssh-rsa") "Unknown signature key type" >>= fun () ->
    get_cstring sigblob >>= fun (hsig, sigblob) ->
    ok (Ssh_msg_kexdh_reply (k_s, f, hsig))
  | SSH_MSG_USERAUTH_REQUEST ->
    get_string buf >>= fun (user, buf) ->
    get_string buf >>= fun (service, buf) ->
    get_string buf >>= fun (auth_method, buf) ->
    (match auth_method with
     | "publickey" ->
       get_bool buf >>= fun (b, buf) ->
       get_string buf >>= fun (key_alg, buf) ->
       get_cstring buf >>= fun (key_blob, buf) ->
       ok (Publickey (b, key_alg, key_blob), buf)
     | "password" ->
       get_bool buf >>= fun (b, buf) ->
       get_string buf >>= fun (password, buf) ->
       ok (Password (b, password), buf)
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

