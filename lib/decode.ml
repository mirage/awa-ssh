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

open Sexplib.Conv
open Rresult.R
open Util

let decode_message_id buf =
  trap_error (fun () ->
      let id = (Cstruct.get_uint8 buf 0) in
      match Ssh.int_to_message_id id with
      | None -> invalid_arg (Printf.sprintf "Unknown message id %d" id)
      | Some msgid -> msgid, (Cstruct.shift buf 1)) ()

let decode_string buf =
  (* XXX bad to_int conversion *)
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      (Cstruct.copy buf 4 len), Cstruct.shift buf (len + 4)) ()

let decode_cstring buf =
  (* XXX bad to_int conversion *)
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      (Cstruct.set_len (Cstruct.shift buf 4) len,
       Cstruct.shift buf (len + 4))) ()

let decode_mpint buf =
  trap_error (fun () ->
      match ((Cstruct.BE.get_uint32 buf 0) |> Int32.to_int) with
      | 0 -> Nocrypto.Numeric.Z.zero, Cstruct.shift buf 4
      | len ->
        let mpbuf = Cstruct.sub buf 4 len in
        let msb = Cstruct.get_uint8 mpbuf 0 in
        if (msb land 0x80) <> 0 then
          invalid_arg "Negative mpint"
        else
          (* of_cstruct_be strips leading zeros for us *)
          Nocrypto.Numeric.Z.of_cstruct_be mpbuf,
          Cstruct.shift buf (len + 4)) ()

let decode_key buf =
  decode_string buf >>= fun (key, buf) ->
  guard (key = "ssh-rsa") "Bad key type" >>= fun () ->
  decode_mpint buf >>= fun (e, buf) ->
  decode_mpint buf >>= fun (n, buf) ->
  ok (Nocrypto.Rsa.{e; n}, buf)

let decode_uint32 buf =
  trap_error (fun () ->
      Cstruct.BE.get_uint32 buf 0, Cstruct.shift buf 4) ()

let decode_bool buf =
  trap_error (fun () ->
      (Cstruct.get_uint8 buf 0) <> 0, Cstruct.shift buf 1) ()

let decode_nl buf =
  decode_string buf >>= fun (s, buf) ->
  ok ((Str.split (Str.regexp ",") s), buf)


let decode_kex_pkt buf =
  let open Ssh in
  let cookiebegin = buf in
  (* Jump over cookie *)
  safe_shift buf 16 >>= fun buf ->
  decode_nl buf >>= fun (kex_algorithms, buf) ->
  decode_nl buf >>= fun (server_host_key_algorithms, buf) ->
  decode_nl buf >>= fun (encryption_algorithms_ctos, buf) ->
  decode_nl buf >>= fun (encryption_algorithms_stoc, buf) ->
  decode_nl buf >>= fun (mac_algorithms_ctos, buf) ->
  decode_nl buf >>= fun (mac_algorithms_stoc, buf) ->
  decode_nl buf >>= fun (compression_algorithms_ctos, buf) ->
  decode_nl buf >>= fun (compression_algorithms_stoc, buf) ->
  decode_nl buf >>= fun (languages_ctos, buf) ->
  decode_nl buf >>= fun (languages_stoc, buf) ->
  decode_bool buf >>= fun (first_kex_packet_follows, buf) ->
  ok ({ cookie = Cstruct.set_len cookiebegin 16;
        kex_algorithms;
        server_host_key_algorithms;
        encryption_algorithms_ctos;
        encryption_algorithms_stoc;
        mac_algorithms_ctos;
        mac_algorithms_stoc;
        compression_algorithms_ctos;
        compression_algorithms_stoc;
        languages_ctos;
        languages_stoc;
        first_kex_packet_follows },
      buf)

let decode_message buf =
  let open Ssh in
  decode_message_id buf >>= fun (msgid, buf) ->
  let unimplemented () =
    error (Printf.sprintf "Message %d unimplemented" (message_id_to_int msgid))
  in
  match msgid with
  | SSH_MSG_DISCONNECT ->
    decode_uint32 buf >>= fun (code, buf) ->
    decode_string buf >>= fun (desc, buf) ->
    decode_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_disconnect (code, desc, lang))
  | SSH_MSG_IGNORE ->
    decode_string buf >>= fun (x, buf) ->
    ok (Ssh_msg_ignore x)
  | SSH_MSG_UNIMPLEMENTED ->
    decode_uint32 buf >>= fun (x, buf) ->
    ok (Ssh_msg_unimplemented x)
  | SSH_MSG_DEBUG ->
    decode_bool buf >>= fun (always_display, buf) ->
    decode_string buf >>= fun (message, buf) ->
    decode_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_debug (always_display, message, lang))
  | SSH_MSG_SERVICE_REQUEST ->
    decode_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_request x)
  | SSH_MSG_SERVICE_ACCEPT ->
    decode_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_accept x)
  | SSH_MSG_KEXINIT ->
    decode_kex_pkt buf >>= fun (kex, buf) -> ok (Ssh_msg_kexinit kex)
  | SSH_MSG_NEWKEYS -> ok Ssh_msg_newkeys
  | SSH_MSG_KEXDH_INIT -> decode_mpint buf >>= fun (e, buf) ->
    ok (Ssh_msg_kexdh_init e)
  | SSH_MSG_KEXDH_REPLY ->
    decode_key buf >>= fun (k_s, buf) ->
    decode_mpint buf >>= fun (f, buf) ->
    decode_cstring buf >>= fun (hsig, buf) ->
    ok (Ssh_msg_kexdh_reply (k_s, f, hsig))
  | SSH_MSG_USERAUTH_REQUEST -> unimplemented ()
  | SSH_MSG_USERAUTH_FAILURE ->
    decode_nl buf >>= fun (nl, buf) ->
    decode_bool buf >>= fun (psucc, buf) ->
    ok (Ssh_msg_userauth_failure (nl, psucc))
  | SSH_MSG_USERAUTH_SUCCESS -> unimplemented ()
  | SSH_MSG_USERAUTH_BANNER ->
    decode_string buf >>= fun (s1, buf) ->
    decode_string buf >>= fun (s2, buf) ->
    ok (Ssh_msg_userauth_banner (s1, s2))
  | SSH_MSG_GLOBAL_REQUEST -> unimplemented ()
  | SSH_MSG_REQUEST_SUCCESS -> unimplemented ()
  | SSH_MSG_REQUEST_FAILURE -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_FAILURE -> unimplemented ()
  | SSH_MSG_CHANNEL_WINDOW_ADJUST -> unimplemented ()
  | SSH_MSG_CHANNEL_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EXTENDED_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EOF -> unimplemented ()
  | SSH_MSG_CHANNEL_CLOSE -> unimplemented ()
  | SSH_MSG_CHANNEL_REQUEST -> unimplemented ()
  | SSH_MSG_CHANNEL_SUCCESS -> unimplemented ()
  | SSH_MSG_CHANNEL_FAILURE -> unimplemented ()

let scan_message buf =
  Ssh.scan_pkt buf >>= function
  | None -> ok None
  | Some (pkt, clen) -> decode_message pkt >>= fun msg -> ok (Some msg)
