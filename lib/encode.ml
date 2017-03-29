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

type t = {
  tlen : int;
  coff : int;
  cbuf : Cstruct.t;
}

let chunk_size = 1024

let create () =
  { tlen = chunk_size; coff = 0; cbuf = Cstruct.create chunk_size }

let to_cstruct t = Cstruct.set_len t.cbuf t.coff

let left t = t.tlen - t.coff

let used t = t.coff

let grow len t =
  let tlen = t.tlen + len in
  let cbuf = Cstruct.append t.cbuf (Cstruct.create len) in
  { t with tlen; cbuf }

let guard_space len t =
  if (left t) >= len then t else grow (max len chunk_size) t

let shift n t = { t with coff = t.coff + n }

let reserve n t = shift n t

let put_uint8 b t =
  let t = guard_space 1 t in
  Cstruct.set_uint8 t.cbuf t.coff b;
  shift 1 t

let put_bool b t =
  let x = if b then 1 else 0 in
  put_uint8 x t

let put_uint32 w t =
  let t = guard_space 4 t in
  Cstruct.BE.set_uint32 t.cbuf t.coff w;
  shift 4 t

let put_string s t =
  let len = String.length s in
  let t = put_uint32 (Int32.of_int len) t in
  let t = guard_space len t in
  Cstruct.blit_from_string s 0 t.cbuf t.coff len;
  shift len t

let put_cstring s t =
  let len = Cstruct.len s in
  let t = put_uint32 (Int32.of_int len) t in
  let t = guard_space len t in
  Cstruct.blit s 0 t.cbuf t.coff len;
  shift len t

let put_id id buf =
  put_uint8 (Ssh.message_id_to_int id) buf

let put_raw buf t =
  let len = Cstruct.len buf in
  let t = guard_space len t in
  Cstruct.blit buf 0 t.cbuf t.coff len;
  shift len t

let put_random len t =
  put_raw (Nocrypto.Rng.generate len) t

let put_nl nl t =
  put_string (String.concat "," nl) t

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
  put_id Ssh.SSH_MSG_KEXINIT (create ()) |>
  put_kexinit kex |> to_cstruct

let blob_of_key (rsa : Nocrypto.Rsa.pub) =
  let open Nocrypto.Rsa in
  put_string "ssh-rsa" (create ()) |>
  put_mpint rsa.e |>
  put_mpint rsa.n |>
  to_cstruct

let blob_of_key_signature signature =
  put_string "ssh-rsa" (create ()) |>
  put_cstring signature |>
  to_cstruct

let put_message msg buf =
  let open Ssh in
  let unimplemented () = failwith "implement me" in
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
    | Ssh_msg_kexdh_reply (k_s, f, hsig) ->
      put_id SSH_MSG_KEXDH_REPLY buf |>
      put_cstring (blob_of_key k_s) |>
      put_mpint f |>
      put_cstring (blob_of_key_signature hsig)
    | Ssh_msg_userauth_request (user, service, auth_method) ->
      let buf = put_id SSH_MSG_USERAUTH_REQUEST buf |>
                put_string user |>
                put_string service
      in
      (match auth_method with
       | Publickey (key_alg, key_blob, signature) ->
         let buf = put_string "publickey" buf |>
                   put_bool (is_some signature) |>
                   put_string key_alg |>
                   put_cstring key_blob
         in
         (match signature with
          | None -> buf
          | Some signature -> put_cstring signature buf)
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
    | Ssh_msg_userauth_pk_ok (key_alg, key_blob) ->
      put_id SSH_MSG_USERAUTH_PK_OK buf |>
      put_string key_alg |>
      put_cstring key_blob
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
