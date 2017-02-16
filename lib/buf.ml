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

type t = {
  tlen : int;
  coff : int;
  cbuf : Cstruct.t;
}

let chunk_size = 256

let create ?(len=chunk_size) () =
  { tlen = len; coff = 0; cbuf = Cstruct.create len }

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

let add_uint8 b t =
  let t = guard_space 1 t in
  Cstruct.set_uint8 t.cbuf t.coff b;
  shift 1 t

let add_bool b t =
  let x = if b then 1 else 0 in
  add_uint8 x t

let add_uint32 w t =
  let t = guard_space 4 t in
  Cstruct.BE.set_uint32 t.cbuf t.coff w;
  shift 4 t

let add_string s t =
  let len = String.length s in
  let t = add_uint32 (Int32.of_int len) t in
  let t = guard_space len t in
  Cstruct.blit_from_string s 0 t.cbuf t.coff len;
  shift len t

let add_cstring s t =
  let len = Cstruct.len s in
  let t = add_uint32 (Int32.of_int len) t in
  let t = guard_space len t in
  Cstruct.blit s 0 t.cbuf t.coff len;
  shift len t

let add_raw buf t =
  let len = Cstruct.len buf in
  let t = guard_space len t in
  Cstruct.blit buf 0 t.cbuf t.coff len;
  shift len t

let add_random len t =
  add_raw (Nocrypto.Rng.generate len) t

let add_nl nl t =
  add_string (String.concat "," nl) t

let add_mpint mpint t =
  let mpbuf = Nocrypto.Numeric.Z.to_cstruct_be mpint in
  let mplen = Cstruct.len mpbuf in
  let t =
    if mplen > 0 &&
       ((Cstruct.get_uint8 mpbuf 0) land 0x80) <> 0 then
      add_uint32 (Int32.of_int (succ mplen)) t |>
      add_uint8 0
    else
      add_uint32 (Int32.of_int mplen) t
  in
  add_raw mpbuf t

let add_key (rsa : Nocrypto.Rsa.pub) t =
  let open Nocrypto.Rsa in
  add_string "ssh-rsa" t |> add_mpint rsa.e |> add_mpint rsa.n

let add_kex_pkt kex t =
  let open Ssh in
  let nll = [ kex.kex_algorithms;
              kex.server_host_key_algorithms;
              kex.encryption_algorithms_ctos;
              kex.encryption_algorithms_stoc;
              kex.mac_algorithms_ctos;
              kex.mac_algorithms_stoc;
              kex.compression_algorithms_ctos;
              kex.compression_algorithms_stoc;
              kex.languages_ctos;
              kex.languages_stoc; ]
  in
  let buf =
    add_uint8 (message_id_to_int SSH_MSG_KEXDH_INIT) (create ()) |>
    add_raw kex.cookie
  in
  List.fold_left (fun buf nl -> add_nl nl buf) buf nll |>
  add_bool kex.first_kex_packet_follows |>
  add_uint32 Int32.zero

(* *** *)
open Ssh

let encode_key rsa =
  add_key rsa (create ()) |> to_cstruct

let encode_kex_pkt kex =
  add_kex_pkt kex (create ()) |> to_cstruct

let encode_message msg =
  let add_id id = add_uint8 (message_id_to_int id) (create ()) in
  let buf = match msg with
    | Ssh_msg_disconnect (code, desc, lang) ->
      add_id SSH_MSG_DISCONNECT |>
      add_uint32 code |>
      add_string desc |>
      add_string lang
    | Ssh_msg_ignore s ->
      add_id SSH_MSG_IGNORE |>
      add_string s
    | Ssh_msg_unimplemented x ->
      add_id SSH_MSG_UNIMPLEMENTED |>
      add_uint32 x
    | Ssh_msg_debug (always_display, message, lang) ->
      add_id SSH_MSG_DEBUG |>
      add_bool always_display |>
      add_string message |>
      add_string lang
    | Ssh_msg_service_request s ->
      add_id SSH_MSG_SERVICE_REQUEST |>
      add_string s
    | Ssh_msg_service_accept s ->
      add_id SSH_MSG_SERVICE_ACCEPT |>
      add_string s
    | Ssh_msg_kexinit kex ->
      add_id SSH_MSG_KEXINIT |>
      add_kex_pkt kex
    | Ssh_msg_newkeys ->
      add_id SSH_MSG_NEWKEYS
    | Ssh_msg_kexdh_reply (k_s, f, hsig) ->
      add_id SSH_MSG_KEXDH_REPLY |>
      add_key k_s |>
      add_mpint f |>
      add_cstring hsig
    | Ssh_msg_userauth_failure (nl, psucc) ->
      add_id SSH_MSG_USERAUTH_FAILURE |>
      add_nl nl |>
      add_bool psucc
    | Ssh_msg_userauth_success ->
      add_id SSH_MSG_USERAUTH_SUCCESS
    | Ssh_msg_userauth_banner (message, lang) ->
      add_id SSH_MSG_USERAUTH_BANNER |>
      add_string message |>
      add_string lang
    (* | SSH_MSG_GLOBAL_REQUEST -> unimplemented () *)
    (* | SSH_MSG_REQUEST_SUCCESS -> unimplemented () *)
    | Ssh_msg_request_failure ->
      add_id SSH_MSG_REQUEST_FAILURE
    (* | SSH_MSG_CHANNEL_OPEN -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> unimplemented () *)
    | Ssh_msg_channel_open_failure ->
      add_id SSH_MSG_CHANNEL_OPEN_FAILURE
    | Ssh_msg_channel_window_adjust (channel, n) ->
      add_id SSH_MSG_CHANNEL_WINDOW_ADJUST |>
      add_uint32 channel |>
      add_uint32 n
    (* | SSH_MSG_CHANNEL_DATA -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_EXTENDED_DATA -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_EOF -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_CLOSE -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_REQUEST -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_SUCCESS -> unimplemented () *)
    | Ssh_msg_channel_failure channel ->
      add_id SSH_MSG_CHANNEL_FAILURE |>
      add_uint32 channel
    | _ -> failwith "removeme"
  in
  to_cstruct buf
