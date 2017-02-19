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

let put_key (rsa : Nocrypto.Rsa.pub) t =
  Nocrypto.Rsa.(put_string "ssh-rsa" t |>
                put_mpint rsa.e |>
                put_mpint rsa.n)

let put_kex kex t =
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
  List.fold_left (fun buf nl -> put_nl nl buf) (create ()) nll |>
  put_bool kex.first_kex_packet_follows |>
  put_uint32 Int32.zero

let buf_of_key rsa =
  put_key rsa (create ()) |> to_cstruct

let buf_of_kex_pkt kex =
  put_id Ssh.SSH_MSG_KEXINIT (create ()) |>
  put_kex kex |> to_cstruct

let put_message msg buf =
  let open Ssh in
  let unimplemented () = failwith "implement me" in
  match msg with
    | Ssh_msg_disconnect (code, desc, lang) ->
      put_id SSH_MSG_DISCONNECT buf |>
      put_uint32 code |>
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
      put_kex kex
    | Ssh_msg_newkeys ->
      put_id SSH_MSG_NEWKEYS buf
    | Ssh_msg_kexdh_init e ->
      put_id SSH_MSG_KEXDH_INIT buf |>
      put_mpint e
    | Ssh_msg_kexdh_reply (k_s, f, hsig) ->
      put_id SSH_MSG_KEXDH_REPLY buf |>
      put_key k_s |>
      put_mpint f |>
      put_cstring hsig
    | Ssh_msg_userauth_request _ -> unimplemented ()
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

let buf_of_pkt msg blen =
  let open Ssh in
  let blen = max 8 blen in
  (* Reserve sizeof_pkt_hdr so we can patch it when we know the size *)
  let buf = reserve sizeof_pkt_hdr (create ()) |>
            put_message msg
  in
  (* packet_length (sizeof_pkt_hdr) + padding_length + payload *)
  let len = used buf in
  (* calculate padding *)
  let padlen =
    let x = blen - (len mod blen) in
    if x < 4 then x + blen else x
  in
  assert (padlen < 256);
  let buf = to_cstruct @@ put_random padlen buf in
  Ssh.set_pkt_hdr_pkt_len buf (Int32.of_int (Cstruct.len buf));
  Ssh.set_pkt_hdr_pad_len buf padlen;
  buf

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let encrypt ~key ~iv buf =
  let open Nocrypto.Cipher_block in
  match key with
  | Cipher.Aes_ctr_key key ->
    let buf = AES.CTR.encrypt ~key ~ctr:iv buf in
    let blocks = (Cstruct.len buf) / AES.CTR.block_size |> Int64.of_int in
    let iv_len = Cstruct.len iv in
    let next_iv = Cstruct.create iv_len in
    Cstruct.blit iv 0 next_iv 0 iv_len;
    (* Update ctr with number of blocks *)
    Counter.add16 next_iv 0 blocks;
    buf, next_iv

  | Cipher.Aes_cbc_key key ->
    let buf = AES.CBC.encrypt ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    buf, next_iv
