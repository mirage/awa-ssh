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

[%%cstruct
type pkt_hdr = {
  pkt_len: uint32_t;
  pad_len: uint8_t;
} [@@big_endian]]

(** {2 Message ID.} *)

[%%cenum
type message_id =
  | SSH_MSG_DISCONNECT                [@id 1]
  | SSH_MSG_IGNORE                    [@id 2]
  | SSH_MSG_UNIMPLEMENTED             [@id 3]
  | SSH_MSG_DEBUG                     [@id 4]
  | SSH_MSG_SERVICE_REQUEST           [@id 5]
  | SSH_MSG_SERVICE_ACCEPT            [@id 6]
  | SSH_MSG_KEXINIT                   [@id 20]
  | SSH_MSG_NEWKEYS                   [@id 21]
  | SSH_MSG_USERAUTH_REQUEST          [@id 50]
  | SSH_MSG_USERAUTH_FAILURE          [@id 51]
  | SSH_MSG_USERAUTH_SUCCESS          [@id 52]
  | SSH_MSG_USERAUTH_BANNER           [@id 53]
  | SSH_MSG_GLOBAL_REQUEST            [@id 80]
  | SSH_MSG_REQUEST_SUCCESS           [@id 81]
  | SSH_MSG_REQUEST_FAILURE           [@id 82]
  | SSH_MSG_CHANNEL_OPEN              [@id 90]
  | SSH_MSG_CHANNEL_OPEN_CONFIRMATION [@id 91]
  | SSH_MSG_CHANNEL_OPEN_FAILURE      [@id 92]
  | SSH_MSG_CHANNEL_WINDOW_ADJUST     [@id 93]
  | SSH_MSG_CHANNEL_DATA              [@id 94]
  | SSH_MSG_CHANNEL_EXTENDED_DATA     [@id 95]
  | SSH_MSG_CHANNEL_EOF               [@id 96]
  | SSH_MSG_CHANNEL_CLOSE             [@id 97]
  | SSH_MSG_CHANNEL_REQUEST           [@id 98]
  | SSH_MSG_CHANNEL_SUCCESS           [@id 99]
  | SSH_MSG_CHANNEL_FAILURE           [@id 100]
[@@uint8_t][@@sexp]]

let message_id_of_buf buf =
  int_to_message_id (Cstruct.get_uint8 buf 0)

let buf_of_message_id m =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 (message_id_to_int m);
  buf

let string_of_buf buf off =
  let len = Cstruct.BE.get_uint32 buf off |> Int32.to_int in
  Cstruct.copy buf (off + 4) len

let buf_of_string s =
  let len = String.length s in
  (* XXX string cant be longer than uint8  *)
  let buf = Cstruct.create (len + 4) in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int len);
  Cstruct.blit_from_string s 0 buf 4 len;
  buf

let uint32_of_buf buf off =
  Cstruct.BE.get_uint32 buf off

let buf_of_uint32 v =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 v;
  buf

let bool_of_buf buf off =
  (Cstruct.get_uint8 buf 0) <> 0

let buf_of_bool b =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 (if b then 1 else 0);
  buf

(** {2 Name lists as in RFC4251 5.} *)

let buf_of_nl nl =
  let s = String.concat "," nl in
  let slen = String.length s in
  let buf = Cstruct.create (4 + slen) in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int slen);
  Cstruct.blit_from_string s 0 buf 4 slen;
  buf

let nl_of_buf buf =
  let len = Cstruct.BE.get_uint32 buf 0 in
  if Usane.Uint32.(Int32.of_int (Cstruct.len buf) < len) then
    invalid_arg "Buffer len doesn't match name-list len";
  Str.split (Str.regexp ",") (Cstruct.copy buf 4 (Int32.to_int len))

let nll_of_buf buf n =
  let rec loop buf l tlen =
    if (List.length l) = n then
      (List.rev l, tlen)
    else
      let len = Int32.to_int (Cstruct.BE.get_uint32 buf 0) in
      let nl = nl_of_buf buf in
      loop (Cstruct.shift buf (len + 4)) (nl :: l) (len + tlen + 4)
  in
  loop buf [] 0

(** {2 SSH_MSG_KEXINIT RFC4253 7.1.} *)

type kex_pkt = {
  cookie : string;
  kex_algorithms : string list;
  server_host_key_algorithms : string list;
  encryption_algorithms_ctos : string list;
  encryption_algorithms_stoc : string list;
  mac_algorithms_ctos : string list;
  mac_algorithms_stoc : string list;
  compression_algorithms_ctos : string list;
  compression_algorithms_stoc : string list;
  languages_ctos : string list;
  languages_stoc : string list;
  first_kex_packet_follows : bool
} [@@deriving sexp]

let buf_of_kex kex =
  let f = buf_of_nl in
  let nll = Cstruct.concat
    [ f kex.kex_algorithms;
      f kex.server_host_key_algorithms;
      f kex.encryption_algorithms_ctos;
      f kex.encryption_algorithms_stoc;
      f kex.mac_algorithms_ctos;
      f kex.mac_algorithms_stoc;
      f kex.compression_algorithms_ctos;
      f kex.compression_algorithms_stoc;
      f kex.languages_ctos;
      f kex.languages_stoc; ]
  in
  let head = Cstruct.create 17 in (* message code + cookie *)
  Cstruct.set_uint8 head 0 (message_id_to_int SSH_MSG_KEXINIT);
  Cstruct.blit_from_string kex.cookie 0 head 1 (String.length kex.cookie);
  let tail = Cstruct.create 5 in  (* first_kex_packet_follows + reserved *)
  Cstruct.set_uint8 tail 0 (if kex.first_kex_packet_follows then 1 else 0);
  Cstruct.concat [head; nll; tail]

let kex_of_buf buf =
  assert ((message_id_of_buf buf) = Some SSH_MSG_KEXINIT);
  (* Jump over msg id and cookie *)
  let nll, nll_len = nll_of_buf (Cstruct.shift buf 17) 10 in
  let first_kex_packet_follows = (Cstruct.get_uint8 buf nll_len) <> 0 in
  { cookie = Cstruct.copy buf 1 16;
    kex_algorithms = List.nth nll 0;
    server_host_key_algorithms = List.nth nll 1;
    encryption_algorithms_ctos = List.nth nll 2;
    encryption_algorithms_stoc = List.nth nll 3;
    mac_algorithms_ctos = List.nth nll 4;
    mac_algorithms_stoc = List.nth nll 5;
    compression_algorithms_ctos = List.nth nll 6;
    compression_algorithms_stoc = List.nth nll 7;
    languages_ctos = List.nth nll 8;
    languages_stoc = List.nth nll 9;
    first_kex_packet_follows; }

(** {2 SSH_MSG_DISCONNECT RFC4253 11.1.} *)

type disconnect_pkt = {
  code : int32;
  desc : string;
  lang : string;
}

let buf_of_disconnect disc =
  let desc = buf_of_string disc.desc in
  let lang = buf_of_string disc.lang in
  Cstruct.concat [buf_of_message_id SSH_MSG_KEXINIT; desc; lang]

let disconnect_of_buf buf =
  assert ((message_id_of_buf buf) = Some SSH_MSG_DISCONNECT);
  let code = uint32_of_buf buf 1 in
  let desc = string_of_buf buf 5 in
  let lang = string_of_buf buf ((String.length desc) + 9) in
  { code; desc; lang }

(** {2 SSH_MSG_IGNORE RFC4253 11.2.} *)

let ignore_of_buf buf =
  assert ((message_id_of_buf buf) = Some SSH_MSG_IGNORE);
  string_of_buf buf 1

let buf_of_ignore s =
  Cstruct.concat [buf_of_message_id SSH_MSG_IGNORE; buf_of_string s]

(** {2 SSH_MSG_UNIMPLEMENTED RFC 4253 11.4} *)

let buf_of_unimplemented v =
  Cstruct.concat [buf_of_message_id SSH_MSG_UNIMPLEMENTED; buf_of_uint32 v]

let unimplemented_of_buf buf =
  assert ((message_id_of_buf buf) = Some SSH_MSG_UNIMPLEMENTED);
  uint32_of_buf buf 1


(** {2 SSH_MSG_DEBUG RFC 4253 11.3} *)

type debug_pkt = {
  always_display : bool;
  message : string;
  lang : string
}

let debug_of_buf buf =
  assert ((message_id_of_buf buf) = Some SSH_MSG_DEBUG);
  let always_display = bool_of_buf buf 1 in
  let message = string_of_buf buf 2 in
  let lang = string_of_buf buf ((String.length message) + 6) in
  { always_display; message; lang }
