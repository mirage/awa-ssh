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

[%%cstruct
type pkt_hdr = {
  pkt_len: uint32_t;
  pad_len: uint8_t;
} [@@big_endian]]

let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let scan_version buf =
  let s = Cstruct.to_string buf in
  let len = String.length s in
  let not_found =
    if len < (1024 * 64) then
      ok None
    else
      error "Buffer is too big"
  in
  let rec scan start off =
    if off = len then
      not_found
    else
      match (String.get s (pred off), String.get s off) with
      | ('\r', '\n') ->
        let line = String.sub s start (off - start - 1) in
        let line_len = String.length line in
        if line_len < 4 ||
           String.sub line 0 4 <> "SSH-" then
          scan (succ off) (succ off)
        else if (line_len < 9) then
          error "Version line is too short"
        else
          let tokens = Str.split_delim (Str.regexp "-") line in
          if List.length tokens <> 3 then
            error "Can't parse version line"
          else
            let version = List.nth tokens 1 in
            let peer_version = List.nth tokens 2 in
            if version <> "2.0" then
              error ("Bad version " ^ version)
            else
              safe_shift buf (succ off) >>= fun buf ->
              ok (Some (peer_version, buf))
      | _ -> scan start (succ off)
  in
  if len < 2 then
    not_found
  else
    scan 0 1

let scan_pkt buf =
  let len = Cstruct.len buf in
  let partial () =
    if len < (1024 * 64) then
      ok None
    else
      error "Buffer is too big"
  in
  if len < 4 then
    partial ()
  else
    let pkt_len32 = get_pkt_hdr_pkt_len buf in
    let pkt_len = Int32.to_int pkt_len32 in
    let pad_len = get_pkt_hdr_pad_len buf in
    (* XXX remember mac_len *)
    guard
      (pkt_len <> 0 &&
       ((u32_compare pkt_len32 max_pkt_len) < 0) &&
       (pkt_len > pad_len + 1))
      "Malformed packet"
    >>= fun () ->
    assert (len > 4);
    if pkt_len > (len - 4) then
      partial ()
    else
      let payload_len = pkt_len - pad_len - 1 in
      let clen =
        4 +                (* pkt_len field itself *)
        pkt_len +          (* size of this packet  *)
        pad_len            (* padding after packet *)
                           (* XXX mac_len missing !*)
      in
      safe_sub buf sizeof_pkt_hdr payload_len >>= fun pkt ->
      ok (Some (pkt, clen))

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
  | SSH_MSG_KEXDH_INIT                [@id 30]
  | SSH_MSG_KEXDH_REPLY               [@id 31]
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

type server_host_key_algorithm =
  | Ssh_rsa

let server_host_key_algorithm_of_string = function
  | "ssh-rsa" -> ok Ssh_rsa
  | s -> error ("Unknown server host key algorithm " ^ s)

let server_host_key_algorithm_to_string = function
  | Ssh_rsa -> "ssh-rsa"

type compression_algorithm =
  | Nothing                        (* Can't use None :-D *)

let compression_algorithm_of_string = function
  | "none" -> ok Nothing
  | s -> error ("Unknown compression algorithm " ^ s)

let compression_algorithm_to_string = function
  | Nothing -> "none"

type kex_pkt = {
  cookie : Cstruct.t;
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


let encode_kex_pkt kex =
  let open Buf in
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
  add_uint32 Int32.zero |>
  to_cstruct

type message =
  | Ssh_msg_disconnect of (int32 * string * string)
  | Ssh_msg_ignore of string
  | Ssh_msg_unimplemented of int32
  | Ssh_msg_debug of (bool * string * string)
  | Ssh_msg_service_request of string
  | Ssh_msg_service_accept of string
  | Ssh_msg_kexinit of kex_pkt
  | Ssh_msg_kexdh_init of Nocrypto.Numeric.Z.t
  | Ssh_msg_kexdh_reply of (Nocrypto.Rsa.pub * Nocrypto.Numeric.Z.t * Cstruct.t)
  | Ssh_msg_newkeys
  | Ssh_msg_userauth_request of (string * string * string * bool * string * Cstruct.t)
  | Ssh_msg_userauth_failure of (string list * bool)
  | Ssh_msg_userauth_success
  | Ssh_msg_userauth_banner of (string * string)
  | Ssh_msg_global_request
  | Ssh_msg_request_success
  | Ssh_msg_request_failure
  | Ssh_msg_channel_open
  | Ssh_msg_channel_open_confirmation
  | Ssh_msg_channel_open_failure
  | Ssh_msg_channel_window_adjust of (int32 * int32)
  | Ssh_msg_channel_data
  | Ssh_msg_channel_extended_data
  | Ssh_msg_channel_eof
  | Ssh_msg_channel_close
  | Ssh_msg_channel_request
  | Ssh_msg_channel_success
  | Ssh_msg_channel_failure of int32


let encode_message msg =
  let open Buf in
  let add_id id buf = add_uint8 (message_id_to_int id) buf in
  let buf = match msg with
    | Ssh_msg_disconnect (code, desc, lang) ->
      add_id SSH_MSG_DISCONNECT (create ()) |>
      add_uint32 code |>
      add_string desc |>
      add_string lang
    | Ssh_msg_ignore s ->
      add_id SSH_MSG_IGNORE (create ()) |>
      add_string s
    | Ssh_msg_unimplemented x ->
      add_id SSH_MSG_UNIMPLEMENTED (create ()) |>
      add_uint32 x
    | Ssh_msg_debug (always_display, message, lang) ->
      add_id SSH_MSG_DEBUG (create ()) |>
      add_bool always_display |>
      add_string message |>
      add_string lang
    | Ssh_msg_service_request s ->
      add_id SSH_MSG_SERVICE_REQUEST (create ()) |>
      add_string s
    | Ssh_msg_service_accept s ->
      add_id SSH_MSG_SERVICE_ACCEPT (create ()) |>
      add_string s
    (* | Ssh_msg_kexinit kex -> encode_kex_pkt kex (\* XXX convert *\) *)
    | Ssh_msg_newkeys ->
      add_id SSH_MSG_NEWKEYS (create ())
    (* | SSH_MSG_KEXDH_INIT -> decode_mpint buf >>= fun (e, buf) -> *)
    (*   ok (Ssh_msg_kexdh_init e) *)
    (* | SSH_MSG_KEXDH_REPLY -> *)
    (*   decode_key buf >>= fun (k_s, buf) -> *)
    (*   decode_mpint buf >>= fun (f, buf) -> *)
    (*   decode_cstring buf >>= fun (hsig, buf) -> *)
    (*   ok (Ssh_msg_kexdh_reply (k_s, f, hsig)) *)
    (* | Ssh_msg_userauth_request user service publickey *)
    (*   -> unimplemented () *)
    | Ssh_msg_userauth_failure (nl, psucc) ->
      add_id SSH_MSG_USERAUTH_FAILURE (create ()) |>
      add_nl nl |>
      add_bool psucc
    | Ssh_msg_userauth_success ->
      add_id SSH_MSG_USERAUTH_SUCCESS (create ())
    | Ssh_msg_userauth_banner (message, lang) ->
      add_id SSH_MSG_USERAUTH_BANNER (create ()) |>
      add_string message |>
      add_string lang
    (* | SSH_MSG_GLOBAL_REQUEST -> unimplemented () *)
    (* | SSH_MSG_REQUEST_SUCCESS -> unimplemented () *)
    | Ssh_msg_request_failure ->
      add_id SSH_MSG_REQUEST_FAILURE (create ())
    (* | SSH_MSG_CHANNEL_OPEN -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> unimplemented () *)
    | Ssh_msg_channel_open_failure ->
      add_id SSH_MSG_CHANNEL_OPEN_FAILURE (create ())
    | Ssh_msg_channel_window_adjust (channel, n) ->
      add_id SSH_MSG_CHANNEL_WINDOW_ADJUST (create ()) |>
      add_uint32 channel |>
      add_uint32 n
    (* | SSH_MSG_CHANNEL_DATA -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_EXTENDED_DATA -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_EOF -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_CLOSE -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_REQUEST -> unimplemented () *)
    (* | SSH_MSG_CHANNEL_SUCCESS -> unimplemented () *)
    | Ssh_msg_channel_failure channel ->
      add_id SSH_MSG_CHANNEL_FAILURE (create ()) |>
      add_uint32 channel
    | _ -> failwith "removeme"
  in
  to_cstruct buf

