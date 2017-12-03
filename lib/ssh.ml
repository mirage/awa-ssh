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

let max_pkt_len = 512 * 1024          (* 512KB should be enough *)
let max_len = 256 * 1024              (* 256KB for a field is enough *)
let channel_win_len =                 (* 4MB channel window *)
  Int32.of_int (4 * 1024 * 1000)
let channel_win_adj_threshold =       (* Refresh window if below 2MB *)
  Int32.of_int (2 * 1024 * 1000)
let channel_max_pkt_len =             (* Must be smaller than max_pkt_len *)
  Int32.of_int (64 * 1024)
let max_channels = 1024               (* 1024 maximum channels per connection *)

let guard_sshlen len =
  guard (len >= 0 && len <= max_len) (sprintf "Bad length: %d" len)

let guard_sshlen_exn len =
  match guard_sshlen len with Ok () -> () | Error e -> invalid_arg e

[%%cenum
type message_id =
  | MSG_DISCONNECT                [@id 1]
  | MSG_IGNORE                    [@id 2]
  | MSG_UNIMPLEMENTED             [@id 3]
  | MSG_DEBUG                     [@id 4]
  | MSG_SERVICE_REQUEST           [@id 5]
  | MSG_SERVICE_ACCEPT            [@id 6]
  | MSG_KEXINIT                   [@id 20]
  | MSG_NEWKEYS                   [@id 21]
  | MSG_KEXDH_INIT                [@id 30]
  | MSG_KEXDH_REPLY               [@id 31]
  | MSG_USERAUTH_REQUEST          [@id 50]
  | MSG_USERAUTH_FAILURE          [@id 51]
  | MSG_USERAUTH_SUCCESS          [@id 52]
  | MSG_USERAUTH_BANNER           [@id 53]
  | MSG_USERAUTH_PK_OK            [@id 60]
  | MSG_GLOBAL_REQUEST            [@id 80]
  | MSG_REQUEST_SUCCESS           [@id 81]
  | MSG_REQUEST_FAILURE           [@id 82]
  | MSG_CHANNEL_OPEN              [@id 90]
  | MSG_CHANNEL_OPEN_CONFIRMATION [@id 91]
  | MSG_CHANNEL_OPEN_FAILURE      [@id 92]
  | MSG_CHANNEL_WINDOW_ADJUST     [@id 93]
  | MSG_CHANNEL_DATA              [@id 94]
  | MSG_CHANNEL_EXTENDED_DATA     [@id 95]
  | MSG_CHANNEL_EOF               [@id 96]
  | MSG_CHANNEL_CLOSE             [@id 97]
  | MSG_CHANNEL_REQUEST           [@id 98]
  | MSG_CHANNEL_SUCCESS           [@id 99]
  | MSG_CHANNEL_FAILURE           [@id 100]
  | MSG_VERSION                   [@id -1]
[@@uint8_t][@@sexp]]

type kexinit = {
  cookie                   : Cstruct.t;
  kex_algs                 : string list;
  server_host_key_algs     : string list;
  encryption_algs_ctos     : string list;
  encryption_algs_stoc     : string list;
  mac_algs_ctos            : string list;
  mac_algs_stoc            : string list;
  compression_algs_ctos    : string list;
  compression_algs_stoc    : string list;
  languages_ctos           : string list;
  languages_stoc           : string list;
  first_kex_packet_follows : bool;
  rawkex                   : Cstruct.t;   (* raw kexinit *)
} [@@deriving sexp]

[%%cenum
type disconnect_code =
  | DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      [@id  1]
  | DISCONNECT_PROTOCOL_ERROR                   [@id  2]
  | DISCONNECT_KEY_EXCHANGE_FAILED              [@id  3]
  | DISCONNECT_RESERVED                         [@id  4]
  | DISCONNECT_MAC_ERROR                        [@id  5]
  | DISCONNECT_COMPRESSION_ERROR                [@id  6]
  | DISCONNECT_SERVICE_NOT_AVAILABLE            [@id  7]
  | DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   [@id  8]
  | DISCONNECT_HOST_KEY_NOT_VERIFIABLE          [@id  9]
  | DISCONNECT_CONNECTION_LOST                  [@id 10]
  | DISCONNECT_BY_APPLICATION                   [@id 11]
  | DISCONNECT_TOO_MANY_CONNECTIONS             [@id 12]
  | DISCONNECT_AUTH_CANCELLED_BY_USER           [@id 13]
  | DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE   [@id 14]
  | DISCONNECT_ILLEGAL_USER_NAME                [@id 15]
[@@uint32_t][@@sexp]]

let int_to_disconnect_code code =
  match int_to_disconnect_code code with
  | Some disc -> disc
  | None -> DISCONNECT_PROTOCOL_ERROR (* Mock up *)

(* Channel open codes *)
[%%cenum
type channel_open_code =
  | OPEN_ADMINISTRATIVELY_PROHIBITED  [@id 1]
  | OPEN_CONNECT_FAILED               [@id 2]
  | OPEN_UNKNOWN_CHANNEL_TYPE         [@id 3]
  | OPEN_RESOURCE_SHORTAGE            [@id 4]
[@@uint32_t][@@sexp]]

type mpint = Nocrypto.Numeric.Z.t

let sexp_of_mpint mpint = sexp_of_string (Z.to_string mpint)

type global_request =
  | Tcpip_forward of (string * int32)
  | Cancel_tcpip_forward of (string * int32)
[@@deriving sexp]

type channel_request =
  | Pty_req of (string * int32 * int32 * int32 * int32 * string)
  | X11_req of (bool * string * string * int32)
  | Env of (string * string)
  | Shell
  | Exec of string
  | Subsystem of string
  | Window_change of (int32 * int32 * int32 * int32)
  | Xon_xoff of bool
  | Signal of string
  | Exit_status of int32
  | Exit_signal of (string * bool * string * string)
  | Raw_data of Cstruct.t
[@@deriving sexp]

type channel_open =
  | Session
  | X11 of (string * int32)
  | Forwarded_tcpip of (string * int32 * string * int32)
  | Direct_tcpip of (string * int32 * string * int32)
  | Raw_data of Cstruct.t
[@@deriving sexp]

(*
 * Protocol Authentication
 *)
type password = string

let sexp_of_password _ = sexp_of_string "????"
let password_of_sexp _ = failwith "password_of_sexp: TODO"

type auth_method =
  | Pubkey of (Hostkey.pub * Cstruct.t option)
  | Password of (password * password option)
  | Hostbased of (string * Cstruct.t * string * string * Cstruct.t) (* TODO *)
  | Authnone
[@@deriving sexp]

let auth_method_equal a b =
  match a, b with
  | Pubkey (key_a, signature_a),
    Pubkey (key_b, signature_b) ->
    let signature_match = match signature_a, signature_b with
      | Some sa, Some sb -> Cstruct.equal sa sb
      | None, None -> true
      | _ -> false
    in
    key_a = key_b && signature_match
  | Password _, Password _ -> a = b
  | Hostbased (key_alg_a, key_blob_a, hostname_a, hostuser_a, hostsig_a),
    Hostbased (key_alg_b, key_blob_b, hostname_b, hostuser_b, hostsig_b) ->
    key_alg_a = key_alg_b && (Cstruct.equal key_blob_a key_blob_b) &&
    hostname_a = hostname_b && hostuser_a = hostuser_b &&
    (Cstruct.equal hostsig_a hostsig_b)
  | Authnone, Authnone -> true
  | _ -> false

type message =
  | Msg_disconnect of (disconnect_code * string * string)
  | Msg_ignore of string
  | Msg_unimplemented of int32
  | Msg_debug of (bool * string * string)
  | Msg_service_request of string
  | Msg_service_accept of string
  | Msg_kexinit of kexinit
  | Msg_newkeys
  | Msg_kexdh_reply of (Hostkey.pub * mpint * Cstruct.t)
  | Msg_kexdh_init of mpint
  | Msg_userauth_request of (string * string * auth_method)
  | Msg_userauth_failure of (string list * bool)
  | Msg_userauth_success
  | Msg_userauth_banner of (string * string)
  | Msg_userauth_pk_ok of Hostkey.pub
  | Msg_global_request of (string * bool * global_request)
  | Msg_request_success of Cstruct.t option
  | Msg_request_failure
  | Msg_channel_open of (int32 * int32 * int32 * channel_open)
  | Msg_channel_open_confirmation of (int32 * int32 * int32 * int32 * Cstruct.t)
  | Msg_channel_open_failure of (int32 * int32 * string * string)
  | Msg_channel_window_adjust of (int32 * int32)
  | Msg_channel_data of (int32 * Cstruct.t)
  | Msg_channel_extended_data of (int32 * int32 * Cstruct.t)
  | Msg_channel_eof of int32
  | Msg_channel_close of int32
  | Msg_channel_request of (int32 * bool * channel_request)
  | Msg_channel_success of int32
  | Msg_channel_failure of int32
  | Msg_version of string       (* Mocked version *)
[@@deriving sexp_of]

let message_to_string msg =
  Sexplib.Sexp.to_string_hum (sexp_of_message msg)

let message_to_id = function
  | Msg_disconnect _               -> MSG_DISCONNECT
  | Msg_ignore _                   -> MSG_IGNORE
  | Msg_unimplemented _            -> MSG_UNIMPLEMENTED
  | Msg_debug _                    -> MSG_DEBUG
  | Msg_service_request _          -> MSG_SERVICE_REQUEST
  | Msg_service_accept _           -> MSG_SERVICE_ACCEPT
  | Msg_kexinit _                  -> MSG_KEXINIT
  | Msg_newkeys                    -> MSG_NEWKEYS
  | Msg_kexdh_init _               -> MSG_KEXDH_INIT
  | Msg_kexdh_reply _              -> MSG_KEXDH_REPLY
  | Msg_userauth_request _         -> MSG_USERAUTH_REQUEST
  | Msg_userauth_failure _         -> MSG_USERAUTH_FAILURE
  | Msg_userauth_success           -> MSG_USERAUTH_SUCCESS
  | Msg_userauth_banner _          -> MSG_USERAUTH_BANNER
  | Msg_userauth_pk_ok _           -> MSG_USERAUTH_PK_OK
  | Msg_global_request _           -> MSG_GLOBAL_REQUEST
  | Msg_request_success _          -> MSG_REQUEST_SUCCESS
  | Msg_request_failure            -> MSG_REQUEST_FAILURE
  | Msg_channel_open _             -> MSG_CHANNEL_OPEN
  | Msg_channel_open_confirmation _-> MSG_CHANNEL_OPEN_CONFIRMATION
  | Msg_channel_open_failure _     -> MSG_CHANNEL_OPEN_FAILURE
  | Msg_channel_window_adjust _    -> MSG_CHANNEL_WINDOW_ADJUST
  | Msg_channel_data _             -> MSG_CHANNEL_DATA
  | Msg_channel_extended_data _    -> MSG_CHANNEL_EXTENDED_DATA
  | Msg_channel_eof _              -> MSG_CHANNEL_EOF
  | Msg_channel_close _            -> MSG_CHANNEL_CLOSE
  | Msg_channel_request _          -> MSG_CHANNEL_REQUEST
  | Msg_channel_success _          -> MSG_CHANNEL_SUCCESS
  | Msg_channel_failure _          -> MSG_CHANNEL_FAILURE
  | Msg_version _                  -> MSG_VERSION

let message_to_int msg = message_id_to_int (message_to_id msg)

let disconnect_msg code s =
  Msg_disconnect (code, s, "")
