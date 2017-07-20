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

let max_pkt_len = 512 * 1024    (* 512KB should be enough *)
let max_len = 256 * 1024        (* 256KB for a field is enough *)

let guard_sshlen len =
  guard (len >= 0 && len <= max_len) (sprintf "Bad length: %d" len)

let guard_sshlen_exn len =
  match guard_sshlen len with Ok () -> () | Error e -> invalid_arg e

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
  | SSH_MSG_USERAUTH_PK_OK            [@id 60]
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
  | SSH_MSG_VERSION                   [@id -1]
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
  input_buf                : Cstruct.t option;   (* Incoming raw kexinit *)
} [@@deriving sexp]

[%%cenum
type disconnect_code =
  | SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      [@id  1]
  | SSH_DISCONNECT_PROTOCOL_ERROR                   [@id  2]
  | SSH_DISCONNECT_KEY_EXCHANGE_FAILED              [@id  3]
  | SSH_DISCONNECT_RESERVED                         [@id  4]
  | SSH_DISCONNECT_MAC_ERROR                        [@id  5]
  | SSH_DISCONNECT_COMPRESSION_ERROR                [@id  6]
  | SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            [@id  7]
  | SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   [@id  8]
  | SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE          [@id  9]
  | SSH_DISCONNECT_CONNECTION_LOST                  [@id 10]
  | SSH_DISCONNECT_BY_APPLICATION                   [@id 11]
  | SSH_DISCONNECT_TOO_MANY_CONNECTIONS             [@id 12]
  | SSH_DISCONNECT_AUTH_CANCELLED_BY_USER           [@id 13]
  | SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE   [@id 14]
  | SSH_DISCONNECT_ILLEGAL_USER_NAME                [@id 15]
[@@uint32_t][@@sexp]]

let int_to_disconnect_code code =
  match int_to_disconnect_code code with
  | Some disc -> disc
  | None -> SSH_DISCONNECT_PROTOCOL_ERROR (* Mock up *)

type mpint = Nocrypto.Numeric.Z.t

let sexp_of_mpint mpint = sexp_of_string (Z.to_string mpint)

type auth_method =
  | Pubkey of (Hostkey.pub * Cstruct.t option)
  | Password of (string * string option)
  | Hostbased of (string * Cstruct.t * string * string * Cstruct.t) (* TODO *)
  | Authnone

let sexp_of_auth_method = function
  | Pubkey (key_blob, signature) ->
    sexp_of_string
      (sprintf "Publickey key_blob=TODO signature=%b" (is_some signature))
  | Password (password, oldpassword) ->
    sexp_of_string
      (sprintf "Password password=XXX oldpassword=%b" (is_some oldpassword))
  | Hostbased (key_alg, key_blob, hostname, hostuser, hostsig) ->
    let s = sprintf
        "Hostbased key_alg=%s key_blob=TODO hostname=%s hostuser=%s hostsig=TODO"
        key_alg hostname hostuser
    in
    sexp_of_string s
  | Authnone -> sexp_of_string "None"

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
  | Ssh_msg_disconnect of (disconnect_code * string * string)
  | Ssh_msg_ignore of string
  | Ssh_msg_unimplemented of int32
  | Ssh_msg_debug of (bool * string * string)
  | Ssh_msg_service_request of string
  | Ssh_msg_service_accept of string
  | Ssh_msg_kexinit of kexinit
  | Ssh_msg_newkeys
  | Ssh_msg_kexdh_reply of (Hostkey.pub * mpint * Cstruct.t)
  | Ssh_msg_kexdh_init of mpint
  | Ssh_msg_userauth_request of (string * string * auth_method)
  | Ssh_msg_userauth_failure of (string list * bool)
  | Ssh_msg_userauth_success
  | Ssh_msg_userauth_banner of (string * string)
  | Ssh_msg_userauth_pk_ok of Hostkey.pub
  | Ssh_msg_global_request
  | Ssh_msg_request_success
  | Ssh_msg_request_failure
  | Ssh_msg_channel_open
  | Ssh_msg_channel_open_confirmation
  | Ssh_msg_channel_open_failure
  | Ssh_msg_channel_window_adjust of (int32 * int32)
  | Ssh_msg_channel_data
  | Ssh_msg_channel_extended_data
  | Ssh_msg_channel_eof of int32
  | Ssh_msg_channel_close of int32
  | Ssh_msg_channel_request
  | Ssh_msg_channel_success of int32
  | Ssh_msg_channel_failure of int32
  | Ssh_msg_version of string       (* Mocked version *)
  [@@deriving sexp_of]

let message_to_string msg =
  Sexplib.Sexp.to_string_hum (sexp_of_message msg)

let message_to_id = function
  | Ssh_msg_disconnect _               -> SSH_MSG_DISCONNECT
  | Ssh_msg_ignore _                   -> SSH_MSG_IGNORE
  | Ssh_msg_unimplemented _            -> SSH_MSG_UNIMPLEMENTED
  | Ssh_msg_debug _                    -> SSH_MSG_DEBUG
  | Ssh_msg_service_request _          -> SSH_MSG_SERVICE_REQUEST
  | Ssh_msg_service_accept _           -> SSH_MSG_SERVICE_ACCEPT
  | Ssh_msg_kexinit _                  -> SSH_MSG_KEXINIT
  | Ssh_msg_newkeys                    -> SSH_MSG_NEWKEYS
  | Ssh_msg_kexdh_init _               -> SSH_MSG_KEXDH_INIT
  | Ssh_msg_kexdh_reply _              -> SSH_MSG_KEXDH_REPLY
  | Ssh_msg_userauth_request _         -> SSH_MSG_USERAUTH_REQUEST
  | Ssh_msg_userauth_failure _         -> SSH_MSG_USERAUTH_FAILURE
  | Ssh_msg_userauth_success           -> SSH_MSG_USERAUTH_SUCCESS
  | Ssh_msg_userauth_banner _          -> SSH_MSG_USERAUTH_BANNER
  | Ssh_msg_userauth_pk_ok _           -> SSH_MSG_USERAUTH_PK_OK
  | Ssh_msg_global_request             -> SSH_MSG_GLOBAL_REQUEST
  | Ssh_msg_request_success            -> SSH_MSG_REQUEST_SUCCESS
  | Ssh_msg_request_failure            -> SSH_MSG_REQUEST_FAILURE
  | Ssh_msg_channel_open               -> SSH_MSG_CHANNEL_OPEN
  | Ssh_msg_channel_open_confirmation  -> SSH_MSG_CHANNEL_OPEN_CONFIRMATION
  | Ssh_msg_channel_open_failure       -> SSH_MSG_CHANNEL_OPEN_FAILURE
  | Ssh_msg_channel_window_adjust _    -> SSH_MSG_CHANNEL_WINDOW_ADJUST
  | Ssh_msg_channel_data               -> SSH_MSG_CHANNEL_DATA
  | Ssh_msg_channel_extended_data      -> SSH_MSG_CHANNEL_EXTENDED_DATA
  | Ssh_msg_channel_eof _              -> SSH_MSG_CHANNEL_EOF
  | Ssh_msg_channel_close _            -> SSH_MSG_CHANNEL_CLOSE
  | Ssh_msg_channel_request            -> SSH_MSG_CHANNEL_REQUEST
  | Ssh_msg_channel_success _          -> SSH_MSG_CHANNEL_SUCCESS
  | Ssh_msg_channel_failure _          -> SSH_MSG_CHANNEL_FAILURE
  | Ssh_msg_version _                  -> SSH_MSG_VERSION

let message_to_int msg = message_id_to_int (message_to_id msg)
