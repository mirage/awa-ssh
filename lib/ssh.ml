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

let version_banner = "SSH-2.0-awa_ssh_0.1"
let max_pkt_len = 512 * 1024          (* 512KB should be enough *)
let max_len = 256 * 1024              (* 256KB for a field is enough *)
let channel_win_len =                 (* 4MB channel window *)
  Int32.of_int (4 * 1024 * 1000)
let channel_win_adj_threshold =       (* Refresh window if below 2MB *)
  Int32.of_int (2 * 1024 * 1000)
let channel_max_pkt_len =             (* Must be smaller than max_pkt_len *)
  Int32.of_int (64 * 1024)
let max_channels = 1024               (* 1024 maximum channels per connection *)

let min_dh, n, max_dh = 2048l, 3072l, 8192l

let guard_sshlen len =
  guard (len >= 0 && len <= max_len) (sprintf "Bad length: %d" len)

let guard_sshlen_exn len =
  match guard_sshlen len with Ok () -> () | Error e -> invalid_arg e

type message_id =
  | MSG_DISCONNECT                [@id 1]
  | MSG_IGNORE                    [@id 2]
  | MSG_UNIMPLEMENTED             [@id 3]
  | MSG_DEBUG                     [@id 4]
  | MSG_SERVICE_REQUEST           [@id 5]
  | MSG_SERVICE_ACCEPT            [@id 6]
  | MSG_EXT_INFO                  [@id 7]
  | MSG_KEXINIT                   [@id 20]
  | MSG_NEWKEYS                   [@id 21]
  | MSG_KEX_0                     [@id 30]
  | MSG_KEX_1                     [@id 31]
  | MSG_KEX_2                     [@id 32]
  | MSG_KEX_3                     [@id 33]
  | MSG_KEX_4                     [@id 34]
  | MSG_USERAUTH_REQUEST          [@id 50]
  | MSG_USERAUTH_FAILURE          [@id 51]
  | MSG_USERAUTH_SUCCESS          [@id 52]
  | MSG_USERAUTH_BANNER           [@id 53]
  | MSG_USERAUTH_1                [@id 60]
  | MSG_USERAUTH_2                [@id 61]
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

let message_id_to_int = function
  | MSG_DISCONNECT                -> 1
  | MSG_IGNORE                    -> 2
  | MSG_UNIMPLEMENTED             -> 3
  | MSG_DEBUG                     -> 4
  | MSG_SERVICE_REQUEST           -> 5
  | MSG_SERVICE_ACCEPT            -> 6
  | MSG_EXT_INFO                  -> 7
  | MSG_KEXINIT                   -> 20
  | MSG_NEWKEYS                   -> 21
  | MSG_KEX_0                     -> 30
  | MSG_KEX_1                     -> 31
  | MSG_KEX_2                     -> 32
  | MSG_KEX_3                     -> 33
  | MSG_KEX_4                     -> 34
  | MSG_USERAUTH_REQUEST          -> 50
  | MSG_USERAUTH_FAILURE          -> 51
  | MSG_USERAUTH_SUCCESS          -> 52
  | MSG_USERAUTH_BANNER           -> 53
  | MSG_USERAUTH_1                -> 60
  | MSG_USERAUTH_2                -> 61
  | MSG_GLOBAL_REQUEST            -> 80
  | MSG_REQUEST_SUCCESS           -> 81
  | MSG_REQUEST_FAILURE           -> 82
  | MSG_CHANNEL_OPEN              -> 90
  | MSG_CHANNEL_OPEN_CONFIRMATION -> 91
  | MSG_CHANNEL_OPEN_FAILURE      -> 92
  | MSG_CHANNEL_WINDOW_ADJUST     -> 93
  | MSG_CHANNEL_DATA              -> 94
  | MSG_CHANNEL_EXTENDED_DATA     -> 95
  | MSG_CHANNEL_EOF               -> 96
  | MSG_CHANNEL_CLOSE             -> 97
  | MSG_CHANNEL_REQUEST           -> 98
  | MSG_CHANNEL_SUCCESS           -> 99
  | MSG_CHANNEL_FAILURE           -> 100
  | MSG_VERSION                   -> -1

let int_to_message_id = function
  | 1 -> Some MSG_DISCONNECT
  | 2 -> Some MSG_IGNORE
  | 3 -> Some MSG_UNIMPLEMENTED
  | 4 -> Some MSG_DEBUG
  | 5 -> Some MSG_SERVICE_REQUEST
  | 6 -> Some MSG_SERVICE_ACCEPT
  | 7 -> Some MSG_EXT_INFO
  | 20 -> Some MSG_KEXINIT
  | 21 -> Some MSG_NEWKEYS
  | 30 -> Some MSG_KEX_0
  | 31 -> Some MSG_KEX_1
  | 32 -> Some MSG_KEX_2
  | 33 -> Some MSG_KEX_3
  | 34 -> Some MSG_KEX_4
  | 50 -> Some MSG_USERAUTH_REQUEST
  | 51 -> Some MSG_USERAUTH_FAILURE
  | 52 -> Some MSG_USERAUTH_SUCCESS
  | 53 -> Some MSG_USERAUTH_BANNER
  | 60 -> Some MSG_USERAUTH_1
  | 61 -> Some MSG_USERAUTH_2
  | 80 -> Some MSG_GLOBAL_REQUEST
  | 81 -> Some MSG_REQUEST_SUCCESS
  | 82 -> Some MSG_REQUEST_FAILURE
  | 90 -> Some MSG_CHANNEL_OPEN
  | 91 -> Some MSG_CHANNEL_OPEN_CONFIRMATION
  | 92 -> Some MSG_CHANNEL_OPEN_FAILURE
  | 93 -> Some MSG_CHANNEL_WINDOW_ADJUST
  | 94 -> Some MSG_CHANNEL_DATA
  | 95 -> Some MSG_CHANNEL_EXTENDED_DATA
  | 96 -> Some MSG_CHANNEL_EOF
  | 97 -> Some MSG_CHANNEL_CLOSE
  | 98 -> Some MSG_CHANNEL_REQUEST
  | 99 -> Some MSG_CHANNEL_SUCCESS
  | 100 -> Some MSG_CHANNEL_FAILURE
  | -1 -> Some MSG_VERSION
  | _ -> None

type kexinit = {
  cookie                   : Cstruct.t;
  kex_algs                 : string list;
  ext_info                 : [`Ext_info_c | `Ext_info_s] option;
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
}

let pp_kexinit ppf kex =
  let string_of_ext_info = function
    | None -> "no ext-info"
    | Some `Ext_info_c -> "ext-info-c"
    | Some `Ext_info_s -> "ext-info-s"
  in
  let pp_sl = Fmt.(list ~sep:(any ", ") string) in
  Fmt.pf ppf "cookie %a@.kex algorithms %a@.ext_info %s@.server host key algorithms %a@. \
              encryption algorithms client to server %a@.encryption algorithms server to client %a@. \
              mac algorithms client to server %a@.mac algorithms server to client %a@. \
              compression algorithms client to server %a@.compression algorithms server to client %a@. \
              languages client to server %a@.languages server to client %a@. \
              first key exchange packet follows %B@.raw kex %a"
    Cstruct.hexdump_pp kex.cookie
    pp_sl kex.kex_algs (string_of_ext_info kex.ext_info) pp_sl kex.server_host_key_algs
    pp_sl kex.encryption_algs_ctos pp_sl kex.encryption_algs_stoc
    pp_sl kex.mac_algs_ctos pp_sl kex.mac_algs_stoc
    pp_sl kex.compression_algs_ctos pp_sl kex.compression_algs_stoc
    pp_sl kex.languages_ctos pp_sl kex.languages_stoc
    kex.first_kex_packet_follows
    Cstruct.hexdump_pp kex.rawkex

type extension = Extension of { name : string; value : string }

let pp_extension ppf (Extension { name; value }) =
  Fmt.pf ppf "%s=%S" name value

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

let disconnect_code_to_int = function
  | DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      ->  1l
  | DISCONNECT_PROTOCOL_ERROR                   ->  2l
  | DISCONNECT_KEY_EXCHANGE_FAILED              ->  3l
  | DISCONNECT_RESERVED                         ->  4l
  | DISCONNECT_MAC_ERROR                        ->  5l
  | DISCONNECT_COMPRESSION_ERROR                ->  6l
  | DISCONNECT_SERVICE_NOT_AVAILABLE            ->  7l
  | DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   ->  8l
  | DISCONNECT_HOST_KEY_NOT_VERIFIABLE          ->  9l
  | DISCONNECT_CONNECTION_LOST                  -> 10l
  | DISCONNECT_BY_APPLICATION                   -> 11l
  | DISCONNECT_TOO_MANY_CONNECTIONS             -> 12l
  | DISCONNECT_AUTH_CANCELLED_BY_USER           -> 13l
  | DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE   -> 14l
  | DISCONNECT_ILLEGAL_USER_NAME                -> 15l

let int_to_disconnect_code = function
  | 1l -> DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
  | 2l -> DISCONNECT_PROTOCOL_ERROR
  | 3l -> DISCONNECT_KEY_EXCHANGE_FAILED
  | 4l -> DISCONNECT_RESERVED
  | 5l -> DISCONNECT_MAC_ERROR
  | 6l -> DISCONNECT_COMPRESSION_ERROR
  | 7l -> DISCONNECT_SERVICE_NOT_AVAILABLE
  | 8l -> DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
  | 9l -> DISCONNECT_HOST_KEY_NOT_VERIFIABLE
  | 10l -> DISCONNECT_CONNECTION_LOST
  | 11l -> DISCONNECT_BY_APPLICATION
  | 12l -> DISCONNECT_TOO_MANY_CONNECTIONS
  | 13l -> DISCONNECT_AUTH_CANCELLED_BY_USER
  | 14l -> DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
  | 15l -> DISCONNECT_ILLEGAL_USER_NAME
  | _ -> DISCONNECT_PROTOCOL_ERROR (* Mock up *)

let disconnect_code_to_string = function
  | DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT -> "Host not allowed to connect"
  | DISCONNECT_PROTOCOL_ERROR -> "Protocol error"
  | DISCONNECT_KEY_EXCHANGE_FAILED -> "Key exchange failed"
  | DISCONNECT_RESERVED -> "Reserved"
  | DISCONNECT_MAC_ERROR -> "MAC error"
  | DISCONNECT_COMPRESSION_ERROR -> "Compression error"
  | DISCONNECT_SERVICE_NOT_AVAILABLE -> "Service not available"
  | DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED -> "Protocol version not supported"
  | DISCONNECT_HOST_KEY_NOT_VERIFIABLE -> "Host key not verifiable"
  | DISCONNECT_CONNECTION_LOST -> "Connection lost"
  | DISCONNECT_BY_APPLICATION -> "Disconnected by application"
  | DISCONNECT_TOO_MANY_CONNECTIONS -> "Too many connections"
  | DISCONNECT_AUTH_CANCELLED_BY_USER -> "Authentication cancelled by user"
  | DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE -> "No more authentication methods available"
  | DISCONNECT_ILLEGAL_USER_NAME -> "Illegal user name"

(* Channel open codes *)
type channel_open_code =
  | OPEN_ADMINISTRATIVELY_PROHIBITED  [@id 1]
  | OPEN_CONNECT_FAILED               [@id 2]
  | OPEN_UNKNOWN_CHANNEL_TYPE         [@id 3]
  | OPEN_RESOURCE_SHORTAGE            [@id 4]

let channel_open_code_to_int = function
  | OPEN_ADMINISTRATIVELY_PROHIBITED  -> 1l
  | OPEN_CONNECT_FAILED               -> 2l
  | OPEN_UNKNOWN_CHANNEL_TYPE         -> 3l
  | OPEN_RESOURCE_SHORTAGE            -> 4l

let int_to_channel_open_code = function
  | 1l -> Some OPEN_ADMINISTRATIVELY_PROHIBITED
  | 2l -> Some OPEN_CONNECT_FAILED
  | 3l -> Some OPEN_UNKNOWN_CHANNEL_TYPE
  | 4l -> Some OPEN_RESOURCE_SHORTAGE
  | _ -> None

type mpint = Z.t

type global_request =
  | Tcpip_forward of (string * int32)
  | Cancel_tcpip_forward of (string * int32)
  | Unknown_request of string

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

type channel_open =
  | Session
  | X11 of (string * int32)
  | Forwarded_tcpip of (string * int32 * string * int32)
  | Direct_tcpip of (string * int32 * string * int32)
  | Raw_data of Cstruct.t

(*
 * Protocol Authentication
 *)
type password = string

type auth_method =
  | Pubkey of string * Cstruct.t * (string * Cstruct.t) option
  | Password of password * password option
  | Keyboard_interactive of string option * string list
  | Authnone

let pp_auth_method ppf = function
  | Pubkey (_sig_alg_raw, _pub_raw, _signature) -> Fmt.string ppf "publickey"
  | Password (_, _) -> Fmt.string ppf "password"
  | Keyboard_interactive (_, _) -> Fmt.string ppf "keyboard-interactive"
  | Authnone -> Fmt.string ppf "none"

let opt_eq f a b =
  match a, b with
  | None, None -> true
  | Some a, Some b -> f a b
  | None, Some _ | Some _, None -> false

let auth_method_equal a b =
  match a, b with
  | Pubkey (sig_alg_raw_a, key_a, signature_a),
    Pubkey (sig_alg_raw_b, key_b, signature_b) ->
    let sig_equal (sig_alg_a, sig_a) (sig_alg_b, sig_b) =
      sig_alg_a = sig_alg_b && Cstruct.equal sig_a sig_b
    in
    String.equal sig_alg_raw_a sig_alg_raw_b &&
    Cstruct.equal key_a key_b &&
    opt_eq sig_equal signature_a signature_b
  | Password (p_a, popt_a), Password (p_b, popt_b) ->
    String.equal p_a p_b && opt_eq String.equal popt_a popt_b
  | Keyboard_interactive (l_a, sub_a), Keyboard_interactive (l_b, sub_b) ->
    opt_eq String.equal l_a l_b && List.for_all2 String.equal sub_a sub_b
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
  | Msg_ext_info of extension list
  | Msg_newkeys
  | Msg_kexdh_reply of Hostkey.pub * mpint * (Hostkey.alg * Cstruct.t)
  | Msg_kexdh_init of mpint
  (* from RFC 5656 / 8731 *)
  | Msg_kexecdh_reply of Hostkey.pub * mpint * (Hostkey.alg * Cstruct.t)
  | Msg_kexecdh_init of mpint
  (* from RFC 4419 *)
  (* there's as well a Msg_kexdh_gex_request_old with only a single int32 *)
  | Msg_kexdh_gex_request of int32 * int32 * int32
  | Msg_kexdh_gex_group of mpint * mpint
  | Msg_kexdh_gex_init of mpint
  | Msg_kexdh_gex_reply of Hostkey.pub * mpint * (Hostkey.alg * Cstruct.t)
  | Msg_kex of message_id * Cstruct.t
  | Msg_userauth_request of (string * string * auth_method)
  | Msg_userauth_failure of (string list * bool)
  | Msg_userauth_success
  | Msg_userauth_banner of (string * string)
  | Msg_userauth_1 of Cstruct.t
  | Msg_userauth_2 of Cstruct.t
  | Msg_userauth_pk_ok of Hostkey.pub
  | Msg_userauth_info_request of string * string * string * (string * bool) list
  | Msg_userauth_info_response of password list
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

let message_to_id = function
  | Msg_disconnect _               -> MSG_DISCONNECT
  | Msg_ignore _                   -> MSG_IGNORE
  | Msg_unimplemented _            -> MSG_UNIMPLEMENTED
  | Msg_debug _                    -> MSG_DEBUG
  | Msg_service_request _          -> MSG_SERVICE_REQUEST
  | Msg_service_accept _           -> MSG_SERVICE_ACCEPT
  | Msg_kexinit _                  -> MSG_KEXINIT
  | Msg_ext_info _                 -> MSG_EXT_INFO
  | Msg_newkeys                    -> MSG_NEWKEYS
  | Msg_kexdh_init _               -> MSG_KEX_0
  | Msg_kexdh_reply _              -> MSG_KEX_1
  | Msg_kexecdh_init _             -> MSG_KEX_0
  | Msg_kexecdh_reply _            -> MSG_KEX_1
  | Msg_kexdh_gex_request _        -> MSG_KEX_4
  | Msg_kexdh_gex_group _          -> MSG_KEX_1
  | Msg_kexdh_gex_init _           -> MSG_KEX_2
  | Msg_kexdh_gex_reply _          -> MSG_KEX_3
  | Msg_kex (id, _)                -> id
  | Msg_userauth_request _         -> MSG_USERAUTH_REQUEST
  | Msg_userauth_failure _         -> MSG_USERAUTH_FAILURE
  | Msg_userauth_success           -> MSG_USERAUTH_SUCCESS
  | Msg_userauth_banner _          -> MSG_USERAUTH_BANNER
  | Msg_userauth_1 _               -> MSG_USERAUTH_1
  | Msg_userauth_2 _               -> MSG_USERAUTH_2
  | Msg_userauth_pk_ok _           -> MSG_USERAUTH_1
  | Msg_userauth_info_request _    -> MSG_USERAUTH_1
  | Msg_userauth_info_response _   -> MSG_USERAUTH_2
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

let pp_lang ppf lang =
  if lang = "" then () else Fmt.pf ppf "(lang %s)" lang

let pp_message ppf = function
  | Msg_disconnect (code, desc, lang) ->
    Fmt.pf ppf "disconnect %s %s%a" (disconnect_code_to_string code) desc
      pp_lang lang
  | Msg_ignore d -> Fmt.pf ppf "ignore %s" d
  | Msg_unimplemented y -> Fmt.pf ppf "unimplemented %lu" y
  | Msg_debug (display, msg, lang) ->
    Fmt.pf ppf "debug (display %B) %s%a" display msg pp_lang lang
  | Msg_service_request s -> Fmt.pf ppf "service request %s" s
  | Msg_service_accept s -> Fmt.pf ppf "service accept %s" s
  | Msg_kexinit kex -> Fmt.pf ppf "kexinit %a" pp_kexinit kex
  | Msg_ext_info extensions ->
    Fmt.pf ppf "extensions [%a]"
      Fmt.(list pp_extension) extensions
  | Msg_newkeys -> Fmt.pf ppf "newkeys"
  | Msg_kexdh_init _z -> Fmt.pf ppf "KEX DH Init"
  | Msg_kexdh_reply (_hostkey, _z, (_alg, _share)) -> Fmt.pf ppf "KEX DH reply"
  | Msg_kexecdh_init _z -> Fmt.pf ppf "KEX ECDH Init"
  | Msg_kexecdh_reply (_hostkey, _z, (_alg, _share)) -> Fmt.pf ppf "KEX ECDH reply"
  | Msg_kexdh_gex_request (_a, _b, _c) -> Fmt.pf ppf "KEX DH gex request"
  | Msg_kexdh_gex_group (_z, _z2) -> Fmt.pf ppf "KEX DH gex group"
  | Msg_kexdh_gex_init _z -> Fmt.pf ppf "KEX DH gex init"
  | Msg_kexdh_gex_reply (_hostkey, _z, (_alg, _share)) -> Fmt.pf ppf "KEX DH gex reply"
  | Msg_kex (id, _) -> Fmt.pf ppf "KEX %u" (message_id_to_int id)
  | Msg_userauth_request (user, service, auth) ->
    Fmt.pf ppf "userauth request %s (service %s) %a" user service pp_auth_method auth
  | Msg_userauth_failure (methods, partial) ->
    Fmt.pf ppf "userauth failure (partial %B) %a" partial
      Fmt.(list ~sep:(any ", ") string) methods
  | Msg_userauth_success -> Fmt.pf ppf "userauth success"
  | Msg_userauth_banner (msg, lang) ->
    Fmt.pf ppf "userauth banner%a %s" pp_lang lang msg
  | Msg_userauth_1 _ -> Fmt.pf ppf "userauth 1"
  | Msg_userauth_2 _ -> Fmt.pf ppf "userauth 2"
  | Msg_userauth_pk_ok _ -> Fmt.pf ppf "userauth pk ok"
  | Msg_userauth_info_request _ -> Fmt.pf ppf "userauth info request"
  | Msg_userauth_info_response _ -> Fmt.pf ppf "userauth info response"
  | Msg_global_request _ -> Fmt.pf ppf "global request"
  | Msg_request_success _ -> Fmt.pf ppf "request success"
  | Msg_request_failure -> Fmt.pf ppf "request failure"
  | Msg_channel_open _ -> Fmt.pf ppf "channel open"
  | Msg_channel_open_confirmation _-> Fmt.pf ppf "channel open confirmation"
  | Msg_channel_open_failure _ -> Fmt.pf ppf "channel open failure"
  | Msg_channel_window_adjust _ -> Fmt.pf ppf "channel window adjust"
  | Msg_channel_data _ -> Fmt.pf ppf "channel data"
  | Msg_channel_extended_data _ -> Fmt.pf ppf "channel extended data"
  | Msg_channel_eof _ -> Fmt.pf ppf "channel eof"
  | Msg_channel_close _ -> Fmt.pf ppf "channel close"
  | Msg_channel_request _ -> Fmt.pf ppf "channel request"
  | Msg_channel_success _ -> Fmt.pf ppf "channel success"
  | Msg_channel_failure _ -> Fmt.pf ppf "channel failure"
  | Msg_version v -> Fmt.pf ppf "version %s" v

let message_to_int msg = message_id_to_int (message_to_id msg)

let disconnect_msg code s =
  Msg_disconnect (code, s, "")
