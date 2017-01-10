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

[%%cstruct
type pkt_hdr = {
  pkt_len: uint32_t;
  pad_len: uint8_t;
} [@@big_endian]]

let trap_error f x =
  try return (f x) with
  | Invalid_argument e -> error e
  | Failure e -> error e

(* let guard p e = if p then ok () else error e *)

let safe_shift buf off =
  trap_error (fun () -> Cstruct.shift buf off) ()

(** {2 Version exchange parser.} *)

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
              ok (Some (buf, peer_version))
      | _ -> scan start (succ off)
  in
  if len < 2 then
    not_found
  else
    scan 0 1

(** {2 Fetch the first packet and walk the buffer .} *)
let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let scan_pkt buf =
  let open Usane in
  let len = Cstruct.len buf in
  let partial () =
    if len < (1024 * 64) then
      None
    else
      invalid_arg "Buffer is too big"
  in
  let wrap () =
    (* Using pad_len as int32 saves us a lot of conversions. *)
    let pkt_len = get_pkt_hdr_pkt_len buf in
    let pad_len = Int32.of_int (get_pkt_hdr_pad_len buf) in
    if pkt_len = Int32.zero || Uint32.(pkt_len >= max_pkt_len) then
      invalid_arg "Bad pkt_len"
    else if Uint32.(pad_len >= pkt_len) then
      invalid_arg "Bad pad_len";
    let buf = Cstruct.shift buf sizeof_pkt_hdr in
    let len = Cstruct.len buf in
    (* This is a partial packet, hold onto t *)
    if Uint32.(pkt_len > (of_int len)) then
      partial ()
    else
      let payload_len, u1 = Uint32.(sub pkt_len pad_len) in
      let payload_len, u2 = Uint32.pred payload_len in
      if u1 || u2 then
        invalid_arg "Bad payload_len";
      Some (Cstruct.set_len buf (Int32.to_int payload_len))
  in
  if len < 2 then
    ok None
  else trap_error wrap ()

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

let assert_message_id buf msgid =
  assert ((message_id_of_buf buf) = Some msgid)

(** {2 Conversions on primitives.} *)

let string_of_buf buf off =
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf off |> Int32.to_int in
      (Cstruct.copy buf (off + 4) len), len) ()

let buf_of_string s =
  let len = String.length s in
  (* XXX string cant be longer than uint8  *)
  let buf = Cstruct.create (len + 4) in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int len);
  Cstruct.blit_from_string s 0 buf 4 len;
  buf

let uint32_of_buf buf off =
  trap_error (fun () -> Cstruct.BE.get_uint32 buf off) ()

let buf_of_uint32 v =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 v;
  buf

let bool_of_buf buf off =
  trap_error (fun () -> (Cstruct.get_uint8 buf 0) <> 0) ()

let buf_of_bool b =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 (if b then 1 else 0);
  buf

(** {2 Name lists as in RFC4251 5.} *)

let buf_of_nl nl =
  buf_of_string (String.concat "," nl)

let nl_of_buf buf off =
  string_of_buf buf off >>= fun (s, len) ->
  ok ((Str.split (Str.regexp ",") s), len)

let nll_of_buf buf n =
  let rec loop buf l tlen =
    if (List.length l) = n then
      ok (List.rev l, tlen)
    else
      nl_of_buf buf 0 >>= fun (nl, len) ->
      safe_shift buf (len + 4) >>= fun buf ->
      loop buf (nl :: l) (len + tlen + 4)
  in
  loop buf [] 0

(** {2 SSH_MSG_DISCONNECT RFC4253 11.1.} *)

let buf_of_disconnect code desc lang =
  let code = buf_of_uint32 code in
  let desc = buf_of_string desc in
  let lang = buf_of_string lang in
  Cstruct.concat [buf_of_message_id SSH_MSG_KEXINIT; code; desc; lang]

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
  let head = buf_of_message_id SSH_MSG_KEXINIT in
  let cookie = Cstruct.create 16 in
  assert ((String.length kex.cookie) = 16);
  Cstruct.blit_from_string kex.cookie 0 cookie 0 16;
  let tail = Cstruct.create 5 in  (* first_kex_packet_follows + reserved *)
  Cstruct.set_uint8 tail 0 (if kex.first_kex_packet_follows then 1 else 0);
  Cstruct.concat [head; cookie; nll; tail]

(** {2 SSH_MSG_USERAUTH_REQUEST RFC4252 5.} *)

(* TODO, variable len *)

(** {2 SSH_MSG_USERAUTH_FAILURE RFC4252 5.1} *)

let buf_of_userauth_failure nl psucc =
  let head = buf_of_message_id SSH_MSG_USERAUTH_FAILURE in
  Cstruct.concat [head; buf_of_nl nl; buf_of_bool psucc]

(** {2 SSH_MSG_GLOBAL_REQUEST RFC4254 4.} *)

(* TODO, variable len *)

(** {2 High level representation of messages, one for each message_id. } *)

type message =
  | Ssh_msg_disconnect of (int32 * string * string)
  | Ssh_msg_ignore of (string * int)
  | Ssh_msg_unimplemented of int32
  | Ssh_msg_debug of (bool * string * string)
  | Ssh_msg_service_request of (string * int)
  | Ssh_msg_service_accept of (string * int)
  | Ssh_msg_kexinit of kex_pkt
  | Ssh_msg_newkeys
  | Ssh_msg_userauth_request
  | Ssh_msg_userauth_failure of (string list * bool)
  | Ssh_msg_userauth_success
  | Ssh_msg_userauth_banner of (string * string)
  | Ssh_msg_global_request
  | Ssh_msg_request_success
  | Ssh_msg_request_failure
  | Ssh_msg_channel_open
  | Ssh_msg_channel_open_confirmation
  | Ssh_msg_channel_open_failure
  | Ssh_msg_channel_window_adjust
  | Ssh_msg_channel_data
  | Ssh_msg_channel_extended_data
  | Ssh_msg_channel_eof
  | Ssh_msg_channel_close
  | Ssh_msg_channel_request
  | Ssh_msg_channel_success
  | Ssh_msg_channel_failure

let message_of_buf buf =
  match message_id_of_buf buf with
  | None -> error "Unknown message id"
  | Some msgid ->
    let unimplemented () =
      error (Printf.sprintf "Message %d unimplemented" (message_id_to_int msgid))
    in
    match msgid with
    | SSH_MSG_DISCONNECT ->
      uint32_of_buf buf 1 >>= fun code ->
      string_of_buf buf 5 >>= fun (desc, len) ->
      string_of_buf buf (len + 9) >>= fun (lang, _) ->
      ok (Ssh_msg_disconnect (code, desc, lang))
    | SSH_MSG_IGNORE ->
      string_of_buf buf 1 >>= fun x ->
      ok (Ssh_msg_ignore x)
    | SSH_MSG_UNIMPLEMENTED ->
      uint32_of_buf buf 1 >>= fun x ->
      ok (Ssh_msg_unimplemented x)
    | SSH_MSG_DEBUG ->
      bool_of_buf buf 1 >>= fun always_display ->
      string_of_buf buf 2 >>= fun (message, len) ->
      string_of_buf buf (len + 6) >>= fun (lang, _) ->
      ok (Ssh_msg_debug (always_display, message, lang))
    | SSH_MSG_SERVICE_REQUEST ->
      string_of_buf buf 1 >>= fun x -> ok (Ssh_msg_service_request x)
    | SSH_MSG_SERVICE_ACCEPT ->
      string_of_buf buf 1 >>= fun x -> ok (Ssh_msg_service_accept x)
    | SSH_MSG_KEXINIT ->
        safe_shift buf 17 >>= fun nllbuf ->
        nll_of_buf nllbuf 10 >>= fun (nll, nll_len) ->
        bool_of_buf buf nll_len >>= fun first_kex_packet_follows ->
        ok (Ssh_msg_kexinit
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
                first_kex_packet_follows; })
    | SSH_MSG_NEWKEYS -> ok Ssh_msg_newkeys
    | SSH_MSG_USERAUTH_REQUEST -> unimplemented ()
    | SSH_MSG_USERAUTH_FAILURE ->
      nl_of_buf buf 1 >>= fun (nl, len) ->
      bool_of_buf buf len >>= fun psucc ->
      ok (Ssh_msg_userauth_failure (nl, psucc))
    | SSH_MSG_USERAUTH_SUCCESS -> unimplemented ()
    | SSH_MSG_USERAUTH_BANNER ->
      string_of_buf buf 1 >>= fun (s1, len1) ->
      string_of_buf buf (len1 + 5) >>= fun (s2, _) ->
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
