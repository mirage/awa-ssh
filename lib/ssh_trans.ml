(*
 * Copyright (c) 2016 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

type state =
  | Version_exchange       (* Handling client version *)
  | Key_exchange           (* Exchanging keys *)

type t = {
  state : state;
  buffer : Cstruct.t;
  peer_version : string;
}

[%%cstruct
type pkt_hdr = {
  pkt_len: uint32_t;
  pad_len: uint8_t;
} [@@big_endian]]

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


let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let version_banner = "SSH-2.0-awa_ssh_0.1\r\n"
let version_banner_buf = Cstruct.of_string version_banner

let add_buf t buf =
  { t with buffer = Cstruct.append t.buffer buf }

let make () =
  { state = Version_exchange;
    buffer = Cstruct.create 0;
    peer_version = "unknown" }

let find_some f = try Some (f ()) with Not_found -> None
let find_some_list f l = try Some (List.find f l)  with Not_found -> None

let handle_version_exchange t =
  assert (t.state = Version_exchange);
  let s = Cstruct.to_string t.buffer in
  let len = String.length s in
  let rec scan start off =
    if off = len then
      { t with buffer = Cstruct.shift t.buffer start }
    else
      match (String.get s (pred off), String.get s off) with
      | ('\r', '\n') ->
        let line = String.sub s start (off - start - 1) in
        if String.length line < 4 ||
           String.sub line 0 4 <> "SSH-" then
          scan (succ off) (succ off)
        else if (String.length line < 9) then
          invalid_arg "Version line is too short"
        else
          let tokens = Str.split_delim (Str.regexp "-") line in
          if List.length tokens <> 3 then
            invalid_arg "Can't parse version line";
          let version = List.nth tokens 1 in
          let peer_version = List.nth tokens 2 in
          if version <> "2.0" then
            invalid_arg ("Bad version " ^ version);
          { state = Key_exchange;
            buffer = Cstruct.shift t.buffer (succ off);
            peer_version }
      | _ -> scan start (succ off)
  in
  if len < 2 then
    t
  else
    scan 0 1

type kex_pkt = {
  cookie : string;
  kex_algorithms : string list;
  server_host_key_algorithms : string list;
  encryption_algorithms_client_to_server : string list;
  encryption_algorithms_server_to_client : string list;
  mac_algorithms_client_to_server : string list;
  mac_algorithms_server_to_client : string list;
  compression_algorithms_client_to_server : string list;
  compression_algorithms_server_to_client : string list;
  languages_client_to_server : string list;
  languages_server_to_client : string list;
  first_kex_packet_follows : bool
} [@@deriving sexp]

(* Parse a name list as in RFC4251 5. *)
let buf_of_namelist nl =
  let s = String.concat "," nl in
  let slen = String.length s in
  let buf = Cstruct.create (4 + slen) in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int slen);
  Cstruct.blit_from_string s 0 buf 4 slen;
  buf

let namelist_of_buf buf =
  let len = Cstruct.BE.get_uint32 buf 0 in
  if Usane.Uint32.(Int32.of_int (Cstruct.len buf) < len) then
    invalid_arg "Buffer len doesn't match name-list len";
  Str.split (Str.regexp ",") (Cstruct.copy buf 4 (Int32.to_int len))

let pick_common ~server ~client =
  find_some_list (fun x -> List.mem x server) client

let buf_of_kex kex =
  let f = buf_of_namelist in
  let nll = Cstruct.concat
    [ f kex.kex_algorithms;
      f kex.server_host_key_algorithms;
      f kex.encryption_algorithms_client_to_server;
      f kex.encryption_algorithms_server_to_client;
      f kex.mac_algorithms_client_to_server;
      f kex.mac_algorithms_server_to_client;
      f kex.compression_algorithms_client_to_server;
      f kex.compression_algorithms_server_to_client;
      f kex.languages_client_to_server;
      f kex.languages_server_to_client; ]
  in
  let head = Cstruct.create 17 in (* message code + cookie *)
  Cstruct.set_uint8 head 0 (message_id_to_int SSH_MSG_KEXINIT);
  Cstruct.blit_from_string kex.cookie 0 head 1 (String.length kex.cookie);
  let tail = Cstruct.create 5 in  (* first_kex_packet_follows + reserved *)
  Cstruct.set_uint8 tail 0 (if kex.first_kex_packet_follows then 1 else 0);
  Cstruct.concat [head; nll; tail]

let kex_of_buf buf =
  let rec loop buf l tlen =
    if (List.length l) = 10 then
      (List.rev l, tlen)
    else
      let len = Int32.to_int (Cstruct.BE.get_uint32 buf 0) in
      let nl = namelist_of_buf buf in
      loop (Cstruct.shift buf (len + 4)) (nl :: l) (len + tlen + 4)
  in
  if (Cstruct.get_uint8 buf 0) <> (message_id_to_int SSH_MSG_KEXINIT) then
    invalid_arg "message id is not SSH_MSG_KEXINIT";
  (* Jump over msg id and cookie *)
  let nll, nll_len = loop (Cstruct.shift buf 17) [] 0 in
  let first_kex_packet_follows = (Cstruct.get_uint8 buf nll_len) <> 0 in
  { cookie = Cstruct.copy buf 1 16;
    kex_algorithms = List.nth nll 0;
    server_host_key_algorithms = List.nth nll 1;
    encryption_algorithms_client_to_server = List.nth nll 2;
    encryption_algorithms_server_to_client = List.nth nll 3;
    mac_algorithms_client_to_server = List.nth nll 4;
    mac_algorithms_server_to_client = List.nth nll 5;
    compression_algorithms_client_to_server = List.nth nll 6;
    compression_algorithms_server_to_client = List.nth nll 7;
    languages_client_to_server = List.nth nll 8;
    languages_server_to_client = List.nth nll 9;
    first_kex_packet_follows; }

let handle_key_exchange t =
  let open Usane in
  if Cstruct.len t.buffer < 2 then
    t
  else
    (* Using pad_len as int32 saves us a lot of conversions. *)
    let pkt_len = get_pkt_hdr_pkt_len t.buffer in
    let pad_len = Int32.of_int (get_pkt_hdr_pad_len t.buffer) in
    if pkt_len = Int32.zero || Uint32.(pkt_len >= max_pkt_len) then
      invalid_arg (Printf.sprintf "Bad pkt_len %ld\n" pkt_len)
    else if Uint32.(pad_len >= pkt_len) then
      invalid_arg (Printf.sprintf "Bad pad_len %ld\n" pad_len);
    let buffer = Cstruct.shift t.buffer sizeof_pkt_hdr in
    (* This is a partial packet, hold onto t *)
    if Uint32.(pkt_len > (of_int (Cstruct.len buffer))) then
      t
    else
      let payload_len, u1 = Uint32.(sub pkt_len pad_len) in
      let payload_len, u2 = Uint32.pred payload_len in
      if u1 || u2 then
        invalid_arg (Printf.sprintf "Bad payload_len %ld\n" payload_len);
      let kex_pkt = kex_of_buf (Cstruct.set_len buffer (Int32.to_int payload_len)) in
      (* Safe since we know pkt_len is < max_pkt_len and > 0 *)
      { t with buffer = Cstruct.shift buffer (Int32.to_int pkt_len) }

let handle t = match t.state with
  | Version_exchange -> handle_version_exchange t  (* We're waiting for the banner *)
  | Key_exchange -> handle_key_exchange t          (* We're negotiatiating cipher/mac *)
