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
open Ssh_wire

type state =
  | Version_exchange       (* Handling client version *)
  | Key_exchange           (* Exchanging keys *)

type t = {
  state : state;
  buffer : Cstruct.t;
  peer_version : string;
}

let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let version_banner = "SSH-2.0-awa_ssh_0.1\r\n"

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

let pick_common ~server ~client =
  find_some_list (fun x -> List.mem x server) client

(* Pick into buffer.buffer and try to pop a packet *)
let extract_pkt t =
  let open Usane in
  if Cstruct.len t.buffer < 2 then
    None
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
      None
    else
      let payload_len, u1 = Uint32.(sub pkt_len pad_len) in
      let payload_len, u2 = Uint32.pred payload_len in
      if u1 || u2 then
        invalid_arg (Printf.sprintf "Bad payload_len %ld\n" payload_len);
      Some
        ((Cstruct.set_len buffer (Int32.to_int payload_len)),
         {t with buffer = Cstruct.shift buffer (Int32.to_int pkt_len)})

let supported_kex = {
  cookie = "";
  kex_algorithms = [ "diffie-hellman-group1-sha1";
                     "diffie-hellman-group14-sha1" ];
  server_host_key_algorithms = [];
  encryption_algorithms_ctos = [ "aes128-ctr" ];
  encryption_algorithms_stoc = [ "aes128-ctr" ];
  mac_algorithms_ctos = [ "hmac-sha1" ];
  mac_algorithms_stoc = [ "hmac-sha1" ];
  compression_algorithms_ctos = [ "none" ];
  compression_algorithms_stoc = [ "none" ];
  languages_ctos = [];
  languages_stoc = [];
  first_kex_packet_follows = false;
}

let make_kex_pkt cookie =
  if (String.length cookie) <> 16 then invalid_arg "Bad cookie len";
  { supported_kex with cookie }

let handle_key_exchange t pkt =
  t

let handle t = match t.state with
  | Version_exchange -> handle_version_exchange t  (* We're waiting for the banner *)
  | Key_exchange -> match extract_pkt t with       (* We're negotiatiating cipher/mac *)
    | None -> t
    | Some (buf, t) ->
      if (message_id_of_buf buf) <> (Some SSH_MSG_KEXINIT) then
        invalid_arg "Not SSH_MSG_KEXINIT";
      handle_key_exchange t (kex_of_buf buf)
