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

let version_banner = "SSH-2.0-awa_ssh_0.1\r\n"

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

let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let add_buf t buf =
  { state = t.state;
    buffer = Cstruct.append t.buffer buf;
    peer_version = t.peer_version }

let make () =
  ({ state = Version_exchange;
     buffer = Cstruct.create 0;
     peer_version = "unknown" },
   Cstruct.of_string version_banner)

let find_some f = try Some (f ()) with Not_found -> None

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
          failwith "Version line is too short"
        else
          let tokens = Str.split_delim (Str.regexp "-") line in
          if List.length tokens <> 3 then
            failwith "Can't parse version line";
          let version = List.nth tokens 1 in
          let peer_version = List.nth tokens 2 in
          if version <> "2.0" then
            failwith ("Bad version " ^ version);
          { state = Key_exchange;
            buffer = Cstruct.shift t.buffer (succ off);
            peer_version }
      | _ -> scan start (succ off)
  in
  if len < 2 then
    t
  else
    scan 0 1

let handle_key_exchange t =
  if Cstruct.len t.buffer < 2 then
    t
  else
    (* Using pad_len as int32 saves us a lot of conversions. *)
    let pkt_len = get_pkt_hdr_pkt_len t.buffer in
    let pad_len = Int32.of_int (get_pkt_hdr_pad_len t.buffer) in
    (* Remember, ocaml has no unsigned, so we must cmp <= Int32.zero *)
    if pkt_len <= Int32.zero || pkt_len > max_pkt_len then
      failwith (Printf.sprintf "Bad pkt_len %ld\n" pkt_len)
    else if pad_len >= pkt_len then
      failwith (Printf.sprintf "Bad pad_len %ld\n" pad_len);
    let buffer = Cstruct.shift t.buffer sizeof_pkt_hdr in
    (* This is a partial packet, hold onto t *)
    (* XXX Remember pkt_len doesn't include mac *)
    if pkt_len < (Int32.of_int (Cstruct.len buffer)) then
      t
    else
      let payload_len = Int32.sub (Int32.sub pkt_len pad_len) Int32.one in
      (* There is no way for payload_len to be less than zero, but be paranoid. *)
      if payload_len <= Int32.zero then
        failwith (Printf.sprintf "Bad payload_len %ld\n" payload_len);
      t

let handle t = match t.state with
  | Version_exchange -> handle_version_exchange t  (* We're waiting for the banner *)
  | Key_exchange -> handle_key_exchange t          (* We're negotiatiating cipher/mac *)
