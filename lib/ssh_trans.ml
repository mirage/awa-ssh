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
  | New                         (* TCP established *)
  | Version_exchanged           (* We received theirs version_banner *)

type t = {
  state : state;
  buffer : Cstruct.t;
  peer_client : string;
}

let add_buf t buf =
  { state = t.state;
    buffer = Cstruct.append t.buffer buf;
    peer_client = t.peer_client }

let make () =
  ({ state = New;
     buffer = Cstruct.create 0;
     peer_client = "unknown" },
   Cstruct.of_string version_banner)

let find_some f = try Some (f ()) with Not_found -> None

let process_new t =
  assert (t.state = New);
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
          let peer_client = List.nth tokens 2 in
          if version <> "2.0" then
            failwith ("Bad version " ^ version);
          { state = Version_exchanged;
            buffer = Cstruct.shift t.buffer (succ off);
            peer_client }
      | _ -> scan start (succ off)
  in
  if len < 2 then
    t
  else
    scan 0 1

let process t = match t.state with
  | New -> process_new t  (* We're waiting for the banner *)
  | _ -> failwith "todo"
