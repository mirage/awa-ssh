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

open Rresult.R
open Sexplib.Conv

(*
 * Channel entry
 *)

type state = Open | Sent_close
[@@deriving sexp]

type channel_end = {
  id       : int32;
  win      : int32;
  max_pkt  : int32;
} [@@deriving sexp]

type channel = {
  us    : channel_end;
  them  : channel_end;
  state : state;
} [@@deriving sexp]

let compare a b =
  Int32.compare a.us.id b.us.id

type t = channel

module Ordered = struct
  type t = channel
  let compare = compare
end

let make_end id win max_pkt = { id; win; max_pkt }

let make ~us ~them = { us; them; state = Open }

let to_string t = Sexplib.Sexp.to_string_hum (sexp_of_channel t)

(*
 * Channel database
 *)

module Channel_map = Map.Make(Int32)

type db = channel Channel_map.t

let empty_db = Channel_map.empty

(* Find the next available free channel *)
let next_free db =
  let rec linear lkey = function
    | [] -> None
    | hd :: tl ->
      let key = fst hd in
      (* Find a hole *)
      if Int32.succ lkey <> key then
        Some (Int32.succ lkey)
      else
        linear key tl
  in
  match Channel_map.max_binding_opt db with
  | None -> Some Int32.zero
  | Some (key, _) ->
    (* If max binding is not max key *)
    if key <> (Int32.of_int (Ssh.max_channels - 1)) then
      Some (Int32.succ key)
    else
      linear Int32.minus_one (Channel_map.bindings db)

let add ~id ~win ~max_pkt db =
  (* Find the next available free channel *)
  match next_free db with
  | None -> error `No_channels_left
  | Some key ->
    let them = make_end id win max_pkt in
    let us = make_end key
        (Int32.of_int Ssh.channel_win_len)
        (Int32.of_int Ssh.channel_max_pkt_len)
    in
    let c = make ~us ~them in
    ok (c, Channel_map.add key c db)

let update c db = Channel_map.add c.us.id c db

let remove ~id db = Channel_map.remove id db

let lookup ~id db = Channel_map.find_opt id db

(*
 * User API
 *)

let accept_request c = Ssh.Msg_channel_success c.us.id

let deny_request c = Ssh.Msg_channel_failure c.us.id

let close c = Ssh.Msg_channel_close c.them.id

let data_msg c data = Ssh.Msg_channel_data (c.them.id, data)
