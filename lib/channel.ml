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

let src = Logs.Src.create "awa.channel" ~doc:"AWA channel"
module Log = (val Logs.src_log src : Logs.LOG)

(*
 * Channel entry
 *)

type state = Open | Sent_close

type channel_end = {
  id       : int;
  win      : int;
  max_pkt  : int;
}

type channel = {
  us    : channel_end;
  them  : channel_end;
  state : state;
  tosend: string;
}

let compare a b =
  Int.compare a.us.id b.us.id

type t = channel

module Ordered = struct
  type t = channel
  let compare = compare
end

let make_end id win max_pkt = { id; win; max_pkt }

let make ~us ~them = { us; them; state = Open; tosend = "" }

let maybe_split off data =
  if off < String.length data then
    String.sub data 0 off, (String.length data - off)
  else
    data, 0

(* Returns new t, data normalized, and adjust window if <> zero *)
let input_data t data =
  (* Normalize data, discard if greater than window *)
  let len = min (String.length data) t.us.win in
  let data, left = maybe_split len data in
  if left > 0 then
    Log.warn (fun m -> m "channel input_data: discarding %d bytes (window size)"
                 left);
  let new_win = t.us.win - len in
  let* () = guard (new_win >= 0) "window underflow" in
  let win, adjust =
    if new_win < Ssh.channel_win_adj_threshold then
      Ssh.channel_win_len, Ssh.channel_win_len - new_win
    else
      new_win, 0
  in
  let* () = guard (adjust >= 0) "adjust underflow" in
  let t = { t with us = { t.us with win } } in
  let msg = if adjust <> 0 then
      Some (Ssh.Msg_channel_window_adjust (t.them.id, adjust))
    else
      None
  in
  Ok (t, data, msg)

let output_data ~flush t data =
  let fragment data =
    let rec go off =
      if String.length data - off > t.them.max_pkt then
        let frag = String.sub data off t.them.max_pkt in
        Ssh.Msg_channel_data (t.them.id, frag) :: go (off + t.them.max_pkt)
      else
        let frag = String.sub data off (String.length data - off) in
        [ Ssh.Msg_channel_data (t.them.id, frag) ]
    in
    go 0
  in
  let tosend =
    if String.length t.tosend > 0 then
      t.tosend ^ data
    else
      data
  in
  let len = min (String.length tosend) t.them.win in
  let data, tosend =
    if flush then
      tosend, ""
    else
      let data, left = maybe_split len tosend in
      data, String.sub tosend len left
  in
  let win = t.them.win - len in
  let* () = guard (win >= 0) "window underflow" in
  let t = { t with tosend; them = { t.them with win } } in
  Ok (t, fragment data)

let flush t =
  let data = t.tosend in
  let t = { t with tosend = "" } in
  output_data ~flush:true t data

let adjust_window t len =
  let win = t.them.win + len in
  (* XXX this does not handle up to 4GB correctly. *)
  let* () = guard (win > 0) "window overflow" in
  let data = t.tosend in
  let t = { t with tosend = ""; them = { t.them with win } } in
  output_data ~flush:true t data

(*
 * Channel database
 *)

module Channel_map = Map.Make(Int)

type db = channel Channel_map.t

let empty_db = Channel_map.empty

let is_empty = Channel_map.is_empty

(* Find the next available free channel *)
let next_free db =
  let rec linear lkey = function
    | [] -> None
    | hd :: tl ->
      let key = fst hd in
      (* Find a hole *)
      if succ lkey <> key then
        Some (succ lkey)
      else
        linear key tl
  in
  match Channel_map.max_binding_opt db with
  | None -> Some 0
  | Some (key, _) ->
    (* If max binding is not max key *)
    if key <> (Ssh.max_channels - 1) then
      Some (succ key)
    else
      linear (-1) (Channel_map.bindings db)

let add ~id ~win ~max_pkt db =
  (* Find the next available free channel *)
  match next_free db with
  | None -> Error `No_channels_left
  | Some key ->
    let them = make_end id win max_pkt in
    let us = make_end key Ssh.channel_win_len Ssh.channel_max_pkt_len in
    let c = make ~us ~them in
    Ok (c, Channel_map.add key c db)

let update c db = Channel_map.add c.us.id c db

let remove id db = Channel_map.remove id db

let lookup id db = Channel_map.find_opt id db

let id c = c.us.id

let their_id c = c.them.id
