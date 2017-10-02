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

module Channel_map = Map.Make(Int32)

type t = Channel.t Channel_map.t

let make () =
  Channel_map.empty

(* Find the next available free channel *)
let next_free t =
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
  match Channel_map.max_binding_opt t with
  | None -> Some Int32.zero
  | Some (key, _) ->
    (* If max binding is not max key *)
    if key <> (Int32.of_int (Ssh.max_channels - 1)) then
      Some (Int32.succ key)
    else
      linear Int32.minus_one (Channel_map.bindings t)

let add ~id ~win ~max_pkt t =
  (* Find the next available free channel *)
  match next_free t with
  | None -> error `No_channels_left
  | Some key ->
    let them = Channel.make_end id win max_pkt in
    let us = Channel.make_end key
        (Int32.of_int Ssh.channel_win_len)
        (Int32.of_int Ssh.channel_max_pkt_len)
    in
    let c = Channel.make ~us ~them in
    ok (c, Channel_map.add key c t)

let lookup id t =
  Channel_map.find_opt id t
