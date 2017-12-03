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
open Util

(*
 * NOTICE: This is a highly experimental Driver for Awa.
 *)

type t = {
  server         : Server.t;            (* Underlying  *)
  input_buffer   : Cstruct.t;           (* Unprocessed input *)
  write_cb       : Cstruct.t -> unit;   (* Blocking write callback *)
  read_cb        : unit -> Cstruct.t;   (* Blocking read callback *)
}

let send_msg t msg =
  Server.output_msg t.server msg >>= fun (server, msg_buf) ->
  Printf.printf ">>> %s\n%!" (Ssh.message_to_string msg);
  t.write_cb msg_buf;
  ok { t with server }

let send_msgs t msgs =
  List.fold_left
    (fun t msg ->
       match t with
       | Ok t -> send_msg t msg
       | Error e -> error e)
    (ok t) msgs

let of_server server msgs write_cb read_cb =
  let t = { server; input_buffer = Cstruct.create 0; write_cb; read_cb } in
  send_msgs t msgs

let maybe_rekey t now =
  let s = t.server in
  if not (Kex.should_rekey s.Server.keys_stoc now) ||
     s.Server.keying then
    ok t
  else
    Server.rekey s now >>= fun (s, kexinit) ->
    let t = { t with server = s } in
    send_msg t (Ssh.Msg_kexinit kexinit)

let rec poll t now =
  let server = t.server in
  Server.pop_msg2 server t.input_buffer >>= fun (server, msg, input_buffer) ->
  match msg with
  | None ->
    let input_buffer = cs_join input_buffer (t.read_cb ()) in
    poll { t with server; input_buffer } now
  | Some msg ->
    Printf.printf "<<< %s\n%!" (Ssh.message_to_string msg);
    Server.input_msg server msg now >>= fun (server, replies, event) ->
    let t = { t with server; input_buffer } in
    send_msgs t replies >>= fun t ->
    (match event with
      | None -> poll t now (* XXX now is WRONG HERE ! *)
      | Some event -> ok (t, event))

let send_channel_data t id data =
  match Channel.lookup id t.server.Server.channels with
  | None -> error "No such channel"
  | Some c -> send_msg t (Ssh.Msg_channel_data (Channel.their_id c, data))

let disconnect t =
  send_msg t (Ssh.disconnect_msg Ssh.DISCONNECT_BY_APPLICATION
                "user disconnected")
