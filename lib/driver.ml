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

(*
 * NOTICE: This is a highly experimental Driver for Awa.
 *)

type t = {
  server         : Server.t;            (* Underlying server *)
  input_buffer   : Cstruct.t;           (* Unprocessed input *)
  write_cb       : Cstruct.t -> unit;   (* Blocking write callback *)
  read_cb        : unit -> Cstruct.t;   (* Blocking read callback *)
  time_cb        : unit -> Mtime.t;     (* Monotonic time in ns *)
}

let send_msg t msg =
  let* server, msg_buf = Server.output_msg t.server msg in
  Printf.printf ">>> %s\n%!" (Fmt.to_to_string Ssh.pp_message msg);
  t.write_cb msg_buf;
  Ok { t with server }

let rec send_msgs t = function
  | msg :: msgs ->
    let* t = send_msg t msg in
    send_msgs t msgs
  | [] -> Ok t

let of_server server msgs write_cb read_cb time_cb =
  let t = { server;
            input_buffer = Cstruct.create 0;
            write_cb;
            read_cb;
            time_cb }
  in
  send_msgs t msgs

let rekey t =
  match Server.rekey t.server with
  | None -> Ok t
  | Some (server, kexinit) -> send_msg { t with server } kexinit

let rec poll t =
  Printf.printf "poll called, input buffer %d\n%!"
    (Cstruct.length t.input_buffer);
  let now = t.time_cb () in
  let server = t.server in
  let* server, msg, input_buffer = Server.pop_msg2 server t.input_buffer in
  match msg with
  | None ->
    Printf.printf "no msg :/, input %d\n%!" (Cstruct.length input_buffer);
    let input_buffer = cs_join input_buffer (t.read_cb ()) in
    poll { t with server; input_buffer }
  | Some msg ->
    Printf.printf "<<< %s\n%!" (Fmt.to_to_string Ssh.pp_message msg);
    let* server, replies, event = Server.input_msg server msg now in
    let t = { t with server; input_buffer } in
    let* t = send_msgs t replies in
    match event with
    | None -> poll t
    | Some event -> Ok (t, event)

let send_channel_data t id data =
  let* server, msgs = Server.output_channel_data t.server id data in
  send_msgs { t with server } msgs

let disconnect t =
  send_msg t (Ssh.disconnect_msg Ssh.DISCONNECT_BY_APPLICATION
                "user disconnected")
