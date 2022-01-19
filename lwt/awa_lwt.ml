(*
 * Copyright (c) 2018 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

open Lwt.Infix

type nexus_msg =
  | Rekey
  | Net_eof
  | Net_io of Cstruct.t
  | Sshout of (int32 * Cstruct.t)
  | Ssherr of (int32 * Cstruct.t)

type sshin_msg = [
  | `Data of Cstruct.t
  | `Eof
]

type channel = {
  cmd         : string;
  id          : int32;
  sshin_mbox  : sshin_msg Lwt_mvar.t;
  exec_thread : unit Lwt.t;
}

type exec_callback =
  string ->                     (* cmd *)
  (unit -> sshin_msg Lwt.t) ->  (* sshin *)
  (Cstruct.t -> unit Lwt.t) ->  (* sshout *)
  (Cstruct.t -> unit Lwt.t) ->  (* ssherr *)
  unit Lwt.t

type t = {
  exec_callback  : exec_callback;       (* callback to run on exec *)
  channels       : channel list;        (* Opened channels *)
  nexus_mbox     : nexus_msg Lwt_mvar.t;(* Nexus mailbox *)
}

let wrapr = function
  | Ok x -> Lwt.return x
  | Error e -> Lwt.fail_invalid_arg e

let send_msg fd server msg =
  wrapr (Awa.Server.output_msg server msg)
  >>= fun (server, msg_buf) ->
  Lwt_io.printf ">>> %s\n%!" (Awa.Ssh.message_to_string msg)
  >>= fun () ->
  Lwt_unix.write fd (Cstruct.to_bytes msg_buf) 0 (Cstruct.length msg_buf)
  >>= fun n ->
  assert (n = Cstruct.length msg_buf);
  Lwt.return server

let rec send_msgs fd server = function
  | msg :: msgs ->
    send_msg fd server msg
    >>= fun server ->
    send_msgs fd server msgs
  | [] -> Lwt.return server

let net_read fd =
  let lwtbuf = Bytes.create 4096 in (* XXX revise *)
  Lwt_unix.read fd lwtbuf 0 4096 >>= fun n ->
  assert (n >= 0); (* handle exception ! ! *)
  if n = 0 then
    Lwt.return Net_eof
  else
    let () = assert (n > 0) in          (* XXX *)
    let buf = Cstruct.create n in
    Cstruct.blit_from_bytes lwtbuf 0 buf 0 n;
    Lwt.return (Net_io buf)

let sshin_eof c =
  Lwt_mvar.put c.sshin_mbox `Eof

let sshin_data c data =
  Lwt_mvar.put c.sshin_mbox (`Data data)

let lookup_channel t id =
  List.find_opt (fun c -> id = c.id) t.channels

let rec nexus t fd server input_buffer =
  wrapr (Awa.Server.pop_msg2 server input_buffer)
  >>= fun (server, msg, input_buffer) ->
  match msg with
  | None -> (* No SSH msg *)
    Lwt.catch
      (fun () ->
         Lwt.pick [ Lwt_mvar.take t.nexus_mbox;
                    net_read fd;
                    Lwt_unix.timeout (float_of_int 2) ])
      (function Lwt_unix.Timeout -> Lwt.return Rekey | exn -> Lwt.fail exn)
    >>= fun nexus_msg ->
    (match nexus_msg with
     | Rekey ->
       (match Awa.Server.maybe_rekey server (Mtime_clock.now ()) with
        | None -> nexus t fd server input_buffer
        | Some (server, kexinit) ->
          Lwt_io.printf "Rekeying\n%!" >>= fun () ->
          send_msg fd server kexinit
          >>= fun server ->
          nexus t fd server input_buffer)
     | Net_eof ->
       Lwt_io.printf "Got Net_eof\n%!" >>= fun () ->
       Lwt.return t
     | Net_io buf -> nexus t fd server (Awa.Util.cs_join input_buffer buf)
     | Sshout (id, buf) | Ssherr (id, buf) ->
       wrapr (Awa.Server.output_channel_data server id buf)
       >>= fun (server, msgs) ->
       send_msgs fd server msgs >>= fun server ->
       nexus t fd server input_buffer)
  | Some msg -> (* SSH msg *)
    Lwt_io.printf "<<< %s\n%!" (Awa.Ssh.message_to_string msg)
    >>= fun () ->
    wrapr (Awa.Server.input_msg server msg (Mtime_clock.now ()))
    >>= fun (server, replies, event) ->
    send_msgs fd server replies
    >>= fun server ->
    match event with
    | None -> nexus t fd server input_buffer
    | Some Awa.Server.Disconnected s ->
      Lwt_io.printf "Disconnected: %s\n%!" s >>= fun () ->
      Lwt_list.iter_p sshin_eof t.channels
      >>= fun () ->
      Lwt.return t
    | Some Awa.Server.Channel_eof id ->
      (match lookup_channel t id with
       | Some c -> sshin_eof c >>= fun () -> Lwt.return t
       | None -> Lwt.return t)
    | Some Awa.Server.Channel_data (id, data) ->
      (match lookup_channel t id with
       | Some c -> sshin_data c data
       | None -> Lwt.return_unit)
      >>= fun () ->
      nexus t fd server input_buffer
    | Some Awa.Server.Channel_subsystem (id, cmd) (* same as exec *)
    | Some Awa.Server.Channel_exec (id, cmd) ->
      (* Create an input box *)
      let sshin_mbox = Lwt_mvar.create_empty () in
      (* Create a callback for each mbox *)
      let sshin () = Lwt_mvar.take sshin_mbox in
      let sshout id buf = Lwt_mvar.put t.nexus_mbox (Sshout (id, buf)) in
      let ssherr id buf = Lwt_mvar.put t.nexus_mbox (Ssherr (id, buf)) in
      (* Create the execution thread *)
      let exec_thread = t.exec_callback cmd sshin (sshout id) (ssherr id) in
      let c = { cmd; id; sshin_mbox; exec_thread } in
      let t = { t with channels = c :: t.channels } in
      nexus t fd server input_buffer

let spawn_server server msgs fd exec_callback =
  let t = { exec_callback;
            channels = [];
            nexus_mbox = Lwt_mvar.create_empty () }
  in
  send_msgs fd server msgs >>= fun server ->
  nexus t fd server (Cstruct.create 0)
