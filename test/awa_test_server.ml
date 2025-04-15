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

let () = Printexc.record_backtrace true

open Awa

module Driver = struct
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
    Logs.debug (fun m -> m ">>> %s" (Fmt.to_to_string Ssh.pp_message msg));
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
    Logs.info (fun m -> m "poll called, input buffer %d"
                  (Cstruct.length t.input_buffer));
    let now = t.time_cb () in
    let server = t.server in
    let* server, msg, input_buffer = Server.pop_msg2 server t.input_buffer in
    match msg with
    | None ->
      Logs.info (fun m -> m "no msg :/, input %d" (Cstruct.length input_buffer));
      let input_buffer = cs_join input_buffer (t.read_cb ()) in
      poll { t with server; input_buffer }
    | Some msg ->
      Logs.debug (fun m -> m "<<< %a" Ssh.pp_message msg);
      let* server, replies, event = Server.input_msg server msg now in
      let t = { t with server; input_buffer } in
      let* t = send_msgs t replies in
      match event with
      | None -> poll t
      | Some event -> Ok (t, event)

  let user_auth t userauth success =
    let* server, reply =
      if success then
        Awa.Server.accept_userauth t.server userauth
      else
        Awa.Server.reject_userauth t.server userauth
    in
    send_msg { t with server } reply

  let send_channel_data t id data =
    let* server, msgs = Server.output_channel_data t.server id data in
    send_msgs { t with server } msgs

  let disconnect t =
    send_msg t (Ssh.disconnect_msg Ssh.DISCONNECT_BY_APPLICATION
                  "user disconnected")
end

let ( let* ) = Result.bind

(* Driver callbacks  *)
let read_cstruct fd () =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    Logs.debug (fun m -> m "read %u bytes" (Cstruct.length cbuf));
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.length buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let echo t id data =
  Driver.send_channel_data t id data

let bc t id data =
  let len = Cstruct.length data in
  let line = Cstruct.sub data 0 (len - 1) |> Cstruct.to_string in
  let args = String.split_on_char ' ' line in
  let reply =
    if List.length args <> 3 then
      "Syntax error: A op B. Be nice\n"
    else
      let a = int_of_string (List.nth args 0) in
      let op = List.nth args 1 in
      let b = int_of_string (List.nth args 2) in
      match op with
      | "+" -> Printf.sprintf "%d\n" (a + b)
      | "-" -> Printf.sprintf "%d\n" (a - b)
      | "*" -> Printf.sprintf "%d\n" (a * b)
      | "/" -> if b = 0 then "Don't be an ass !\n" else Printf.sprintf "%d\n" (a / b)
      | op -> Printf.sprintf "Unknown operator %s\n" op
  in
  Driver.send_channel_data t id (Cstruct.of_string reply)

let rec serve t user_auth cmd =
  let open Server in
  let* t, poll_result = Driver.poll t in
  match poll_result with
  | Userauth (username, userauth) ->
    let* t = Driver.user_auth t userauth (user_auth username userauth) in
    serve t user_auth cmd
  | Disconnected s ->
    Logs.info (fun m -> m "Disconnected: %s" s);
    Ok ()
  | Channel_eof id ->
    Logs.info (fun m -> m "Channel %lu EOF" id);
    Ok ()
  | Channel_data (id, data) ->
    Logs.info (fun m -> m "channel data %d" (Cstruct.length data));
    (match cmd with
     | None -> serve t user_auth cmd
     | Some "echo" ->
       if (Cstruct.to_string data) = "rekey\n" then
         let* t = Driver.rekey t in
         serve t user_auth cmd
       else
         let* t = echo t id data in
         serve t user_auth cmd
     | Some "bc" ->
       let* t = bc t id data in
       serve t user_auth cmd
     | _ -> Error "Unexpected cmd")
  | Channel_subsystem (id, exec) (* same as exec *)
  | Channel_exec (id, exec) ->
    Logs.info (fun m -> m "channel exec %s" exec);
    begin match exec with
    | "suicide" ->
      let* _ = Driver.disconnect t in
      Ok ()
    | "ping" ->
      let* t = Driver.send_channel_data t id (Cstruct.of_string "pong\n") in
      let* _ = Driver.disconnect t in
      Logs.info (fun m -> m "sent pong");
      Ok ()
    | "echo" | "bc" as c -> serve t user_auth (Some c)
    | _ ->
      let msg = Printf.sprintf "Unknown command %s" exec in
      let* t = Driver.send_channel_data t id (Cstruct.of_string msg) in
      Logs.info (fun m -> m "%s" msg);
      let* t = Driver.disconnect t in
      serve t user_auth cmd end
  | Set_env (k, v) ->
    Logs.info (fun m -> m "Ignoring Set_env (%S, %S)" k v);
    serve t user_auth cmd
  | Pty _ | Pty_set _ ->
    let msg =
      Ssh.disconnect_msg Ssh.DISCONNECT_SERVICE_NOT_AVAILABLE
      "Sorry no PTY for you"
    in
    let* _ = Driver.send_msg t msg in
    Ok ()
  | Start_shell _ ->
    let msg =
      Ssh.disconnect_msg Ssh.DISCONNECT_SERVICE_NOT_AVAILABLE
        "Sorry no shell for you"
    in
    let* _ = Driver.send_msg t msg in
    Ok ()

let user_auth =
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/data/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = Result.get_ok (Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  fun user userauth ->
  match user, userauth with
  | "foo", Awa.Server.Password "bar" ->
    true
  | "awa", Awa.Server.Pubkey pubkeyauth ->
    Awa.Server.verify_pubkeyauth ~user:"awa" pubkeyauth &&
    Awa.Server.pubkey_of_pubkeyauth pubkeyauth = key
  | _ -> false

let rec wait_connection priv_key listen_fd server_port =
  Logs.info (fun m -> m "Awa server waiting connections on port %d" server_port);
  let client_fd, _ = Unix.(accept listen_fd) in
  Logs.info (fun m -> m "Client connected!");
  let server, msgs = Server.make priv_key in
  let* t =
    Driver.of_server server msgs
      (write_cstruct client_fd)
      (read_cstruct client_fd)
      Mtime_clock.now
  in
  let () = match serve t user_auth None with
    | Ok () -> Logs.info (fun m -> m "Client finished")
    | Error e -> Logs.warn (fun m -> m "error: %s" e)
  in
  Unix.close client_fd;
  wait_connection priv_key listen_fd server_port

let jump () =
  Mirage_crypto_rng_unix.use_default ();
  let g = Mirage_crypto_rng.(create ~seed:"180586" (module Fortuna)) in
  let (ec_priv,_) = Mirage_crypto_ec.Ed25519.generate ~g () in
  let priv_key = Awa.Hostkey.Ed25519_priv (ec_priv) in
  let server_port = 18022 in
  let listen_fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(setsockopt listen_fd SO_REUSEADDR true);
  Unix.(bind listen_fd (ADDR_INET (inet_addr_any, server_port)));
  Unix.listen listen_fd 1;
  Result.map_error
    (fun msg -> `Msg msg)
    (wait_connection priv_key listen_fd server_port)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let cmd =
  let term =
    Term.(term_result (const jump $ setup_log))
  and info =
    Cmd.info "awa_test_server" ~version:"%%VERSION_NUM"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
