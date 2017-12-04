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

open Rresult.R
open Awa

let printf = Printf.printf
let sprintf = Printf.sprintf

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
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let echo t id data =
  Driver.send_channel_data t id data

let bc t id data =
  let len = Cstruct.len data in
  let line = (Cstruct.set_len data (len - 1)) |> Cstruct.to_string in
  let args = String.split_on_char ' ' line in
  let reply =
    if List.length args <> 3 then
      "Syntax error: A op B. Be nice\n"
    else
      let a = int_of_string (List.nth args 0) in
      let op = List.nth args 1 in
      let b = int_of_string (List.nth args 2) in
      match op with
      | "+" -> sprintf "%d\n" (a + b)
      | "-" -> sprintf "%d\n" (a - b)
      | "*" -> sprintf "%d\n" (a * b)
      | "/" -> if b = 0 then "Don't be an ass !\n" else sprintf "%d\n" (a / b)
      | op -> "Unknown operator\n"
  in
  Driver.send_channel_data t id (Cstruct.of_string reply)

let rec serve t fd cmd =
  let open Server in
  (* XXX Replace with Mtime for monotonic uptime  *)
  Driver.poll t Int64.one >>= fun (t, poll_result) ->
  match poll_result with
  | Disconnected s -> ok (printf "Disconnected: %s\n%!" s)
  | Channel_eof id -> ok (printf "Channel %ld EOF\n%!" id)
  | Channel_data (id, data) ->
    (match cmd with
     | None -> serve t fd cmd
     | Some "echo" -> echo t id data >>= fun t -> serve t fd cmd
     | Some "bc" -> bc t id data >>= fun t -> serve t fd cmd
     | _ -> error "Unexpected cmd")
  | Channel_exec (id, exec) -> match exec with
    | "suicide" -> Driver.disconnect t >>= fun _ -> ok ()
    | "ping" ->
      Driver.send_channel_data t id (Cstruct.of_string "pong\n") >>= fun t ->
      Driver.disconnect t >>= fun _ -> ok (printf "sent pong\n%!")
    | "echo" | "bc" as c -> serve t fd (Some c)
    | unknown ->
      let m = sprintf "Unknown command %s\n%!" exec in
      Driver.send_channel_data t id (Cstruct.of_string m) >>= fun t ->
      printf "%s\n%!" m;
      Driver.disconnect t >>= fun t -> serve t fd cmd

let user_db =
  (* User foo auths by passoword *)
  let foo = Auth.make_user "foo" ~password:"bar" [] in
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = get_ok (Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  let awa = Auth.make_user "awa" [ key ] in
  [ foo; awa ]

let rec wait_connection rsa listen_fd server_port =
  printf "Awa server waiting connections on port %d\n%!" server_port;
  let client_fd, _ = Unix.(accept listen_fd) in
  printf "Client connected !\n%!";
  let server, msgs = Server.make rsa user_db in
  Driver.of_server server msgs
    (write_cstruct client_fd)
    (read_cstruct client_fd)
  >>= fun t ->
  let () = match serve t client_fd None with
    | Ok _ -> printf "Client finished\n%!"
    | Error e -> printf "error: %s\n%!" e
  in
  Unix.close client_fd;
  wait_connection rsa listen_fd server_port

let () =
  Nocrypto.Rng.reseed (Cstruct.of_string "180586");
  let rsa = Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048) in
  let server_port = 18022 in
  let listen_fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(setsockopt listen_fd SO_REUSEADDR true);
  Unix.(bind listen_fd (ADDR_INET (inet_addr_any, server_port)));
  Unix.listen listen_fd 1;
  match wait_connection rsa listen_fd server_port with
  | Error e -> printf "error %s\n%!" e
  | Ok _ -> printf "ok\n%!\n"
