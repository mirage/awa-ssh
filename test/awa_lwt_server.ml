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

let user_db =
  (* User foo auths by passoword *)
  let foo = Awa.Auth.make_user "foo" ~password:"bar" [] in
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/data/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = Result.get_ok (Awa.Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  let awa = Awa.Auth.make_user "awa" [ key ] in
  [ foo; awa ]

let exec addr ?cmd sshin sshout _ssherror =
  let rec echo () =
    sshin () >>= function
    | `Eof -> Lwt.return_unit
    | `Data input -> sshout input >>= fun () -> echo ()
  in
  let ping () = sshout (Cstruct.of_string "pong\n") in
  let badcmd cmd =
    sshout (Cstruct.of_string (Printf.sprintf "Bad command `%s`\n" cmd))
  in
  match cmd with
  | None ->
    Lwt_io.printf "[%s] impossible to execute a shell\n%!" addr >>= fun () ->
    sshout (Cstruct.of_string (Printf.sprintf "No shell available"))
  | Some cmd ->
    Lwt_io.printf "[%s] executing `%s`\n%!" addr cmd >>= fun () ->
    (match cmd with "echo" -> echo () | "ping" -> ping () | _ -> badcmd cmd)
    >>= fun () ->
    Lwt_io.printf "[%s] execution of `%s` finished\n%!" addr cmd
    (* XXX Awa_lwt must close the channel when exec returns ! *)

let serve rsa fd addr =
  Lwt_io.printf "[%s] connected\n%!" addr >>= fun () ->
  let server, msgs = Awa.Server.make rsa user_db in
  Awa_lwt.spawn_server server msgs fd (exec addr) >>= fun _t ->
  Lwt_io.printf "[%s] finished\n%!" addr >>= fun () ->
  Lwt_unix.close fd

let rec wait_connection priv_key listen_fd server_port =
  Lwt_io.printf "Awa server waiting connections on port %d\n%!" server_port
  >>= fun () ->
  Lwt_unix.(accept listen_fd) >>= fun (client_fd, saddr) ->
  let client_addr = match saddr with
    | Lwt_unix.ADDR_UNIX s -> s
    | Lwt_unix.ADDR_INET (addr, port) ->
      Printf.sprintf "%s:%d" (Unix.string_of_inet_addr addr) port
  in
  Lwt.ignore_result (serve priv_key client_fd client_addr);
  wait_connection priv_key listen_fd server_port

let main =
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  let g = Mirage_crypto_rng.(create ~seed:(Cstruct.of_string "180586") (module Fortuna)) in
  let (ec_priv,_) = Mirage_crypto_ec.Ed25519.generate ~g () in
  let priv_key = Awa.Hostkey.Ed25519_priv (ec_priv) in
  let server_port = 18022 in
  let listen_fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  Lwt_unix.(setsockopt listen_fd SO_REUSEADDR true);
  Lwt_unix.(bind listen_fd (ADDR_INET
                              (Unix.inet_addr_any, server_port)))
  >>= fun () ->
  Lwt_unix.listen listen_fd 1;
  wait_connection priv_key listen_fd server_port

let () =
  Lwt_main.run main
