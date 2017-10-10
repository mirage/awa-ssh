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

type user = {
  name     : string;
  password : string option;
  keys     : Hostkey.pub list;
}

type db = user list

type state =
  | Preauth
  | Inprogress of (string * string * int)
  | Done

let lookup_user username db =
  List.find_opt (fun user -> user.name = username) db

let lookup_key user key  =
  List.find_opt (fun key2 -> key = key2 ) user.keys

let lookup_user_key user key db =
  match lookup_user user db with
  | None -> None
  | Some user -> lookup_key user key

let by_password username password db =
  match lookup_user username db with
  | None -> false
  | Some user -> user.password = Some password

let by_pubkey username pubkey session_id service signed db =
  match lookup_user_key username pubkey db with
  | None -> false
  | Some pubkey ->
    if pubkey = Hostkey.Unknown then
      false
    else
      let unsigned =
        let open Wire in
        put_cstring session_id (Dbuf.create ()) |>
        put_message_id Ssh.MSG_USERAUTH_REQUEST |>
        put_string username |>
        put_string service |>
        put_string "publickey" |>
        put_bool true |>
        put_string (Hostkey.sshname pubkey) |>
        put_pubkey pubkey |>
        Dbuf.to_cstruct
      in
      match Hostkey.verify pubkey ~unsigned ~signed with
      | Ok () -> true
      | Error e -> false
