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

type pubkeyauth = {
  pubkey : Hostkey.pub ;
  session_id : string ;
  service : string ;
  sig_alg : Hostkey.alg ;
  signed : string ;
}

let pubkey_of_pubkeyauth { pubkey; _ } = pubkey

type userauth =
  | Password of string
  | Pubkey of pubkeyauth

let make_user name ?password keys =
  if password = None && keys = [] then
    invalid_arg "password must be Some, and/or keys must not be empty";
  { name; password; keys }

let lookup_user name db =
  List.find_opt (fun user -> user.name = name) db

let to_hash name alg pubkey session_id service =
  let open Wire in
  put_string session_id (Dbuf.create ()) |>
  put_message_id Ssh.MSG_USERAUTH_REQUEST |>
  put_string name |>
  put_string service |>
  put_string "publickey" |>
  put_bool true |>
  put_string (Hostkey.alg_to_string alg) |>
  put_pubkey pubkey |>
  Dbuf.to_cstruct |>
  Cstruct.to_string

let sign name alg key session_id service =
  let data = to_hash name alg (Hostkey.pub_of_priv key) session_id service in
  Hostkey.sign alg key data

let verify_signature name alg pubkey session_id service signed =
  let unsigned = to_hash name alg pubkey session_id service in
  Hostkey.verify alg pubkey ~unsigned ~signed

let verify_pubkeyauth ~user { pubkey; session_id; service ; sig_alg ; signed } =
  verify_signature user sig_alg pubkey session_id service signed

let verify db user userauth =
  match lookup_user user db, userauth with
  | None, Pubkey pubkeyauth ->
    verify_pubkeyauth ~user pubkeyauth && false
  | (None | Some { password = None; _ }), Password _ -> false
  | Some u, Pubkey pubkeyauth ->
    verify_pubkeyauth ~user pubkeyauth &&
    List.exists (fun pubkey -> Hostkey.pub_eq pubkey pubkeyauth.pubkey) u.keys
  | Some { password = Some password; _ }, Password password' ->
      let open Digestif.SHA256 in
      let a = digest_string password
      and b = digest_string password' in
      Digestif.SHA256.equal a b
