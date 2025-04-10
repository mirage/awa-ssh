(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
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

type t

val make : ?authenticator:Keys.authenticator -> user:string ->
  [ `Pubkey of Hostkey.priv | `Password of string ] -> t * Cstruct.t list

type event = [
  | `Established of int32
  | `Channel_data of int32 * Cstruct.t
  | `Channel_stderr of int32 * Cstruct.t
  | `Channel_eof of int32
  | `Channel_exit_status of int32 * int32
  | `Disconnected
]

val pp_event : Format.formatter -> event -> unit

val incoming : t -> Mtime.t -> Cstruct.t ->
  (t * Cstruct.t list * event list, string) result

val outgoing_request : t -> ?id:int32 -> ?want_reply:bool ->
  Ssh.channel_request -> (t * Cstruct.t, string) result

val outgoing_data : t -> ?id:int32 -> Cstruct.t ->
  (t * Cstruct.t list, string) result

val eof : ?id:int32 -> t -> t * Cstruct.t list

val close : ?id:int32 -> t -> t * Cstruct.t option
