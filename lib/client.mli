(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed!
*)

type t

val make : string -> Hostkey.priv -> Nocrypto.Rsa.pub -> unit -> t * Cstruct.t list

type event = [
  | `Established of int32
  | `Channel_data of int32 * Cstruct.t
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
