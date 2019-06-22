(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed!
*)

type t

val make : string -> Hostkey.priv -> unit -> t * Cstruct.t list

type event =
  | Channel_data of int32 * Cstruct.t
  | Channel_eof of int32
  | Channel_exit_status of int32 * int32
  | Channel_close of int32

val pp_event : Format.formatter -> event -> unit

val incoming : t -> Mtime.t -> Cstruct.t ->
  (t * Cstruct.t list * event list, string) result

val outgoing : t -> ?id:int32 -> Cstruct.t ->
  (t * Cstruct.t list, string) result
