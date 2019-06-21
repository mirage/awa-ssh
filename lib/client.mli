(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed!
*)

type t

val make : string -> Hostkey.priv -> unit -> (t * Ssh.message list)

val output_msg : t -> Ssh.message -> (t * Cstruct.t, string) result

type event =
  | Channel_data of int32 * Cstruct.t
  | Channel_eof of int32
  | Channel_exit_status of int32 * int32
  | Channel_close of int32

val pp_event : Format.formatter -> event -> unit

val handle_input : t -> Cstruct.t -> Mtime.t ->
  (t * Ssh.message list * event list, string) result

val output_channel_data : t -> int32 -> Cstruct.t ->
  (t * Ssh.message list, string) result
