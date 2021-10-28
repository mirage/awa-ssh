(** Effectful operations using Mirage for pure SSH. *)

(** SSH module given a flow *)
module Make (F : Mirage_flow.S) (T : Mirage_time.S) (M : Mirage_clock.MCLOCK) : sig

  module FLOW : Mirage_flow.S

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Msg of string
                | `Read of F.error
                | `Write of F.write_error ]

  type write_error = [ `Closed | error ]
  (** The type for write errors. *)

  (** we provide the FLOW interface *)
  include Mirage_flow.S
    with type error := error
     and type write_error := write_error

  (** [client_of_flow ~authenticator ~user key channel_request flow] upgrades the
      existing connection to SSH, mutually authenticates, opens a channel and
      sends the channel request. *)
  val client_of_flow : ?authenticator:Awa.Keys.authenticator -> user:string ->
    Awa.Hostkey.priv -> Awa.Ssh.channel_request -> FLOW.flow ->
    (flow, error) result Lwt.t

 type t

  type sshin_msg = [
    | `Data of Cstruct.t
    | `Eof
  ]

  type exec_callback =
    string ->                     (* cmd *)
    (unit -> sshin_msg Lwt.t) ->  (* sshin *)
    (Cstruct.t -> unit Lwt.t) ->  (* sshout *)
    (Cstruct.t -> unit Lwt.t) ->  (* ssherr *)
    unit Lwt.t

  val spawn_server : Awa.Server.t -> Awa.Ssh.message list -> F.flow ->
    exec_callback -> t Lwt.t

end
  with module FLOW = F
