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

  val spawn_server : ?stop:Lwt_switch.t -> Awa.Server.t -> Awa.Ssh.message list -> F.flow ->
    exec_callback -> t Lwt.t
  (** [spawn_server ?stop server msgs flow callback] launches an {i internal}
      SSH channels handler which can be stopped by [stop]. This SSH channels
      handler will call [callback] for every new channels requested by the
      client. [msgs] are the SSH {i hello} given by {!val:Awa.Server.make} which
      returns also a {!type:Awa.Server.t} required here.

      A basic usage of [spawn_server] is:
      {[
        let ssh_channel_handler _cmd _ic _oc _ec =
          Lwt.return_unit

        let tcp_handler flow =
          let server, msgs = Awa.Server.make private_key db in
          SSH.spawn_server server msgs flow ssh_handler >>= fun _t ->
          close flow
      ]}

      {b NOTE}: Even if the [ssh_channel_handler] is fulfilled, [spawn_server]
      continues to handle SSH channels. Only [stop] can really stop the internal
      SSH channels handler. *)

end
  with module FLOW = F
