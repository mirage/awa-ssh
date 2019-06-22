(** Effectful operations using Mirage for pure SSH. *)

(** SSH module given a flow *)
module Make (F : Mirage_flow_lwt.S) (M : Mirage_clock.MCLOCK) : sig

  module FLOW : Mirage_flow_lwt.S

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Msg of string
                | `Read of F.error
                | `Write of F.write_error ]

  type write_error = [ `Closed | error ]
  (** The type for write errors. *)

  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  (** we provide the FLOW interface *)
  include Mirage_flow_lwt.S
    with type 'a io  := 'a io
     and type buffer := buffer
     and type error := error
     and type write_error := write_error

  (** [client_of_flow username key flow] upgrades the existing connection
      to SSH using the configuration. *)
  val client_of_flow : string -> Awa.Hostkey.priv -> Nocrypto.Rsa.pub ->
    FLOW.flow -> (flow, error) result Lwt.t

end
  with module FLOW = F
