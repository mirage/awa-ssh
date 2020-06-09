type endpoint =
  { authenticator : Awa.Keys.authenticator option
  ; user : string
  ; key : Awa.Hostkey.priv
  ; req : Awa.Ssh.channel_request }

module Make
    (Scheduler : Conduit.Sigs.SCHEDULER)
    (Conduit : Conduit.S
     with type input = Cstruct.t
      and type output = Cstruct.t
      and type +'a s = 'a Scheduler.t)
    (M : Mirage_clock.MCLOCK) : sig
  type 'flow protocol_with_ssh

  val protocol_with_ssh :
      ('edn, 'flow) Conduit.protocol ->
      ('edn * endpoint, 'flow protocol_with_ssh) Conduit.protocol
end
