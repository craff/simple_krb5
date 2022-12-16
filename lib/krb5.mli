exception Krb5_error of string

val is_thread_safe : unit -> bool

type context

val init_context : bool -> context
(** [init_context(secure)] initialize a krb5 context *)

type principal

val parse_name : context:context -> string -> principal
(** [parse_name ~context name] parses a principal name *)

val principal_realm : principal -> string
val principal_data  : principal -> string array

type keytab

val kt_resolve : context:context -> ?name:string -> unit -> keytab
(** [kt_resolve ~context ~name ()] resolve a keytab name (or default keytab
    if no name is given *)

type ccache

val cc_resolve : context:context -> ?name:string -> unit -> ccache
(** [cc_resolve ~context ~name] get the handle to a credential cache.
    use the default cache is name is not given *)

type creds

val get_init_creds_password
    : ?tkt_service:string -> principal:principal -> ?server:principal ->
      ?keytab:keytab -> ?ccache:ccache -> string -> creds
(** [get_init_creds_password ~tkt_service ~principal ~server password
    get and verify the given principal

    @param: tkt_service: the service to use (default ticket-granting)
    @param: principal: the principal we want to get credentials
    @param: server: the server to query (default server if not given)
    @param: password: the password
*)

val get_init_creds_keytab
    : ?tkt_service:string -> principal:principal -> ?server:principal ->
      ?ccache:ccache -> keytab -> creds

val ticket_string_from_creds : creds -> string
