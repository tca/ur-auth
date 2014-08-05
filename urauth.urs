signature AUTHORITY_CONF = sig
    val hash_length : int
    val iterations : int
    val session_length : int
    val secure_cookie : bool
    val derive_salt : int -> string -> string -> transaction string
end

signature AUTHORITY = sig
    val get_session : unit -> transaction (option int)
    val clear_session : unit -> transaction unit	      
    val auth_user : string -> string -> transaction (option int)
    val add_user : string -> string -> transaction (option int)
end

functor Make(A : AUTHORITY_CONF) : AUTHORITY
