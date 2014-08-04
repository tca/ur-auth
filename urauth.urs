signature AUTHORITY_CONF = sig
    val hash_length : int
    val iterations : int
    val derive_salt : int -> string -> string -> transaction int
end

signature AUTHORITY = sig
    val auth_user : string -> string -> transaction (option int)
    val add_user : string -> string -> transaction (option int)
end

functor Make(A : AUTHORITY_CONF) : AUTHORITY
