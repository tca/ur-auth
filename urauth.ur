signature AUTHORITY_CONF = sig
    val hash_length : int
    val iterations : int
    val derive_salt : int -> string -> string -> transaction string
end

signature AUTHORITY = sig
    val auth_user : string -> string -> transaction (option int)
    val add_user : string -> string -> transaction (option int)
end

functor Make(A : AUTHORITY_CONF) : AUTHORITY = struct
    val hash_length = A.hash_length
    val iterations = A.iterations

    sequence user_counter

    table users : { Id : int, UserName : string, PassHash : blob, PassSalt : string }
		      PRIMARY KEY (Id), CONSTRAINT UniqueUserName UNIQUE (UserName)

    fun hash_pass pass salt = Pbkdf2.pkcs5_pbkdf2_hmac_sha1 hash_length iterations pass salt

    fun auth_user uname pass =
	user <- oneOrNoRows (SELECT *
			     FROM users
			     WHERE users.UserName={[uname]});
	case user of
	    None => return None
	  | Some(user') =>
	    case (hash_pass pass user'.Users.PassSalt) of
		None => return None
	      | Some(hash) => if (Pbkdf2.eq hash user'.Users.PassHash)
			      then return (Some user'.Users.Id)
			      else return None
				   

    fun add_user uname pass =
	existing <- oneOrNoRows (SELECT users.Id
				 FROM users
				 WHERE users.UserName={[uname]});
	case existing of
	    Some _ => return None
	  | None =>
	    user_id <- nextval user_counter;
	    salt <- A.derive_salt user_id uname pass;
	    case hash_pass pass salt of
		None => return None
	      | Some(hash) =>
		dml (INSERT INTO users (Id, UserName, PassHash, PassSalt)
		     VALUES ({[user_id]}, {[uname]}, {[hash]}, {[salt]}));
		return (Some user_id)
		
end
