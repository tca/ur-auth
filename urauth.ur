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

functor Make(A : AUTHORITY_CONF) : AUTHORITY = struct
    val hash_length = A.hash_length
    val iterations = A.iterations

    sequence user_counter

    table users : { Id : int, UserName : string, PassHash : blob, PassSalt : string }
		      PRIMARY KEY (Id), CONSTRAINT UniqueUserName UNIQUE (UserName)

    table sessions : { Id : int, Key : string, Expires : time }
    cookie s : string

    fun hash_pass pass salt = Pbkdf2.pkcs5_pbkdf2_hmac_sha1 hash_length iterations pass salt

    fun init_session uid = 
	dt <- Datetime.now;
	r <- rand;
	let
	    val expires = Datetime.toTime (Datetime.addDays A.session_length dt)
	in
	    setCookie s { Value = (show r),
			  Expires = (Some expires),
			  Secure = A.secure_cookie};
	    dml (INSERT INTO sessions (Id, Key, Expires)
		 VALUES ({[uid]}, {[show r]}, {[expires]}));
	    return ()
	end

    fun clear_session () = clearCookie s; return ()

    fun get_session () =
	so <- getCookie s;
	case so of
	    None => return None
	  | Some skey =>
	    u <- oneOrNoRows (SELECT sessions.Id FROM sessions WHERE sessions.Key={[skey]});
	    case u of
		None => return None
	      | Some session => return (Some session.Sessions.Id)
    

    fun garbage_collect_sessions () =
	dt <- now;
	dml (DELETE FROM sessions WHERE Expires < {[dt]});
	return ()
	
    (* 24 hours = 86400 seconds *)
    task periodic 86400 = garbage_collect_sessions

    (* 1. is user already logged in?
       2. check credentials
       3. set cookie & create session in db *)
    fun auth_user uname pass =
	uid <- get_session ();
	case uid of
	    Some uid' => return (Some uid')
	  | None => 
	    user <- oneOrNoRows (SELECT *
				 FROM users
				 WHERE users.UserName={[uname]});
	    case user of
		None => return None
	      | Some(user') =>
		case (hash_pass pass user'.Users.PassSalt) of
		    None => return None
		  | Some(hash) =>
		    case (Pbkdf2.eq hash user'.Users.PassHash) of
			False => return None
		      | True =>
			init_session user'.Users.Id;
			return (Some user'.Users.Id)


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
		init_session user_id;
		return (Some user_id)
end
